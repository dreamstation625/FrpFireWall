package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/dreamstation625/FrpFireWall/internal/portrange"
)

// nftables 驱动的设计要点
//
// 优先在现有 input 链前插入带归属标记的 DROP 规则，保留系统判决流程。
// nft 的 accept 仍会继续执行同 hook 的后续 base chain，drop 则立即终止。
// 只有可靠确认不存在 input 链时，才在本项目独立表中创建 base chain。
// 读取或解析失败必须中止，不能被当成没有系统防火墙。
//
// 关键约束二：**规则落点按协议栈分开，一个不够**。
//
// nftables 的 family 决定这条链处理哪个协议栈：
//
//	inet → IPv4 与 IPv6 都走这里，同一个链里用 `ip saddr` / `ip6 saddr` 区分
//	ip   → 只有 IPv4。链里写 `ip6 saddr` 会报
//	       "conflicting protocols specified: ip vs. ip6"，整份脚本被拒绝
//	ip6  → 只有 IPv6
//
// 而 ip 与 ip6 是彼此独立的家族，想同时管住两个协议栈就必须有两个链。
// 系统里 `table ip filter` 与 `table ip6 filter` 并存是常态（ufw、docker、
// iptables-nft 生成的规则都长这样），所以落点必须按协议栈分别记录。
//
// 白名单不落内核：白名单的语义是"豁免本程序封禁"，而 return verdict 在 base chain
// 里的行为依赖上下文，不可靠。改为在生成黑名单集合时把白名单地址减掉，
// 效果等价且零歧义。

// nftTarget 是一条链的完整坐标。
type nftTarget struct {
	Family string
	Table  string
	Chain  string
}

// nftStack 是一个协议栈的规则落点。
type nftStack struct {
	target nftTarget
	// bits 是地址位宽：32=IPv4 / 128=IPv6。
	// 它同时决定用哪个集合名、表达式前缀是 ip 还是 ip6。
	bits int
}

func (s nftStack) isV6() bool { return s.bits == 128 }

// proto 返回表达式里用的协议前缀。
func (s nftStack) proto() string {
	if s.isV6() {
		return "ip6"
	}
	return "ip"
}

// set 返回该协议栈用的黑名单集合名。
func (s nftStack) set() string {
	if s.isV6() {
		return setBlack6
	}
	return setBlack
}

// portSet 返回该协议栈上某个端口限定分组用的地址集合名。
//
// 和全端口黑名单分开成两套集合，而不是共用一个再靠规则区分：集合的元素本来就
// 不同（同一个地址可能只在其中一个里），共用的后果是"这条规则到底封哪些地址"
// 得回头去看上层怎么填的。
//
// 每个分组各有一个集合，名字由端口签名派生 —— 详见 portSetName 的说明。
func (s nftStack) portSet(key string) string { return portSetName(s.bits, key) }

// setType 返回集合元素类型。
func (s nftStack) setType() string {
	if s.isV6() {
		return "ipv6_addr"
	}
	return "ipv4_addr"
}

// comment 返回该协议栈规则的归属标记。
func (s nftStack) comment() string {
	if s.isV6() {
		return commentBlack6
	}
	return commentBlack
}

// commentPort 返回该协议栈上某个端口限定分组的归属标记。
func (s nftStack) commentPort(key string) string { return portComment(key) }

// label 是给人看的协议栈名，用在展示与告警里。
func (s nftStack) label() string {
	if s.isV6() {
		return "IPv6"
	}
	return "IPv4"
}

type nftablesDriver struct {
	report *Report
	// stacks 是本程序规则的实际落点。inet 家族下两项共用一个 target，
	// ip / ip6 家族下则是两个不同的链。
	stacks []nftStack
	ready  bool
}

func newNFTablesDriver(report *Report) *nftablesDriver {
	return &nftablesDriver{report: report}
}

func (d *nftablesDriver) Name() string { return string(BackendNFTables) }

func (d *nftablesDriver) Capability() Capability {
	c := Capability{
		Backend:   string(BackendNFTables),
		Version:   d.report.NFTablesVersion,
		Supported: d.report.HasNFTables,
		RateLimit: nftVersionAtLeast(d.report.NFTablesVersion, 0, 9, 3),
	}
	if c.Supported {
		// 地址装在集合里、规则只有一条，所以计数只能到分组这一层。
		c.CounterGranularity = CounterKindGroup
	}
	if !d.report.HasNFTables {
		c.Reason = "未找到 nft 命令，Debian/Ubuntu 请执行 apt install nftables"
	} else if !c.RateLimit {
		c.Reason = fmt.Sprintf("nftables %s 版本过低，不支持动态集合（per-IP 限速需要 >= 0.9.3）", d.report.NFTablesVersion)
	} else {
		c.Reason = "当前 nftables 的 per-IP 内核限速只支持 IPv4；IPv6 黑名单仍受支持"
	}
	if len(d.report.Warnings) > 0 {
		c.Reason = strings.TrimSpace(c.Reason + "；" + strings.Join(d.report.Warnings, "；"))
	}
	return c
}

// EnsureBase 定位（或创建）input base chain，按协议栈记录落点，并保证集合存在。
func (d *nftablesDriver) EnsureBase() error { return d.ensureBase(context.Background()) }

func (d *nftablesDriver) ensureBase(ctx context.Context) error {

	chains, err := d.inputChains(ctx)
	if err != nil {
		return err
	}
	inet, hasInet := chains["inet"]
	ip, hasIP := chains["ip"]
	ip6, hasIP6 := chains["ip6"]

	switch {
	case hasInet:
		// 一个链同时管两个协议栈，最省事也最不容易出错
		d.stacks = []nftStack{
			{target: inet, bits: 32},
			{target: inet, bits: 128},
		}
	case hasIP && hasIP6:
		d.stacks = []nftStack{
			{target: ip, bits: 32},
			{target: ip6, bits: 128},
		}
	case hasIP:
		d.stacks = []nftStack{{target: ip, bits: 32}}
		d.warn(halfStackWarning("IPv6"))
	case hasIP6:
		d.stacks = []nftStack{{target: ip6, bits: 128}}
		d.warn(halfStackWarning("IPv4"))
	default:
		t, err := d.createDefaultChain(ctx)
		if err != nil {
			return err
		}
		d.stacks = []nftStack{
			{target: t, bits: 32},
			{target: t, bits: 128},
		}
	}

	for _, s := range d.stacks {
		if err := d.ensureSet(ctx, s, s.set(), s.setType(), false); err != nil {
			return err
		}
		// 端口限定分组的集合不在这里建：那时候还不知道有哪些分组（集合名由
		// 端口签名派生），由 Sync 按期望状态补齐（见 ensurePortSets）。
	}
	d.ready = true
	return nil
}

// createDefaultChain 在系统里没有任何 INPUT base chain 时建一个标准的 inet 链。
//
// 只在"什么都没有"时才走这条路 —— 有链可插入时绝不新建，见文件头的关键约束一。
func (d *nftablesDriver) createDefaultChain(ctx context.Context) (nftTarget, error) {
	script := "create table inet frpfirewall\ncreate chain inet frpfirewall input { type filter hook input priority filter; policy accept; }\n"
	if _, err := runStdin(ctx, script, "nft", "-f", "-"); err != nil {
		return nftTarget{}, fmt.Errorf("创建独立受管链失败: %w", err)
	}
	return nftTarget{Family: "inet", Table: "frpfirewall", Chain: "input"}, nil
}

// inputChains 一次性取回 ruleset 里所有 INPUT base chain，按家族归组。
// 同家族有多个候选取 priority 最小的（最先执行，我们的 drop 也就能最早生效）。
//
// 只调用一次 nft：原先是按家族各跑一遍 list ruleset，三倍开销。
func (d *nftablesDriver) inputChains(ctx context.Context) (map[string]nftTarget, error) {
	out, err := run(ctx, "nft", "-j", "list", "ruleset")
	if err != nil {
		return nil, fmt.Errorf("读取 nft 规则失败: %w", err)
	}

	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil, fmt.Errorf("解析 nft 规则失败: %w", err)
	}
	if doc.Nftables == nil {
		return nil, fmt.Errorf("nft 返回了不完整的规则集")
	}

	found := make(map[string]nftTarget, 3)
	prio := make(map[string]int, 3)
	for _, item := range doc.Nftables {
		raw, ok := item["chain"]
		if !ok {
			continue
		}
		var ch struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
			Hook   string `json:"hook"`
			Prio   int    `json:"prio"`
		}
		if err := json.Unmarshal(raw, &ch); err != nil {
			return nil, fmt.Errorf("解析 nft 链失败: %w", err)
		}
		if ch.Hook != "input" {
			continue
		}
		// 只认这三个家族：ip / ip6 各管一个协议栈，inet 两个都管。
		// bridge / netdev / arp 跟本程序无关。
		if ch.Family != "inet" && ch.Family != "ip" && ch.Family != "ip6" {
			continue
		}
		if _, seen := found[ch.Family]; seen && ch.Prio >= prio[ch.Family] {
			continue
		}
		if !nftIdentifier.MatchString(ch.Table) || !nftIdentifier.MatchString(ch.Name) {
			return nil, fmt.Errorf("系统 input 链名称无法安全编译")
		}
		found[ch.Family] = nftTarget{Family: ch.Family, Table: ch.Table, Chain: ch.Name}
		prio[ch.Family] = ch.Prio
	}
	return found, nil
}

func (d *nftablesDriver) ensureSet(ctx context.Context, s nftStack, name, typ string, dynamic bool) error {
	if _, err := run(ctx, "nft", "list", "set", s.target.Family, s.target.Table, name); err == nil {
		return nil
	}
	spec := fmt.Sprintf("{ type %s; flags interval; }", typ)
	if dynamic {
		spec = fmt.Sprintf("{ type %s; flags dynamic,timeout; timeout 10s; }", typ)
	}
	if _, err := run(ctx, "nft", "add", "set", s.target.Family, s.target.Table, name, spec); err != nil {
		return fmt.Errorf("创建集合 %s 失败: %w", name, err)
	}
	return nil
}

// warn 追加一条告警，重复的不再追加。
// Sync 每次都会走 EnsureBase，不去重的话同一句话会在报告里堆一长串。
func (d *nftablesDriver) warn(msg string) {
	for _, w := range d.report.Warnings {
		if w == msg {
			return
		}
	}
	d.report.Warnings = append(d.report.Warnings, msg)
}

// Sync 全量对齐：重建归属本程序的规则 + 重填黑名单集合。
// 所有落点的改动放进同一个 nft 事务，原子提交，中途没有规则空窗。
func (d *nftablesDriver) Sync(des Desired) error { return d.SyncContext(context.Background(), des) }

func (d *nftablesDriver) SyncContext(ctx context.Context, des Desired) error {
	if err := d.ensureBase(ctx); err != nil {
		return err
	}

	// 按链去重地取受管规则 handle。inet 家族下两个协议栈共用一条链，
	// 不去重就会把同一个 handle 在同一个事务里删两次，nft 找不到第二条即报错，
	// 整份脚本随之失败 —— 连"删掉旧规则"这一步都做不到。
	handles := make(map[nftTarget][]int, len(d.stacks))
	for _, s := range d.stacks {
		if _, done := handles[s.target]; done {
			continue
		}
		h, err := d.managedRuleHandles(ctx, s)
		if err != nil {
			return err
		}
		handles[s.target] = h
	}

	// 连接速率限制要先确认动态集合能建出来（老版本 nftables 不支持）。
	// 只有 IPv4 落点能做：动态集合的元素类型是 ipv4_addr，IPv6 得另建一个
	// ipv6_addr 的动态集合。与其为了对称下发一条在 ip6 家族里语法不合法的
	// 规则（整份事务会被拒），不如在这一半上干脆跳过。
	rates := planRateRules(des.RateLimits)
	if len(rates) > 0 && d.Capability().RateLimit {
		if s, ok := d.stackFor(32); ok {
			failed := make(map[string]bool, len(rates))
			for _, p := range rates {
				if err := d.ensureSet(ctx, s, p.set, "ipv4_addr", true); err != nil {
					failed[p.rule.Key] = true
					d.warn(fmt.Sprintf("限速规则「%s」的动态集合建不出来，已跳过这条：%v", p.rule.Name, err))
				}
			}
			if len(failed) > 0 {
				kept := rates[:0]
				for _, p := range rates {
					if !failed[p.rule.Key] {
						kept = append(kept, p)
					}
				}
				rates = kept
			}
		} else {
			d.warn("当前 nftables 只找到 IPv6 落点，per-IP 连接速率限制只支持 IPv4，已跳过")
			rates = nil
		}
	} else if len(rates) > 0 {
		d.warn(fmt.Sprintf("nftables %s 版本过低，不支持动态集合，已跳过 per-IP 连接速率限制",
			d.report.NFTablesVersion))
		rates = nil
	} else {
		rates = nil
	}

	// 动态集合带 timeout，元素会自己过期；但规则改速率、改条件、删掉之后，
	// 旧的集合会一直留在内核里。它们不参与判决（规则每次全量重建），
	// 却会在 `nft list sets` 里越堆越多，排障时干扰判断。按前缀清掉不在本次期望里的。

	// 端口限定分组各需要一个地址集合，名字由端口签名派生。补在渲染脚本之前 ——
	// 脚本里会对每个集合做 flush，集合不存在的话整份脚本会在事务里被拒，
	// 那时连全端口规则都下不去。
	groups := portGroups(des)
	if err := d.ensurePortSets(ctx, groups); err != nil {
		return err
	}

	// 「端口限定」的条目在没配端口时生成不出规则，会变成"看起来封了其实没封"。
	// 这种情况必须报出来，不能静默。
	for _, g := range des.PortBlacklists {
		if len(g.Ports.Normalize()) == 0 && len(g.Prefixes) > 0 {
			d.warn(fmt.Sprintf(
				"有 %d 个地址属于「%s」，但这一组没有配置任何端口，这些条目暂未下发",
				len(g.Prefixes), g.Label))
		}
	}

	// 逻辑同上，只是对象换成端口限定的集合：分组改了端口或条目被删之后，
	// 旧集合不再被任何规则引用，却会一直留在 nft list sets 里。

	if st, ok := d.stackFor(32); ok {
		if _, err := run(ctx, "nft", "add", "chain", st.target.Family, st.target.Table, nftRateChain); err != nil && !isAlreadyExists(err) {
			return err
		}
	}
	script := renderScript(d.stacks, des, handles, rates)

	// 语法预检：不通过就整个放弃，绝不带着半截规则上生产。
	if _, err := runStdin(ctx, script, "nft", "-c", "-f", "-"); err != nil {
		return fmt.Errorf("规则语法预检失败，已放弃本次下发: %w\n%s", err, script)
	}
	if _, err := runStdin(ctx, script, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("下发规则失败: %w", err)
	}
	d.pruneRateSets(ctx, rates)
	d.prunePortSets(ctx, groups)
	return nil
}

// portGroups 取出真正能下发成规则的分组。
//
// 丢掉两类：端口为空的（写不出 dport）、地址为空的（没有来源）。留着一份
// 空集合只会让 `nft list sets` 里多出几个永远空的集合，而"没生效"这件事
// 应该由告警说清楚，不该藏在一堆空对象里。
//
// 顺带在驱动入口归一化一次端口，作为 Set 类型约定的兜底：直接手写 Set 字面量的
// 调用方不会经过归一化，而落在 nft 里的越界端口会让整份脚本预检失败 ——
// 预检失败是整份放弃，v4 规则会跟着 v6 一起陪葬。
func portGroups(des Desired) []PortBlacklist {
	out := make([]PortBlacklist, 0, len(des.PortBlacklists))
	for _, g := range des.PortBlacklists {
		if len(g.Prefixes) == 0 {
			continue
		}
		ports := g.Ports.Normalize()
		if len(ports) == 0 {
			continue
		}
		g.Ports = ports
		out = append(out, g)
	}
	return out
}

// ensurePortSets 保证每个分组在每张表里都有集合。
//
// 只能在这里补，不能在 EnsureBase 里预先建好 —— 集合名由端口签名派生，而
// EnsureBase 拿不到期望状态，那时候根本不知道有哪些分组。
func (d *nftablesDriver) ensurePortSets(ctx context.Context, groups []PortBlacklist) error {
	if len(groups) == 0 {
		return nil
	}
	for _, s := range d.stacks {
		for _, g := range groups {
			if err := d.ensureSet(ctx, s, s.portSet(g.Key), s.setType(), false); err != nil {
				return err
			}
		}
	}
	return nil
}

// prunePortSets 删掉内核里不再需要的端口限定集合。
//
// 与 pruneRateSets 同理：集合本身不会自己消失，分组改了端口、条目被删之后旧集合
// 会一直留着。不参与判决（规则每次全量重建），但会在 `nft list sets` 里越堆越多。
// 这里还顺带回收老版本那两个固定名字的集合（见 isPortSetName）。
//
// 删不掉也不影响功能，所以忽略错误。
func (d *nftablesDriver) prunePortSets(ctx context.Context, groups []PortBlacklist) {
	keep := make(map[string]bool, len(groups)*len(d.stacks))
	for _, s := range d.stacks {
		for _, g := range groups {
			keep[s.portSet(g.Key)] = true
		}
	}

	// 按落点去重：inet 家族下两个协议栈共用同一张表，不去重就会把同一批集合
	// 删两遍（第二遍必然失败）。
	seen := make(map[nftTarget]bool, len(d.stacks))
	for _, s := range d.stacks {
		if seen[s.target] {
			continue
		}
		seen[s.target] = true
		for _, name := range d.listOwnSets(ctx, s, isPortSetName) {
			if keep[name] {
				continue
			}
			_, _ = run(ctx, "nft", "delete", "set", s.target.Family, s.target.Table, name)
		}
	}
}

// renderScript 生成一次 Sync 要提交的全部 nft 语句。
//
// 抽成纯函数是为了能被测：这类脚本只有在真实内核上才会被拒绝，而"生成了 ip6
// 表达式却落在 ip 家族的链上"这种错误，用桩命令测永远发现不了（桩只会点头），
// 看脚本本身却一眼可见。Preview 也复用它，保证"预览到的"就是"会下发的"。
//
// handles 按链给出要删的规则 handle；rates 是本次要落地的限速规则（可为空）。
func renderScript(stacks []nftStack, des Desired, handles map[nftTarget][]int, rates []nftRatePlan) string {
	var b strings.Builder

	groups := portGroups(des)

	// 1. 删掉旧的受管规则（同一个事务里会重新插入，所以没有空窗）。
	//    按链去重：同一目标可能被两个协议栈共用（inet）。
	deleted := make(map[nftTarget]bool, len(stacks))
	for _, s := range stacks {
		if deleted[s.target] {
			continue
		}
		deleted[s.target] = true
		for _, h := range handles[s.target] {
			fmt.Fprintf(&b, "delete rule %s %s %s handle %d\n",
				s.target.Family, s.target.Table, s.target.Chain, h)
		}
	}

	// 2. 重填黑名单集合。每个协议栈有各自的集合：inet 下两个集合同表，
	//    ip / ip6 下则分别在各自家族的表里。
	//
	//    端口限定的集合也必须 flush：地址从端口限定改成全端口、或者条目被删掉时，
	//    残留的元素会继续封着那些端口。flush 一个空集合是合法的。
	for _, s := range stacks {
		for _, item := range []struct {
			name  string
			addrs []string
		}{
			{s.set(), filterByFamily(des.Blacklist, s.bits)},
		} {
			fmt.Fprintf(&b, "flush set %s %s %s\n", s.target.Family, s.target.Table, item.name)
			if len(item.addrs) > 0 {
				fmt.Fprintf(&b, "add element %s %s %s { %s }\n",
					s.target.Family, s.target.Table, item.name, strings.Join(item.addrs, ", "))
			}
		}
		for _, g := range groups {
			name := s.portSet(g.Key)
			fmt.Fprintf(&b, "flush set %s %s %s\n", s.target.Family, s.target.Table, name)
			if addrs := filterByFamily(g.Prefixes, s.bits); len(addrs) > 0 {
				fmt.Fprintf(&b, "add element %s %s %s { %s }\n",
					s.target.Family, s.target.Table, name, strings.Join(addrs, ", "))
			}
		}
	}

	// 3. 限速规则。表达式里的 saddr 是 IPv4 的，所以只落在 v4 链上。
	//
	//    普通子链按配置顺序追加，匹配后的 RETURN 跳过后续本项目限速。
	if s, ok := stackOf(stacks, 32); ok {
		fmt.Fprintf(&b, "flush chain %s %s %s\n", s.target.Family, s.target.Table, nftRateChain)
		for _, p := range rates {
			if expr, ok := nftRateExpr(p.rule, p.set); ok {
				fmt.Fprintf(&b, "add rule %s %s %s %s comment %q\n", s.target.Family, s.target.Table, nftRateChain, expr, rateComment(p.rule.Key))
				match := strings.Split(expr, " add @")[0]
				fmt.Fprintf(&b, "add rule %s %s %s %s return comment %q\n", s.target.Family, s.target.Table, nftRateChain, match, "frpfirewall:rate-match")
			}
		}
		if len(rates) > 0 {
			fmt.Fprintf(&b, "insert rule %s %s %s jump %s comment %q\n", s.target.Family, s.target.Table, s.target.Chain, nftRateChain, "frpfirewall:rate-jump")
		}
	}

	// 4. 重新插入黑名单规则。
	//
	//    insert 一律插到链首，所以想让最终顺序是「全端口 → 仅 frp 端口」，
	//    输出就得倒着来。这里先把期望的最终顺序整列出来再倒序输出，而不是靠
	//    手工安排几层倒着遍历 —— 规则种类一多，"该倒着遍历哪一层"就成了最容易
	//    搞错的地方，而顺序错了只有去读 nft list 才发现。
	type nftRule struct {
		stack   nftStack
		expr    string
		comment string
	}

	// 每条规则都带 counter：nft 不像 iptables 那样默认数数，规则里没有
	// counter 表达式内核就一个包都不记，界面上的"丢包统计"只能是 0。
	// counter 必须放在 drop **之前** —— drop 是终止性语句，写在它后面的
	// 表达式根本不会执行。
	forward := make([]nftRule, 0, len(stacks)*3)
	for _, s := range stacks {
		forward = append(forward, nftRule{
			stack:   s,
			expr:    fmt.Sprintf("%s saddr @%s counter drop", s.proto(), s.set()),
			comment: s.comment(),
		})
	}

	// 「端口限定」的规则只在真的用得着时才生成：没有端口就写不出 dport，
	// 某个协议栈下没有这类地址则不必为它插一条永不匹配的规则。
	for _, g := range groups {
		exprs := nftPortExprs(g.Ports)
		if len(exprs) == 0 {
			continue
		}
		for _, s := range stacks {
			if len(filterByFamily(g.Prefixes, s.bits)) == 0 {
				continue
			}
			for _, pe := range exprs {
				forward = append(forward, nftRule{
					stack:   s,
					expr:    fmt.Sprintf("%s %s saddr @%s counter drop", pe, s.proto(), s.portSet(g.Key)),
					comment: s.commentPort(g.Key),
				})
			}
		}
	}

	for i := len(forward) - 1; i >= 0; i-- {
		r := forward[i]
		fmt.Fprintf(&b, "insert rule %s %s %s %s comment \"%s\"\n",
			r.stack.target.Family, r.stack.target.Table, r.stack.target.Chain, r.expr, r.comment)
	}

	return b.String()
}

// nftPorts 渲染成 nft 集合字面量里的元素列表，例如 "80, 20000-30000"。
// 逗号后的空格只是给预览文本看的，nft 两种写法都认。
func nftPorts(s portrange.Set) string { return renderPorts(s, "-", ", ") }

// nftPortExprs 返回端口限定规则的端口匹配前缀，TCP 与 UDP 各一条。
//
// 两种协议都要：frps 的 bindPort 是 TCP，而 proxyPorts 里可能配了 UDP 代理端口，
// 只封 TCP 会留下一条用 UDP 绕过的路径。自定义端口同理 —— 用户填的是目的端口，
// 没理由替他假定只有 TCP。端口为空时返回 nil，调用方据此跳过，
// 而不是生成一条匹配不存在的端口的规则。
//
// 区间直接写进集合字面量（`{ 80, 20000-30000 }`），nft 原生支持，
// 所以 20000-30000 是一个元素，不是一万个。
func nftPortExprs(ports portrange.Set) []string {
	if len(ports) == 0 {
		return nil
	}
	list := nftPorts(ports)
	return []string{
		"tcp dport { " + list + " }",
		"udp dport { " + list + " }",
	}
}

// AddBlock 增量封禁一条，不做全量重建。
//
// 只往全端口集合里加：target 参数里没有"范围"这个维度，要按范围区分只能走
// Sync。当前没有调用方（封禁统一走全量 Sync），保留接口是为将来留个落点 ——
// 真要用它时得把范围一起加进签名，别只改一半。
func (d *nftablesDriver) AddBlock(target string) error {
	if !d.ready {
		if err := d.EnsureBase(); err != nil {
			return err
		}
	}
	ctx := context.Background()
	p, err := normalizeTarget(target)
	if err != nil {
		return err
	}
	s, err := d.stackForTarget(p)
	if err != nil {
		return err
	}
	// add element 幂等，重复添加不报错
	_, err = run(ctx, "nft", "add", "element", s.target.Family, s.target.Table, s.set(),
		"{", p.String(), "}")
	return err
}

// DelBlock 增量解封一条。同样只作用于全端口集合，理由见 AddBlock。
func (d *nftablesDriver) DelBlock(target string) error {
	if !d.ready {
		if err := d.EnsureBase(); err != nil {
			return err
		}
	}
	ctx := context.Background()
	p, err := normalizeTarget(target)
	if err != nil {
		return err
	}
	s, err := d.stackForTarget(p)
	if err != nil {
		return err
	}
	if _, err := run(ctx, "nft", "delete", "element", s.target.Family, s.target.Table, s.set(),
		"{", p.String(), "}"); err != nil {
		// 元素不存在时 nft 会报错，属于正常的幂等场景，忽略
		if strings.Contains(strings.ToLower(err.Error()), "no such file") ||
			strings.Contains(strings.ToLower(err.Error()), "not found") {
			return nil
		}
		return err
	}
	return nil
}

func (d *nftablesDriver) DumpManaged() (*ManagedRules, error) {
	if !d.ready {
		if err := d.EnsureBase(); err != nil {
			return nil, err
		}
	}
	ctx := context.Background()
	res := &ManagedRules{Backend: string(BackendNFTables)}

	var b strings.Builder
	// inet 家族下两个落点共用一条链，链内容只列一次，免得同一批规则重复出现。
	listedChain := make(map[nftTarget]bool, len(d.stacks))
	listedPortSets := make(map[nftTarget]bool, len(d.stacks))
	for _, s := range d.stacks {
		if !listedChain[s.target] {
			listedChain[s.target] = true
			out, err := run(ctx, "nft", "-a", "list", "chain", s.target.Family, s.target.Table, s.target.Chain)
			if err == nil {
				fmt.Fprintf(&b, "# nft -a list chain %s %s %s\n", s.target.Family, s.target.Table, s.target.Chain)
				for _, line := range strings.Split(out, "\n") {
					if strings.Contains(line, commentPrefix) {
						b.WriteString(strings.TrimSpace(line) + "\n")
						res.Summary = append(res.Summary, strings.TrimSpace(line))
					}
				}
			}
		}
		if s.bits == 32 {
			out, err := run(ctx, "nft", "-a", "list", "chain", s.target.Family, s.target.Table, nftRateChain)
			if err == nil {
				fmt.Fprintf(&b, "# nft -a list chain %s %s %s\n", s.target.Family, s.target.Table, nftRateChain)
				for _, line := range strings.Split(out, "\n") {
					if strings.Contains(line, commentPrefix) {
						b.WriteString(strings.TrimSpace(line) + "\n")
						res.Summary = append(res.Summary, strings.TrimSpace(line))
					}
				}
			}
		}
		// 集合逐个报数：只报一个总数的话，界面看到"黑名单 12 个元素"
		// 无从判断其中多少是全端口封、多少是限定了端口。
		res.Summary = append(res.Summary,
			fmt.Sprintf("%s 黑名单（全端口）: 集合 %s 内 %d 个元素",
				s.label(), s.set(), d.setSize(ctx, s, s.set())))

		// 端口限定的集合名字是算出来的，只能从内核里列出来再逐个报。
		// 报的是内核现状而不是期望状态 —— 显示"当前实际封着多少个地址"，
		// 正是这个接口存在的意义。
		if !listedPortSets[s.target] {
			listedPortSets[s.target] = true
			for _, name := range d.listOwnSets(ctx, s, isPortSetName) {
				res.Summary = append(res.Summary,
					fmt.Sprintf("%s 黑名单（端口限定）: 集合 %s 内 %d 个元素",
						s.label(), name, d.setSize(ctx, s, name)))
			}
		}
	}

	res.Raw = b.String()
	return res, nil
}

// Counters 读受管规则的丢包计数。
//
// 粒度只能到**规则**，到不了地址：地址装在集合里、规则只有一条，内核在规则上
// 数数。要做到按地址只能放弃集合、给每个地址单插一条规则，地址一多规则条数
// 就爆炸 —— 不值当。所以这里返回的条目是"全端口那一组""某个端口组""某条
// 限速规则"这种分组级别的量。
func (d *nftablesDriver) Counters() ([]RuleCounter, error) {
	if !d.ready {
		if err := d.EnsureBase(); err != nil {
			return nil, err
		}
	}
	ctx := context.Background()

	var out []RuleCounter
	// inet 家族下两个协议栈共用一条链，链只列一次，否则同一批规则会重复计数。
	listed := make(map[nftTarget]bool, len(d.stacks))
	for _, s := range d.stacks {
		if listed[s.target] {
			continue
		}
		listed[s.target] = true
		res, err := run(ctx, "nft", "-a", "list", "chain", s.target.Family, s.target.Table, s.target.Chain)
		if err != nil {
			continue
		}
		out = append(out, parseNFTCounters(res)...)
	}
	if s, ok := d.stackFor(32); ok {
		if raw, err := run(ctx, "nft", "-a", "list", "chain", s.target.Family, s.target.Table, nftRateChain); err == nil {
			out = append(out, parseNFTCounters(raw)...)
		}
	}
	return out, nil
}

// nftCounterRe / nftCommentRe 匹配 `nft list chain` 一条规则里的计数与归属注释。
//
// 只认同时带 comment 的规则：comment 是"这条规则属于本程序"的唯一标记，
// 链里还有系统自己的规则，没有 comment 的一概不算我们的。
var (
	nftCounterRe = regexp.MustCompile(`counter packets (\d+) bytes (\d+)`)
	nftCommentRe = regexp.MustCompile(`comment "([^"]*)"`)
)

// parseNFTCounters 解析 `nft -a list chain` 的输出。
//
// 抽成纯函数只为能单测：本机没有 nft，只有拿真实格式的输出样本喂进去这一条路。
func parseNFTCounters(raw string) []RuleCounter {
	out := make([]RuleCounter, 0, 8)
	for _, line := range strings.Split(raw, "\n") {
		cm := nftCommentRe.FindStringSubmatch(line)
		if cm == nil || !strings.Contains(cm[1], commentPrefix) {
			continue
		}
		// 没有 counter 表达式的规则数不出数：可能是老版本程序插进去的残留，
		// 也可能是 counter 被手工去掉了。跳过而不是报 0 —— 报 0 会让人以为
		// "这条规则在生效但一个包都没拦到"。
		ct := nftCounterRe.FindStringSubmatch(line)
		if ct == nil {
			continue
		}
		pkts, err1 := strconv.ParseUint(ct[1], 10, 64)
		octets, err2 := strconv.ParseUint(ct[2], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		comment := cm[1]
		kind, label := nftCounterKind(comment)
		out = append(out, RuleCounter{
			Kind: kind, Key: comment, Label: label,
			Family: nftCounterFamily(line), Packets: pkts, Bytes: octets,
		})
	}
	return out
}

// nftCounterKind 按规则注释判断这条计数属于哪一类。
func nftCounterKind(comment string) (kind, label string) {
	switch {
	case strings.HasPrefix(comment, commentPortPrefix):
		return CounterKindPort, "端口限定"
	case strings.HasPrefix(comment, commentRate):
		return CounterKindRate, "限速"
	case strings.HasPrefix(comment, commentBlack):
		return CounterKindGroup, "全端口封禁"
	}
	return CounterKindGroup, "受管规则"
}

// nftCounterFamily 从规则表达式里认协议栈，认不出返回空串。
//
// 不能用链的家族：inet 家族下一条链里同时装着 ip 与 ip6 的规则。
func nftCounterFamily(line string) string {
	switch {
	case strings.Contains(line, "ip6 saddr"):
		return "ipv6"
	case strings.Contains(line, "ip saddr"):
		return "ipv4"
	}
	return ""
}

func (d *nftablesDriver) setSize(ctx context.Context, s nftStack, name string) int {
	out, err := run(ctx, "nft", "-j", "list", "set", s.target.Family, s.target.Table, name)
	if err != nil {
		return 0
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return 0
	}
	for _, item := range doc.Nftables {
		raw, ok := item["set"]
		if !ok {
			continue
		}
		var st struct {
			Elem []json.RawMessage `json:"elem"`
		}
		if err := json.Unmarshal(raw, &st); err != nil {
			continue
		}
		return len(st.Elem)
	}
	return 0
}

func (d *nftablesDriver) DumpSystem() (string, error) {
	ctx := context.Background()
	out, err := run(ctx, "nft", "list", "ruleset")
	if err != nil {
		return "", err
	}
	return out, nil
}

// Preview 只生成规则脚本，不落盘。
//
// 事务部分直接复用 renderScript —— 预览的价值就在于"看到的等于会下发的"，
// 两份独立实现迟早会漂移，而漂移之后预览就成了误导。
func (d *nftablesDriver) Preview(des Desired) (string, error) {
	stacks := d.effectiveStacks()

	var b strings.Builder
	targets := make([]string, 0, len(stacks))
	seen := make(map[nftTarget]bool, len(stacks))
	for _, s := range stacks {
		if seen[s.target] {
			continue
		}
		seen[s.target] = true
		targets = append(targets, fmt.Sprintf("%s %s %s", s.target.Family, s.target.Table, s.target.Chain))
	}
	fmt.Fprintf(&b, "# nftables 规则预览（受管规则插入 %s 链首）\n\n", strings.Join(targets, "、"))

	fmt.Fprintf(&b, "# --- 集合定义（首次创建）---\n")
	if s, ok := stackOf(stacks, 32); ok {
		fmt.Fprintf(&b, "add chain %s %s %s\n", s.target.Family, s.target.Table, nftRateChain)
	}
	for _, s := range stacks {
		names := []string{s.set()}
		// 端口限定分组的集合名由端口签名派生，只有拿得到期望状态才算得出来，
		// 所以只能列在这里 —— 列出名字本身就是预览的一部分（内核里会是哪些对象）。
		for _, g := range portGroups(des) {
			names = append(names, s.portSet(g.Key))
		}
		for _, name := range names {
			fmt.Fprintf(&b, "add set %s %s %s { type %s; flags interval; }\n",
				s.target.Family, s.target.Table, name, s.setType())
		}
	}
	for _, p := range planRateRules(des.RateLimits) {
		s, ok := stackOf(stacks, 32)
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "add set %s %s %s { type ipv4_addr; flags dynamic,timeout; timeout 10s; }\n",
			s.target.Family, s.target.Table, p.set)
	}

	fmt.Fprintf(&b, "\n# --- 本次下发的原子事务 ---\n")
	b.WriteString(renderScript(stacks, des, nil, planRateRules(des.RateLimits)))

	fmt.Fprintf(&b, "\n# 白名单不写入内核：生成黑名单时会剔除白名单地址，效果等价且无 verdict 歧义。\n")
	return b.String(), nil
}

func (d *nftablesDriver) Snapshot() (string, error) {
	ctx := context.Background()
	var b strings.Builder
	listedChain := make(map[nftTarget]bool, len(d.stacks))
	listedPortSets := make(map[nftTarget]bool, len(d.stacks))
	for _, s := range d.stacks {
		if out, err := run(ctx, "nft", "list", "set", s.target.Family, s.target.Table, s.set()); err == nil {
			fmt.Fprintf(&b, "# set %s\n%s\n", s.set(), out)
		}
		// 端口限定与限速集合都是一条配置一个，名字是算出来的，只能先列出来再逐个 dump。
		if !listedPortSets[s.target] {
			listedPortSets[s.target] = true
			for _, name := range d.listOwnSets(ctx, s, isPortSetName) {
				if out, err := run(ctx, "nft", "list", "set", s.target.Family, s.target.Table, name); err == nil {
					fmt.Fprintf(&b, "# set %s\n%s\n", name, out)
				}
			}
		}
		if s.bits == 32 {
			if out, err := run(ctx, "nft", "-a", "list", "chain", s.target.Family, s.target.Table, nftRateChain); err == nil {
				fmt.Fprintf(&b, "# rate chain\n%s\n", out)
			}
			for _, name := range d.listOwnRateSets(ctx, s) {
				if out, err := run(ctx, "nft", "list", "set", s.target.Family, s.target.Table, name); err == nil {
					fmt.Fprintf(&b, "# set %s\n%s\n", name, out)
				}
			}
		}
		if !listedChain[s.target] {
			listedChain[s.target] = true
			if out, err := run(ctx, "nft", "-a", "list", "chain",
				s.target.Family, s.target.Table, s.target.Chain); err == nil {
				fmt.Fprintf(&b, "# chain %s %s %s\n%s\n",
					s.target.Family, s.target.Table, s.target.Chain, out)
			}
		}
	}
	return b.String(), nil
}

// Restore 拒绝重放包含系统规则的 nft 文本快照；恢复由期望状态 Sync 承担。
func (d *nftablesDriver) Restore(snapshot string) error {
	return fmt.Errorf("nft 快照仅用于检查；恢复请通过期望状态重新同步，禁止重放系统规则")
}

// managedRuleHandles 找出某条链里归属本程序的规则 handle（靠 comment 标记识别）。
func (d *nftablesDriver) managedRuleHandles(ctx context.Context, s nftStack) ([]int, error) {
	out, err := run(ctx, "nft", "-a", "list", "chain", s.target.Family, s.target.Table, s.target.Chain)
	if err != nil {
		return nil, fmt.Errorf("读取受管规则失败: %w", err)
	}
	var handles []int
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, commentPrefix) {
			continue
		}
		if m := reHandle.FindStringSubmatch(line); len(m) > 1 {
			if n, err := strconv.Atoi(m[1]); err == nil {
				handles = append(handles, n)
			}
		}
	}
	return handles, nil
}

var reHandle = regexp.MustCompile(`#\s*handle\s+(\d+)`)

// ---- 落点查找 ----

// stackOf 从落点列表里取指定地址族的那个。
func stackOf(stacks []nftStack, bits int) (nftStack, bool) {
	for _, s := range stacks {
		if s.bits == bits {
			return s, true
		}
	}
	return nftStack{}, false
}

func (d *nftablesDriver) stackFor(bits int) (nftStack, bool) {
	return stackOf(d.stacks, bits)
}

// stackForTarget 找到该地址该去的落点。
//
// 找不到时返回错误而不是静默成功：静默成功会让用户以为已经封上了，
// 而实际上那个协议栈的规则根本没下发（机器只有 ip 链、却要封一个 v6 地址）。
func (d *nftablesDriver) stackForTarget(p netip.Prefix) (nftStack, error) {
	bits := p.Addr().BitLen()
	s, ok := d.stackFor(bits)
	if !ok {
		label := "IPv4"
		if bits == 128 {
			label = "IPv6"
		}
		return nftStack{}, fmt.Errorf("当前没有可用的 %s INPUT 链，%s 地址无法下发到防火墙", label, label)
	}
	return s, nil
}

// effectiveStacks 返回可用于预览的落点。
// 真实落点要先 EnsureBase 才知道；还没探测过就按"自建 inet 单链双栈"假设，
// 与 createDefaultChain 的结果一致，这样最早的预览也有意义。
func (d *nftablesDriver) effectiveStacks() []nftStack {
	if len(d.stacks) > 0 {
		return d.stacks
	}
	t := nftTarget{Family: "inet", Table: "filter", Chain: "input"}
	return []nftStack{{target: t, bits: 32}, {target: t, bits: 128}}
}

// halfStackWarning 描述"只找到一个协议栈的 INPUT 链"这个状态。
//
// 这不是可以忽略的小事：nftables 的 ip 与 ip6 家族互不相通，缺了哪一半，
// 那个协议栈的封禁就完全不生效。机器如果有那一半的连通性，被封的地址换个
// 协议栈就能绕过 —— 而这从界面上看不出来。
func halfStackWarning(missing string) string {
	present := "IPv4"
	if missing == "IPv4" {
		present = "IPv6"
	}
	return fmt.Sprintf(
		"系统里只有 %s 的 INPUT 链，%s 封禁无法下发（nftables 的 ip 与 ip6 家族互不相通，两族各需一条 INPUT 链）。"+
			"这台机器若有 %s 连通性，被封的地址换个协议栈即可绕过。",
		present, missing, missing)
}

// nftRatePlan 是一条限速规则在 nft 上的落地形态：规则本身 + 它专用的动态集合名。
type nftRatePlan struct {
	set  string
	rule RateLimitRule
}

// planRateRules 选出能在 IPv4 落点上表达出来的限速规则。
//
// nft 的动态集合元素类型是 ipv4_addr，所以限速只落在 IPv4 链上。
// 来源段按协议栈过滤的事交给 filterRateRules —— 那条判断错了不会报错，
// 只会静默放大成全网限速，两个驱动共用一份实现。
func planRateRules(list []RateLimitRule) []nftRatePlan {
	out := make([]nftRatePlan, 0, len(list))
	for _, r := range filterRateRules(list, 32) {
		if r.PerSec <= 0 {
			continue
		}
		out = append(out, nftRatePlan{set: rateSetName(r.Key), rule: r})
	}
	return out
}

// nftRateExpr 生成一条 per-IP 连接速率限制表达式。
//
// nftables 没有 hashlimit 等价物，标准做法是用带 timeout 的动态集合计数：
//
//	tcp dport { 20000-30000 } ct state new add @frpfirewall_rate_x { ip saddr limit rate over 20/second burst 40 packets } counter drop
//
// 表达式只对 IPv4 有效（集合元素类型是 ipv4_addr），所以只用在 IPv4 落点上。
//
// 来源条件写成集合字面量而不是拆成多条规则：来源数量不该把规则条数乘上去，
// 而且这些规则共用同一个集合与同一张计数表，拆开反而要小心别让配额翻倍。
func nftRateExpr(r RateLimitRule, set string) (string, bool) {
	if r.PerSec <= 0 || set == "" {
		return "", false
	}

	var b strings.Builder
	if len(r.Sources) > 0 {
		fmt.Fprintf(&b, "ip saddr { %s } ", strings.Join(r.Sources, ", "))
	}
	if ps := r.Ports.Normalize(); len(ps) > 0 {
		// 限速规则是单条规则，没法像 iptables 那样按块拆，所以这里直接
		// 把整个区间集合写进集合字面量 —— 区间写法让它天然只有几个元素。
		fmt.Fprintf(&b, "tcp dport { %s } ", nftPorts(ps))
	} else {
		b.WriteString("meta l4proto tcp ")
	}
	// counter 同样放在 drop 之前：drop 之后写的表达式不会被执行。
	fmt.Fprintf(&b, "ct state new add @%s { ip saddr limit rate over %d/second burst %d packets } counter drop",
		set, r.PerSec, r.burst())
	return b.String(), true
}

// listOwnSets 列出某个落点里名字满足 match 的集合。
//
// 只认 nft -j 的输出：`nft list sets` 的文本格式会按列宽折行，
// 用正则去啃迟早会栽在某个版本上（这套代码里已经栽过一次）。
func (d *nftablesDriver) listOwnSets(ctx context.Context, s nftStack, match func(string) bool) []string {
	out, err := run(ctx, "nft", "-j", "list", "sets")
	if err != nil {
		return nil
	}

	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil
	}

	var names []string
	for _, item := range doc.Nftables {
		raw, ok := item["set"]
		if !ok {
			continue
		}
		var st struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
		}
		if err := json.Unmarshal(raw, &st); err != nil {
			continue
		}
		if st.Family != s.target.Family || st.Table != s.target.Table {
			continue
		}
		if !match(st.Name) {
			continue
		}
		names = append(names, st.Name)
	}
	return names
}

// listOwnRateSets 列出内核里属于本程序的限速集合。
func (d *nftablesDriver) listOwnRateSets(ctx context.Context, s nftStack) []string {
	return d.listOwnSets(ctx, s, isRateSetName)
}

// pruneRateSets 删掉内核里不再需要的限速集合。
//
// 动态集合的元素会自己过期，但集合本身不会消失。规则改速率、改条件、删掉之后，
// 旧集合会一直留着 —— 不参与判决（规则每次全量重建），却会在 `nft list sets`
// 里越堆越多，排障时得先去认哪些是废的。删不掉也不影响功能，所以忽略错误。
func (d *nftablesDriver) pruneRateSets(ctx context.Context, rates []nftRatePlan) {
	s, ok := d.stackFor(32)
	if !ok {
		return
	}
	keep := make(map[string]bool, len(rates))
	for _, p := range rates {
		keep[p.set] = true
	}
	for _, name := range d.listOwnRateSets(ctx, s) {
		if keep[name] {
			continue
		}
		_, _ = run(ctx, "nft", "delete", "set", s.target.Family, s.target.Table, name)
	}
}

// nftVersionAtLeast 比较 nftables 版本号。
func nftVersionAtLeast(v string, major, minor, patch int) bool {
	if v == "" {
		return false
	}
	parts := strings.Split(v, ".")
	nums := make([]int, 0, 3)
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimFunc(p, func(r rune) bool { return r < '0' || r > '9' }))
		if err != nil {
			break
		}
		nums = append(nums, n)
		if len(nums) == 3 {
			break
		}
	}
	want := []int{major, minor, patch}
	for i := 0; i < 3; i++ {
		got := 0
		if i < len(nums) {
			got = nums[i]
		}
		if got > want[i] {
			return true
		}
		if got < want[i] {
			return false
		}
	}
	return true
}
