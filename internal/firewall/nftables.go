package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// nftables 驱动的设计要点
//
// 关键约束一：**不自己创建带 hook 的 base chain**。
//
// 原因是 nftables 的 verdict 语义 —— 同一个 hook 上的多个 base chain 按 priority
// 依次执行，一旦某个链给出 accept（包括链尾 policy accept），后续链就不再评估。
// 如果我们建一个 `type filter hook input priority -150; policy accept;` 的链，
// 那么所有包走到链尾都会被 accept，系统原有的 input 链（ufw / 手工规则）将完全失效。
// 这是灾难性的。
//
// 所以正确做法是：把规则**插入到系统已有 input base chain 的最前面**。
// 这样天然共享同一套判决流程，我们的规则对不匹配的包"什么都不做"，自然往下走。
//
// 系统没有 input 链时（全新 Debian/Ubuntu 未启用任何防火墙工具），
// 才创建标准的 `table inet filter` + `chain input`。
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
	if !d.report.HasNFTables {
		c.Reason = "未找到 nft 命令，Debian/Ubuntu 请执行 apt install nftables"
	} else if !c.RateLimit {
		c.Reason = fmt.Sprintf("nftables %s 版本过低，不支持动态集合（per-IP 限速需要 >= 0.9.3）", d.report.NFTablesVersion)
	}
	return c
}

// EnsureBase 定位（或创建）input base chain，按协议栈记录落点，并保证集合存在。
func (d *nftablesDriver) EnsureBase() error {
	ctx := context.Background()

	chains := d.inputChains(ctx)
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
	}
	d.ready = true
	return nil
}

// createDefaultChain 在系统里没有任何 INPUT base chain 时建一个标准的 inet 链。
//
// 只在"什么都没有"时才走这条路 —— 有链可插入时绝不新建，见文件头的关键约束一。
func (d *nftablesDriver) createDefaultChain(ctx context.Context) (nftTarget, error) {
	if _, err := run(ctx, "nft", "add", "table", "inet", "filter"); err != nil && !isAlreadyExists(err) {
		return nftTarget{}, fmt.Errorf("创建 table inet filter 失败: %w", err)
	}
	if _, err := run(ctx, "nft", "add", "chain", "inet", "filter", "input",
		"{", "type", "filter", "hook", "input", "priority", "filter", ";",
		"policy", "accept", ";", "}"); err != nil && !isAlreadyExists(err) {
		return nftTarget{}, fmt.Errorf("创建 input 链失败: %w", err)
	}
	return nftTarget{Family: "inet", Table: "filter", Chain: "input"}, nil
}

// inputChains 一次性取回 ruleset 里所有 INPUT base chain，按家族归组。
// 同家族有多个候选取 priority 最小的（最先执行，我们的 drop 也就能最早生效）。
//
// 只调用一次 nft：原先是按家族各跑一遍 list ruleset，三倍开销。
func (d *nftablesDriver) inputChains(ctx context.Context) map[string]nftTarget {
	out, err := run(ctx, "nft", "-j", "list", "ruleset")
	if err != nil {
		return nil
	}

	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil
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
			continue
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
		found[ch.Family] = nftTarget{Family: ch.Family, Table: ch.Table, Chain: ch.Name}
		prio[ch.Family] = ch.Prio
	}
	return found
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
func (d *nftablesDriver) Sync(des Desired) error {
	if err := d.EnsureBase(); err != nil {
		return err
	}
	ctx := context.Background()

	// 按链去重地取受管规则 handle。inet 家族下两个协议栈共用一条链，
	// 不去重就会把同一个 handle 在同一个事务里删两次，nft 找不到第二条即报错，
	// 整份脚本随之失败 —— 连"删掉旧规则"这一步都做不到。
	handles := make(map[nftTarget][]int, len(d.stacks))
	for _, s := range d.stacks {
		if _, done := handles[s.target]; done {
			continue
		}
		handles[s.target] = d.managedRuleHandles(ctx, s)
	}

	// 连接速率限制要先确认动态集合能建出来（老版本 nftables 不支持）。
	// 只有 IPv4 落点能做：动态集合的元素类型是 ipv4_addr，IPv6 得另建一个
	// ipv6_addr 的动态集合。与其为了对称下发一条在 ip6 家族里语法不合法的
	// 规则（整份事务会被拒），不如在这一半上干脆跳过。
	rateOn := false
	if des.RateLimit != nil && des.RateLimit.Enabled && d.Capability().RateLimit {
		if s, ok := d.stackFor(32); ok {
			if err := d.ensureSet(ctx, s, setRate, "ipv4_addr", true); err == nil {
				rateOn = true
			} else {
				d.warn("当前 nftables 不支持动态集合，已跳过 per-IP 连接速率限制")
			}
		}
	}

	script := renderScript(d.stacks, des, handles, rateOn)

	// 语法预检：不通过就整个放弃，绝不带着半截规则上生产。
	if _, err := runStdin(ctx, script, "nft", "-c", "-f", "-"); err != nil {
		return fmt.Errorf("规则语法预检失败，已放弃本次下发: %w\n%s", err, script)
	}
	if _, err := runStdin(ctx, script, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("下发规则失败: %w", err)
	}
	return nil
}

// renderScript 生成一次 Sync 要提交的全部 nft 语句。
//
// 抽成纯函数是为了能被测：这类脚本只有在真实内核上才会被拒绝，而"生成了 ip6
// 表达式却落在 ip 家族的链上"这种错误，用桩命令测永远发现不了（桩只会点头），
// 看脚本本身却一眼可见。Preview 也复用它，保证"预览到的"就是"会下发的"。
//
// handles 按链给出要删的规则 handle；rateOn 表示限速规则是否可以下发。
func renderScript(stacks []nftStack, des Desired, handles map[nftTarget][]int, rateOn bool) string {
	var b strings.Builder

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
	for _, s := range stacks {
		black := filterByFamily(des.Blacklist, s.bits)
		fmt.Fprintf(&b, "flush set %s %s %s\n", s.target.Family, s.target.Table, s.set())
		if len(black) > 0 {
			fmt.Fprintf(&b, "add element %s %s %s { %s }\n",
				s.target.Family, s.target.Table, s.set(), strings.Join(black, ", "))
		}
	}

	// 3. 限速规则。表达式里的 saddr 是 IPv4 的，所以只落在 v4 链上。
	if rateOn {
		if expr, ok := nftRateLimitExpr(des.RateLimit, des.ProtectPorts); ok {
			if s, ok := stackOf(stacks, 32); ok {
				fmt.Fprintf(&b, "insert rule %s %s %s %s comment \"%s\"\n",
					s.target.Family, s.target.Table, s.target.Chain, expr, commentRate)
			}
		}
	}

	// 4. 重新插入黑名单规则。insert 始终插到链首，所以按落点倒着插。
	//    同一条链上（inet 的情况）最终顺序是 IPv4 → IPv6 → 限速；
	//    先判 v4 还是 v6 不影响结果，两个集合的地址不可能同时命中。
	for i := len(stacks) - 1; i >= 0; i-- {
		s := stacks[i]
		fmt.Fprintf(&b, "insert rule %s %s %s %s saddr @%s drop comment \"%s\"\n",
			s.target.Family, s.target.Table, s.target.Chain, s.proto(), s.set(), s.comment())
	}

	return b.String()
}

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
		res.Summary = append(res.Summary,
			fmt.Sprintf("%s 黑名单: 集合 %s 内 %d 个元素", s.label(), s.set(), d.setSize(ctx, s)))
	}

	res.Raw = b.String()
	return res, nil
}

func (d *nftablesDriver) setSize(ctx context.Context, s nftStack) int {
	out, err := run(ctx, "nft", "-j", "list", "set", s.target.Family, s.target.Table, s.set())
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
	for _, s := range stacks {
		fmt.Fprintf(&b, "add set %s %s %s { type %s; flags interval; }\n",
			s.target.Family, s.target.Table, s.set(), s.setType())
	}

	fmt.Fprintf(&b, "\n# --- 本次下发的原子事务 ---\n")
	b.WriteString(renderScript(stacks, des, nil, des.RateLimit != nil && des.RateLimit.Enabled))

	fmt.Fprintf(&b, "\n# 白名单不写入内核：生成黑名单时会剔除白名单地址，效果等价且无 verdict 歧义。\n")
	return b.String(), nil
}

func (d *nftablesDriver) Snapshot() (string, error) {
	ctx := context.Background()
	var b strings.Builder
	listedChain := make(map[nftTarget]bool, len(d.stacks))
	for _, s := range d.stacks {
		if out, err := run(ctx, "nft", "list", "set", s.target.Family, s.target.Table, s.set()); err == nil {
			fmt.Fprintf(&b, "# set %s\n%s\n", s.set(), out)
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

// Restore 对 nftables 来说等价于重放一次期望状态，由上层 Sync 承担，
// 这里只保证清空受管对象不出错。
func (d *nftablesDriver) Restore(snapshot string) error {
	ctx := context.Background()
	if !d.ready {
		return nil
	}
	for _, s := range d.stacks {
		_, _ = run(ctx, "nft", "flush", "set", s.target.Family, s.target.Table, s.set())
		for _, h := range d.managedRuleHandles(ctx, s) {
			_, _ = run(ctx, "nft", "delete", "rule", s.target.Family, s.target.Table, s.target.Chain,
				"handle", strconv.Itoa(h))
		}
	}
	// 限速集合只建在 IPv4 落点上（见 Sync 的说明）
	if s, ok := d.stackFor(32); ok {
		_, _ = run(ctx, "nft", "flush", "set", s.target.Family, s.target.Table, setRate)
	}
	return nil
}

// managedRuleHandles 找出某条链里归属本程序的规则 handle（靠 comment 标记识别）。
func (d *nftablesDriver) managedRuleHandles(ctx context.Context, s nftStack) []int {
	out, err := run(ctx, "nft", "-a", "list", "chain", s.target.Family, s.target.Table, s.target.Chain)
	if err != nil {
		return nil
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
	return handles
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

// nftRateLimitExpr 生成 per-IP 连接速率限制表达式。
//
// nftables 没有 hashlimit 等价物，标准做法是用带 timeout 的动态集合计数：
//
//	tcp dport { 7000 } ct state new add @frpfirewall_rate { ip saddr limit rate over 20/second burst 40 packets } drop
//
// 表达式只对 IPv4 有效（集合元素类型是 ipv4_addr），所以只用在 IPv4 落点上。
func nftRateLimitExpr(spec *RateLimitSpec, ports []int) (string, bool) {
	if spec == nil || !spec.Enabled || spec.PerSec <= 0 {
		return "", false
	}
	burst := spec.Burst
	if burst <= 0 {
		burst = spec.PerSec * 2
	}

	var b strings.Builder
	if len(ports) > 0 {
		ps := make([]string, 0, len(ports))
		for _, p := range ports {
			ps = append(ps, strconv.Itoa(p))
		}
		fmt.Fprintf(&b, "tcp dport { %s } ", strings.Join(ps, ", "))
	} else {
		b.WriteString("tcp ")
	}
	fmt.Fprintf(&b, "ct state new add @%s { ip saddr limit rate over %d/second burst %d packets } drop",
		setRate, spec.PerSec, burst)
	return b.String(), true
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
