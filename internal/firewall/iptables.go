package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/dreamstation625/FrpFireWall/internal/portrange"
)

// iptables 驱动的受管结构：
//
//	INPUT ─(第1条)─▶ FRPFIREWALL_GUARD
//	                   ├─ -j FRPFIREWALL_BLACK            ← 全端口黑名单
//	                   ├─ -j FRPFIREWALL_BLACK_FRP        ← 端口限定黑名单
//	                   ├─ [限速规则]                 ← 可选
//	                   └─ -j RETURN
//	FRPFIREWALL_BLACK
//	                   └─ -s <黑名单> -j DROP        ← 逐条，不带端口限定
//	FRPFIREWALL_BLACK_FRP
//	                   └─ -s <黑名单> -p tcp -m multiport --dports ... -j DROP
//
// 两条黑名单子链的先后不影响结果（全端口是端口限定的超集），按"从严到宽"排
// 只是为了让 `iptables -S` 的输出自解释。
//
// 端口限定子链（链名里的 FRP 是历史遗留，见 driver.go 的说明）里同时装着
// 「仅 frp 端口」与「自定义端口」两类条目：它们的规则形状一样，都是地址加
// dport，DROP 之间也没有先后之分，所以只用一条链。
//
// 为什么黑名单要单独一个子链：
//
//	增量封禁/解封是高频操作，如果黑名单规则直接写在主链里，
//	每次插入都要算"插到第几条"，还要处理删除后序号漂移。
//	放进独立子链后，追加就是 -A FRPFIREWALL_BLACK，删除就是 -D FRPFIREWALL_BLACK -s X，
//	完全不依赖位置，也不会踩序号陷阱。
//
// 为什么白名单不写内核规则：
//
//	白名单的语义是"豁免本程序封禁"，而不是"放行全端口"。
//	所以正确做法是在上层生成黑名单时把白名单地址减掉，效果完全等价。
//	这样既避免了 ACCEPT 带来的"绕过系统所有既有规则"的后门风险，
//	也避开了 return verdict 在不同链路上下文里的歧义。

type ipFamily struct {
	name string // ipv4 / ipv6
	bin  string // iptables / ip6tables
	bits int    // 32 / 128
}

type iptablesDriver struct {
	report *Report
	fams   []ipFamily
}

func newIPTablesDriver(report *Report) *iptablesDriver {
	d := &iptablesDriver{report: report}
	if _, ok := lookPath("iptables"); ok {
		d.fams = append(d.fams, ipFamily{name: "ipv4", bin: "iptables", bits: 32})
	}
	if _, ok := lookPath("ip6tables"); ok {
		d.fams = append(d.fams, ipFamily{name: "ipv6", bin: "ip6tables", bits: 128})
	}
	return d
}

func (d *iptablesDriver) Name() string { return string(BackendIPTables) }

func (d *iptablesDriver) Capability() Capability {
	c := Capability{
		Backend:   string(BackendIPTables),
		Version:   d.report.IPTablesVersion,
		Supported: len(d.fams) > 0,
	}
	if d.report.HasIPTables {
		c.RateLimit = true // hashlimit 自 iptables 1.4 起都有
		// 每个地址一条规则，所以计数能细到地址。
		c.CounterGranularity = CounterKindAddr
	} else {
		c.Reason = "未找到 iptables 命令"
	}
	return c
}

// EnsureBase 幂等创建受管链，并把跳转挂进 INPUT。
func (d *iptablesDriver) EnsureBase() error {
	ctx := context.Background()
	for _, f := range d.fams {
		for _, chain := range []string{ManagedChain, managedBlackChain, managedPortBlackChain} {
			if _, err := run(ctx, f.bin, "-N", chain); err != nil {
				if !isAlreadyExists(err) {
					return fmt.Errorf("创建链 %s 失败: %w", chain, err)
				}
			}
		}
		// INPUT 里挂跳转，--wait 避免与其它工具抢 xtables 锁。
		if _, err := run(ctx, f.bin, "-w", "-C", "INPUT", "-j", ManagedChain); err != nil {
			if _, err := run(ctx, f.bin, "-w", "-I", "INPUT", "1", "-j", ManagedChain); err != nil {
				return fmt.Errorf("把 %s 挂到 INPUT 失败: %w", ManagedChain, err)
			}
		}
	}
	return nil
}

// Sync 全量重建受管链，使实际状态对齐期望状态。幂等，可随时重放。
func (d *iptablesDriver) Sync(des Desired) error {
	if err := d.EnsureBase(); err != nil {
		return err
	}
	ctx := context.Background()
	for _, f := range d.fams {
		if err := d.syncFamily(ctx, f, des); err != nil {
			return err
		}
	}
	return nil
}

// iptRule 是一条待下发的规则。Soft 为真表示失败不阻断整次同步 ——
// 用于限速这类"模块不可用就降级"的增强能力。
type iptRule struct {
	Args []string
	Soft bool
}

// iptPortGroup 是一个端口限定分组在本协议栈上的落地形态：
// 已按地址族筛过的地址 + 已归一化的端口。
type iptPortGroup struct {
	Key   string
	Label string
	Addrs []string
	Ports portrange.Set
}

// iptRules 是一个协议栈本次要下发的全部规则。
//
// Sync 与 Preview 共用它。iptables 侧原本是两处各自手写规则拼装，加一个维度
// 就得记得改两处，漏一处就是"预览与实际下发不符"——这种问题在排障时最费时间，
// 因为你会先相信预览。
type iptRules struct {
	// Guard 是主链里的规则，按顺序。
	Guard []iptRule
	// Black 是全端口封禁的地址（已按协议栈过滤）。
	Black []string
	// PortGroups 是端口限定封禁的分组（已按协议栈过滤并丢弃空组）。
	PortGroups []iptPortGroup
}

func buildIPTablesRules(des Desired, bits int) iptRules {
	r := iptRules{
		Black: filterByFamily(des.Blacklist, bits),
	}

	// 空端口、以及在本协议栈下没有地址的分组直接丢掉：前者生成不出规则，
	// 后者生成的规则匹配不到任何来源。两种情况都会让 `iptables -S` 里多出
	// 一批读不懂的规则，而真正的"没生效"却要靠告警去发现（见 syncFamily）。
	for _, g := range des.PortBlacklists {
		addrs := filterByFamily(g.Prefixes, bits)
		if len(addrs) == 0 {
			continue
		}
		// 驱动入口再归一化一次：直接手写 Set 字面量的调用方不会经过归一化，
		// 而越界的端口会让整条命令被内核拒掉，连带同批正常规则一起失败。
		ports := g.Ports.Normalize()
		if len(ports) == 0 {
			continue
		}
		r.PortGroups = append(r.PortGroups, iptPortGroup{
			Key: g.Key, Label: g.Label, Addrs: addrs, Ports: ports,
		})
	}

	// 顺序即优先级：全端口在前，端口限定在后。
	r.Guard = append(r.Guard,
		iptRule{Args: []string{"-A", ManagedChain, "-j", managedBlackChain}},
		iptRule{Args: []string{"-A", ManagedChain, "-j", managedPortBlackChain}},
	)

	// 连接速率限制（per-IP），放在封禁判定之后、兜底 RETURN 之前。
	//
	// 顺序就是优先级：全局兜底规则在最前面（作用面最宽），细分规则依次排在后面。
	// 想让"细分优先"真正成立，上层编译时就得把细分规则放在前面 ——
	// 这里不做任何重排，照单下发。
	for _, rl := range filterRateRules(des.RateLimits, bits) {
		for _, args := range rateLimitArgs(rl) {
			r.Guard = append(r.Guard, iptRule{
				Args: append([]string{"-A", ManagedChain}, args...),
				Soft: true,
			})
		}
	}

	// 兜底 RETURN：不匹配的流量回到 INPUT 继续走系统原有规则。
	r.Guard = append(r.Guard, iptRule{Args: []string{"-A", ManagedChain, "-j", "RETURN"}})
	return r
}

// iptPorts 渲染成 iptables multiport 的 --dports 参数，例如 "80,20000:30000"。
// 逗号后不能有空格：multiport 把整串当一个参数解析，多一个空格就是格式错误。
func iptPorts(s portrange.Set) string { return renderPorts(s, ":", ",") }

// portBlockRules 展开"只在指定端口上封禁"的全部分组的规则。
//
// 两种协议都封：frps 的 bindPort 是 TCP，但 proxyPorts 里可能配了 UDP 代理端口，
// 只封 TCP 会留下一条用 UDP 绕过的路径。自定义端口同样按两种协议封 —— 用户填的
// 是"目的端口"，没有理由替他假定只有 TCP。
//
// 端口按「区间个数」切块：multiport 一次最多认 15 个端口或区间，而一个区间
// 无论多宽都只占一个名额 —— 所以 20000-30000 是一条规则，不是一千多条。
func portBlockRules(groups []iptPortGroup) [][]string {
	total := 0
	for _, g := range groups {
		total += len(g.Addrs) * len(g.Ports.Chunks(multiportMax)) * 2
	}
	if total == 0 {
		return nil
	}
	out := make([][]string, 0, total)
	for _, g := range groups {
		for _, addr := range g.Addrs {
			for _, chunk := range g.Ports.Chunks(multiportMax) {
				for _, proto := range []string{"tcp", "udp"} {
					out = append(out, []string{
						"-A", managedPortBlackChain, "-s", addr,
						"-p", proto, "-m", "multiport", "--dports", iptPorts(chunk),
						"-j", "DROP",
					})
				}
			}
		}
	}
	return out
}

// warn 追加一条告警，重复的不再追加（Sync 每次都会重跑，不去重会堆一长串）。
func (d *iptablesDriver) warn(msg string) {
	for _, w := range d.report.Warnings {
		if w == msg {
			return
		}
	}
	d.report.Warnings = append(d.report.Warnings, msg)
}

func (d *iptablesDriver) syncFamily(ctx context.Context, f ipFamily, des Desired) error {
	rules := buildIPTablesRules(des, f.bits)

	// 先清空自己的链——只动受管命名空间，绝不碰系统其它规则。
	for _, chain := range []string{ManagedChain, managedBlackChain, managedPortBlackChain} {
		if _, err := run(ctx, f.bin, "-w", "-F", chain); err != nil {
			return fmt.Errorf("清空 %s 失败: %w", chain, err)
		}
	}

	for _, rule := range rules.Guard {
		full := append([]string{"-w"}, rule.Args...)
		if _, err := run(ctx, f.bin, full...); err != nil {
			if rule.Soft {
				// 限速是增强能力，模块不可用时降级而不是让整次同步失败。
				d.warn(fmt.Sprintf("%s 下发连接速率限制失败，已跳过：%v", f.name, err))
				continue
			}
			return fmt.Errorf("写入主链规则失败: %w", err)
		}
	}

	// 黑名单逐条写入子链。
	for _, b := range rules.Black {
		if _, err := run(ctx, f.bin, "-w", "-A", managedBlackChain, "-s", b, "-j", "DROP"); err != nil {
			return fmt.Errorf("写入黑名单 %s 失败: %w", b, err)
		}
	}

	// 端口限定分组里没端口的那一类，生成不出 dport 条件。静默跳过会让"设了
	// 端口限定范围"看起来生效了、实际一条规则都没有 —— 这种"以为封了其实没封"
	// 必须报出来。按 Desired 里的原始分组报，不能用过滤后的（过滤时已经丢掉了）。
	for _, g := range des.PortBlacklists {
		if len(g.Ports.Normalize()) == 0 && len(g.Prefixes) > 0 {
			d.warn(fmt.Sprintf(
				"有 %d 个地址属于「%s」，但这一组没有配置任何端口，这些条目暂未下发",
				len(g.Prefixes), g.Label))
		}
	}
	for _, args := range portBlockRules(rules.PortGroups) {
		full := append([]string{"-w"}, args...)
		if _, err := run(ctx, f.bin, full...); err != nil {
			return fmt.Errorf("写入端口限定黑名单失败: %w", err)
		}
	}
	return nil
}

// AddBlock 增量封禁一条，不做全量重建。
//
// 只写全端口子链：target 参数里没有"范围"这个维度，要按范围区分只能走 Sync。
// 当前没有调用方（封禁统一走全量 Sync），保留接口是为将来需要秒级增量时留个
// 落点 —— 真要用它时得把范围一起加进签名，别只改一半。
func (d *iptablesDriver) AddBlock(target string) error {
	ctx := context.Background()
	p, err := normalizeTarget(target)
	if err != nil {
		return err
	}
	var firstErr error
	for _, f := range d.fams {
		if p.Addr().BitLen() != f.bits {
			continue
		}
		spec := p.String()
		// 幂等：已存在就跳过。
		if _, err := run(ctx, f.bin, "-w", "-C", managedBlackChain, "-s", spec, "-j", "DROP"); err == nil {
			continue
		}
		if _, err := run(ctx, f.bin, "-w", "-A", managedBlackChain, "-s", spec, "-j", "DROP"); err != nil {
			firstErr = fmt.Errorf("封禁 %s 失败: %w", spec, err)
		}
	}
	return firstErr
}

// DelBlock 增量解封一条。
func (d *iptablesDriver) DelBlock(target string) error {
	ctx := context.Background()
	p, err := normalizeTarget(target)
	if err != nil {
		return err
	}
	var firstErr error
	for _, f := range d.fams {
		if p.Addr().BitLen() != f.bits {
			continue
		}
		spec := p.String()
		if _, err := run(ctx, f.bin, "-w", "-C", managedBlackChain, "-s", spec, "-j", "DROP"); err != nil {
			continue // 本来就不存在
		}
		if _, err := run(ctx, f.bin, "-w", "-D", managedBlackChain, "-s", spec, "-j", "DROP"); err != nil {
			firstErr = fmt.Errorf("解封 %s 失败: %w", spec, err)
		}
	}
	return firstErr
}

func (d *iptablesDriver) DumpManaged() (*ManagedRules, error) {
	ctx := context.Background()
	res := &ManagedRules{Backend: string(BackendIPTables)}
	var raw strings.Builder

	// 主链的规则逐条列出；两条黑名单子链只报条数 —— 上百个地址会把摘要淹掉。
	// 完整内容仍然在 Raw 里，界面上可展开查看。
	for _, f := range d.fams {
		if out, err := run(ctx, f.bin, "-w", "-S", ManagedChain); err == nil {
			raw.WriteString("# " + f.bin + " -S " + ManagedChain + "\n")
			raw.WriteString(out)
			for _, line := range strings.Split(out, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "-A ") {
					res.Summary = append(res.Summary, line)
				}
			}
		}

		for _, item := range []struct{ chain, label string }{
			{managedBlackChain, "全端口"},
			{managedPortBlackChain, "端口限定"},
		} {
			out, err := run(ctx, f.bin, "-w", "-S", item.chain)
			if err != nil {
				continue
			}
			raw.WriteString("\n# " + f.bin + " -S " + item.chain + "\n")
			raw.WriteString(out)
			n := 0
			for _, line := range strings.Split(out, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "-A ") {
					n++
				}
			}
			res.Summary = append(res.Summary,
				fmt.Sprintf("%s: %s 链内封禁 %d 条（%s）", f.name, item.chain, n, item.label))
		}
	}

	res.Raw = raw.String()
	return res, nil
}

// Counters 读两条黑名单子链的丢包计数。
//
// 主链（FRPFIREWALL_GUARD）里的跳转规则不统计：它的计数只是"进了这条链多少
// 包"，而里面真正 DROP 的是子链里的规则，两边数会重复。
func (d *iptablesDriver) Counters() ([]RuleCounter, error) {
	ctx := context.Background()
	var out []RuleCounter
	for _, f := range d.fams {
		for _, item := range []struct {
			chain string
			kind  string
		}{
			{managedBlackChain, CounterKindAddr},
			{managedPortBlackChain, CounterKindPort},
		} {
			// -L -n -v -x 是拿计数的唯一组合：-S 不带计数列、-v 才有 pkts/bytes、
			// -x 关掉 K/M/G 的单位换算（不关的话读出来是 "12M" 这种字符串）。
			res, err := run(ctx, f.bin, "-w", "-L", item.chain, "-n", "-v", "-x")
			if err != nil {
				// 链还不存在（没跑过 EnsureBase）不算错误，跳过这一族即可。
				continue
			}
			out = append(out, parseIPTablesCounters(res, f.name, item.kind)...)
		}
	}
	return out, nil
}

// parseIPTablesCounters 解析 `iptables -L <链> -n -v -x` 的输出。
//
// 输出是列式表格，前九列恒为：
//
//	pkts bytes target prot opt in out source destination
//
// 注意 in / out 是**两列**（平时都是 *），所以 source 在第 8 列、destination
// 在第 9 列 —— 按"看起来有几个词"去数是很容易差一位的。后面才是 -m multiport
// 之类的附加匹配（dports 就藏在里面）。定位 source 用列号而不是关键字搜索：
// 地址后面的字段随规则形态变化，靠关键字找不稳。
//
// 抽成纯函数是为了能脱离内核单测 —— 本机跑不了 iptables，只能用真实格式的
// 输出样本验证解析。
func parseIPTablesCounters(raw, family, kind string) []RuleCounter {
	out := make([]RuleCounter, 0, 8)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Chain ") || strings.HasPrefix(line, "pkts") {
			continue
		}
		f := strings.Fields(line)
		// 八列是下限：pkts bytes target prot opt in out source。
		// destination 在没有端口匹配时也可能被省略，所以不要求第九列。
		if len(f) < 8 {
			continue
		}
		pkts, err1 := strconv.ParseUint(f[0], 10, 64)
		octets, err2 := strconv.ParseUint(f[1], 10, 64)
		if err1 != nil || err2 != nil {
			continue // 表头变体、或这行压根不是规则
		}
		// 只数 DROP：子链里将来若加 ACCEPT / RETURN，它们的计数不是"拦截量"。
		if !strings.EqualFold(f[2], "DROP") {
			continue
		}
		src := f[7]
		// 不限来源的规则不是条目级封禁，算进按条目统计里会虚高一大截。
		if src == "0.0.0.0/0" || src == "::/0" || src == "anywhere" {
			continue
		}
		key, label := src, src
		// destination 之后才是附加匹配：multiport dports ... / tcp dpt:7000
		if len(f) > 9 {
			if ports := iptablesPortFields(f[9:]); ports != "" {
				key += "|" + ports
				label += " 端口 " + ports
			}
		}
		out = append(out, RuleCounter{
			Kind: kind, Key: key, Label: label, Family: family,
			Packets: pkts, Bytes: octets,
		})
	}
	return out
}

// iptablesPortFields 从选项字段里摘出端口条件，没有就返回空串。
//
// `-L` 的输出里 multiport 长成 "multiport dports 7000,7001"，tcp 的则是
// "tcp dpt:7000"。两种都要认，否则端口限定的条目会和全端口的撞成同一个 Key
// —— 同一个地址在两条链里各有一条规则，Key 撞了就只能看到其中一个的计数。
func iptablesPortFields(rest []string) string {
	for i, s := range rest {
		if (s == "dports" || s == "dport" || s == "sports") && i+1 < len(rest) {
			return rest[i+1]
		}
		if after, ok := strings.CutPrefix(s, "dpt:"); ok && after != "" {
			return after
		}
	}
	return ""
}

func (d *iptablesDriver) DumpSystem() (string, error) {
	ctx := context.Background()
	var b strings.Builder
	for _, f := range d.fams {
		out, err := run(ctx, f.bin, "-w", "-S")
		if err != nil {
			fmt.Fprintf(&b, "# %s 读取失败: %v\n\n", f.bin, err)
			continue
		}
		fmt.Fprintf(&b, "# ===== %s -S =====\n%s\n", f.bin, out)
	}
	return b.String(), nil
}

// Preview 生成将要下发的规则文本，不落盘。
//
// 与 syncFamily 共用 buildIPTablesRules / portBlockRules，保证"预览到的"
// 就是"会下发的"。
func (d *iptablesDriver) Preview(des Desired) (string, error) {
	var b strings.Builder
	for _, f := range d.fams {
		rules := buildIPTablesRules(des, f.bits)

		fmt.Fprintf(&b, "# ===== %s（%s）=====\n", f.bin, f.name)
		fmt.Fprintf(&b, "%s -N %s\n%s -N %s\n%s -N %s\n",
			f.bin, ManagedChain, f.bin, managedBlackChain, f.bin, managedPortBlackChain)
		fmt.Fprintf(&b, "%s -C INPUT -j %s || %s -I INPUT 1 -j %s\n", f.bin, ManagedChain, f.bin, ManagedChain)
		fmt.Fprintf(&b, "%s -F %s\n%s -F %s\n%s -F %s\n",
			f.bin, ManagedChain, f.bin, managedBlackChain, f.bin, managedPortBlackChain)

		for _, rule := range rules.Guard {
			fmt.Fprintf(&b, "%s %s\n", f.bin, strings.Join(rule.Args, " "))
		}
		for _, bl := range rules.Black {
			fmt.Fprintf(&b, "%s -A %s -s %s -j DROP\n", f.bin, managedBlackChain, bl)
		}
		for _, g := range des.PortBlacklists {
			if len(g.Ports.Normalize()) > 0 {
				continue
			}
			addrs := filterByFamily(g.Prefixes, f.bits)
			if len(addrs) == 0 {
				continue
			}
			fmt.Fprintf(&b, "# 以下 %d 个地址属于「%s」，但这一组没有端口，无法下发：\n",
				len(addrs), g.Label)
			for _, bl := range addrs {
				fmt.Fprintf(&b, "#   %s\n", bl)
			}
		}
		for _, args := range portBlockRules(rules.PortGroups) {
			fmt.Fprintf(&b, "%s %s\n", f.bin, strings.Join(args, " "))
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}

func (d *iptablesDriver) Snapshot() (string, error) {
	ctx := context.Background()
	var b strings.Builder
	for _, f := range d.fams {
		for _, chain := range []string{ManagedChain, managedBlackChain, managedPortBlackChain} {
			out, err := run(ctx, f.bin, "-w", "-S", chain)
			if err != nil {
				fmt.Fprintf(&b, "# %s %s: %v\n", f.bin, chain, err)
				continue
			}
			fmt.Fprintf(&b, "# %s %s\n%s\n", f.bin, chain, out)
		}
	}
	return b.String(), nil
}

// Restore 回滚到快照。只重建受管链，不动系统规则。
func (d *iptablesDriver) Restore(snapshot string) error {
	ctx := context.Background()
	for _, f := range d.fams {
		for _, chain := range []string{ManagedChain, managedBlackChain, managedPortBlackChain} {
			if _, err := run(ctx, f.bin, "-w", "-F", chain); err != nil {
				return err
			}
		}
	}

	// 快照里存的是 -A 规则行，按顺序回放。
	//
	// 用哪个 bin 要从 "# <bin> <chain>" 注释行里跟出来：v4 与 v6 的规则在快照里
	// 是顺序混排的，回放时若一律用 iptables 执行，v6 规则会落到 v4 表上 ——
	// 回滚"成功"了，恢复出来的却是错的。
	bin := ""
	for _, line := range strings.Split(snapshot, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# ") {
			if f := strings.Fields(line); len(f) >= 3 {
				bin = f[1]
			}
			continue
		}
		if !strings.HasPrefix(line, "-A ") {
			continue
		}
		fields := strings.Fields(line)
		chain := ""
		if len(fields) >= 2 {
			chain = fields[1]
		}
		if chain != ManagedChain && chain != managedBlackChain && chain != managedPortBlackChain {
			continue
		}
		if bin == "" {
			bin = "iptables"
		}
		args := append([]string{"-w"}, fields...)
		_, _ = run(ctx, bin, args...)
	}
	return nil
}

// ---- 辅助 ----

func isAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "already exists") || strings.Contains(s, "chain already")
}

// normalizeTarget 把输入规范成带掩码的 CIDR 字符串，同时做严格校验。
func normalizeTarget(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, fmt.Errorf("空地址")
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("非法 CIDR %q: %w", s, err)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("非法 IP %q: %w", s, err)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// filterByFamily 取属于指定地址族的 CIDR，并去重排序。
func filterByFamily(targets []string, bits int) []string {
	set := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		p, err := normalizeTarget(t)
		if err != nil {
			continue
		}
		if p.Addr().BitLen() != bits {
			continue
		}
		set[p.String()] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// rateLimitArgs 把一条限速规则展开成 iptables 参数。
//
// 展开成「来源 × 端口分块」的笛卡尔积，而不是靠 iptables 自己对重复的 -s
// 做隐式展开 —— 展开出来的条数得能提前数清楚，否则"到底下了几条规则"
// 只能上机器数。端口按区间个数切块（multiport 的 15 个名额数的是端口或区间的
// 个数，20000:30000 只占一个）。
//
// 同一个 Key 拆出来的所有条共用同一个 --hashlimit-name，因而共享同一张计数表。
// 各条各算一份配额的话，实际放行量会按条数翻倍 —— 这块以前踩过。
func rateLimitArgs(r RateLimitRule) [][]string {
	if r.PerSec <= 0 {
		return nil
	}

	head := []string{
		"-p", "tcp",
		"-m", "conntrack", "--ctstate", "NEW",
	}
	tail := []string{
		"-m", "hashlimit",
		"--hashlimit-above", fmt.Sprintf("%d/sec", r.PerSec),
		"--hashlimit-burst", fmt.Sprint(r.burst()),
		"--hashlimit-mode", "srcip",
		"--hashlimit-name", hashlimitName(r.Key),
		"--hashlimit-htable-expire", "60000",
		"-j", "DROP",
	}

	// 没有来源限制时也要走一遍循环，用一个空来源占位，避免两套拼装逻辑。
	sources := r.Sources
	if len(sources) == 0 {
		sources = []string{""}
	}

	chunks := []portrange.Set{nil}
	if ps := r.Ports.Normalize(); len(ps) > 0 {
		chunks = ps.Chunks(multiportMax)
	}

	out := make([][]string, 0, len(sources)*len(chunks))
	for _, src := range sources {
		for _, c := range chunks {
			args := make([]string, 0, len(head)+len(tail)+6)
			args = append(args, head...)
			if src != "" {
				args = append(args, "-s", src)
			}
			if len(c) > 0 {
				args = append(args, "-m", "multiport", "--dports", iptPorts(c))
			}
			args = append(args, tail...)
			out = append(out, args)
		}
	}
	return out
}
