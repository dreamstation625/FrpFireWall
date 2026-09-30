package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// iptables 驱动的受管结构：
//
//	INPUT ─(第1条)─▶ FRPFIREWALL_GUARD
//	                   ├─ -j FRPFIREWALL_BLACK            ← 固定跳转到黑名单子链
//	                   ├─ [限速规则]                 ← 可选
//	                   └─ -j RETURN
//	FRPFIREWALL_BLACK
//	                   └─ -s <黑名单> -j DROP        ← 逐条
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
	} else {
		c.Reason = "未找到 iptables 命令"
	}
	return c
}

// EnsureBase 幂等创建两条受管链，并把跳转挂进 INPUT。
func (d *iptablesDriver) EnsureBase() error {
	ctx := context.Background()
	for _, f := range d.fams {
		for _, chain := range []string{ManagedChain, managedBlackChain} {
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

func (d *iptablesDriver) syncFamily(ctx context.Context, f ipFamily, des Desired) error {
	black := filterByFamily(des.Blacklist, f.bits)

	// 先清空自己的链——只动受管命名空间，绝不碰系统其它规则。
	if _, err := run(ctx, f.bin, "-w", "-F", ManagedChain); err != nil {
		return fmt.Errorf("清空 %s 失败: %w", ManagedChain, err)
	}
	if _, err := run(ctx, f.bin, "-w", "-F", managedBlackChain); err != nil {
		return fmt.Errorf("清空 %s 失败: %w", managedBlackChain, err)
	}

	// 1. 固定跳转到黑名单子链。
	if _, err := run(ctx, f.bin, "-w", "-A", ManagedChain, "-j", managedBlackChain); err != nil {
		return fmt.Errorf("写入黑名单跳转失败: %w", err)
	}

	// 2. 连接速率限制（per-IP），放在封禁判定之后、兜底 RETURN 之前。
	if des.RateLimit != nil && des.RateLimit.Enabled {
		if args, ok := hashlimitArgs(des.RateLimit, des.ProtectPorts, f.bits); ok {
			full := append([]string{"-w", "-A", ManagedChain}, args...)
			if _, err := run(ctx, f.bin, full...); err != nil {
				// 限速是增强能力，模块不可用时降级而不是让整次同步失败。
				d.report.Warnings = append(d.report.Warnings,
					fmt.Sprintf("%s 下发连接速率限制失败，已跳过：%v", f.name, err))
			}
		}
	}

	// 3. 兜底 RETURN：不匹配的流量回到 INPUT 继续走系统原有规则。
	if _, err := run(ctx, f.bin, "-w", "-A", ManagedChain, "-j", "RETURN"); err != nil {
		return fmt.Errorf("写入兜底 RETURN 失败: %w", err)
	}

	// 4. 黑名单逐条写入子链。
	for _, b := range black {
		if _, err := run(ctx, f.bin, "-w", "-A", managedBlackChain, "-s", b, "-j", "DROP"); err != nil {
			return fmt.Errorf("写入黑名单 %s 失败: %w", b, err)
		}
	}
	return nil
}

// AddBlock 增量封禁一条，不做全量重建。
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
		if out, err := run(ctx, f.bin, "-w", "-S", managedBlackChain); err == nil {
			raw.WriteString("\n# " + f.bin + " -S " + managedBlackChain + "\n")
			raw.WriteString(out)
			n := 0
			for _, line := range strings.Split(out, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "-A ") {
					n++
				}
			}
			res.Summary = append(res.Summary,
				fmt.Sprintf("%s: %s 链内封禁 %d 条", f.name, managedBlackChain, n))
		}
	}

	res.Raw = raw.String()
	return res, nil
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
func (d *iptablesDriver) Preview(des Desired) (string, error) {
	var b strings.Builder
	for _, f := range d.fams {
		black := filterByFamily(des.Blacklist, f.bits)

		fmt.Fprintf(&b, "# ===== %s（%s）=====\n", f.bin, f.name)
		fmt.Fprintf(&b, "%s -N %s\n%s -N %s\n", f.bin, ManagedChain, f.bin, managedBlackChain)
		fmt.Fprintf(&b, "%s -C INPUT -j %s || %s -I INPUT 1 -j %s\n", f.bin, ManagedChain, f.bin, ManagedChain)
		fmt.Fprintf(&b, "%s -F %s\n%s -F %s\n", f.bin, ManagedChain, f.bin, managedBlackChain)
		fmt.Fprintf(&b, "%s -A %s -j %s\n", f.bin, ManagedChain, managedBlackChain)
		if des.RateLimit != nil && des.RateLimit.Enabled {
			if args, ok := hashlimitArgs(des.RateLimit, des.ProtectPorts, f.bits); ok {
				fmt.Fprintf(&b, "%s -A %s %s\n", f.bin, ManagedChain, strings.Join(args, " "))
			}
		}
		fmt.Fprintf(&b, "%s -A %s -j RETURN\n", f.bin, ManagedChain)
		for _, bl := range black {
			fmt.Fprintf(&b, "%s -A %s -s %s -j DROP\n", f.bin, managedBlackChain, bl)
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}

func (d *iptablesDriver) Snapshot() (string, error) {
	ctx := context.Background()
	var b strings.Builder
	for _, f := range d.fams {
		out, err := run(ctx, f.bin, "-w", "-S", ManagedChain)
		if err != nil {
			fmt.Fprintf(&b, "# %s %s: %v\n", f.bin, ManagedChain, err)
		} else {
			fmt.Fprintf(&b, "# %s %s\n%s\n", f.bin, ManagedChain, out)
		}
		out2, err := run(ctx, f.bin, "-w", "-S", managedBlackChain)
		if err != nil {
			fmt.Fprintf(&b, "# %s %s: %v\n", f.bin, managedBlackChain, err)
		} else {
			fmt.Fprintf(&b, "# %s %s\n%s\n", f.bin, managedBlackChain, out2)
		}
	}
	return b.String(), nil
}

// Restore 回滚到快照。只重建受管链，不动系统规则。
func (d *iptablesDriver) Restore(snapshot string) error {
	ctx := context.Background()
	for _, f := range d.fams {
		if _, err := run(ctx, f.bin, "-w", "-F", ManagedChain); err != nil {
			return err
		}
		if _, err := run(ctx, f.bin, "-w", "-F", managedBlackChain); err != nil {
			return err
		}
	}
	// 快照里存的是 -A 规则行，按顺序回放。
	for _, line := range strings.Split(snapshot, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-A ") {
			continue
		}
		chain := ""
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			chain = fields[1]
		}
		if chain != ManagedChain && chain != managedBlackChain {
			continue
		}
		args := append([]string{"-w"}, fields...)
		_, _ = run(ctx, "iptables", args...)
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

// hashlimitArgs 生成 per-IP 连接速率限制参数。
//
// hashlimit 是 iptables 里唯一能做到"按源 IP 分别计数"的现成模块，
// 正好用来兜住"不发 frp 协议、纯 TCP 扫描 bindPort"的流量——
// 这类流量不会触发 frps 插件，只能靠网络层限速拦。
func hashlimitArgs(spec *RateLimitSpec, ports []int, bits int) ([]string, bool) {
	if spec == nil || !spec.Enabled || spec.PerSec <= 0 {
		return nil, false
	}
	burst := spec.Burst
	if burst <= 0 {
		burst = spec.PerSec * 2
	}

	args := []string{
		"-p", "tcp",
		"-m", "conntrack", "--ctstate", "NEW",
	}
	switch len(ports) {
	case 0:
		// 不限端口，对全部新建连接生效
	case 1:
		args = append(args, "--dport", fmt.Sprint(ports[0]))
	default:
		ps := make([]string, 0, len(ports))
		for _, p := range ports {
			ps = append(ps, fmt.Sprint(p))
		}
		args = append(args, "-m", "multiport", "--dports", strings.Join(ps, ","))
	}

	args = append(args,
		"-m", "hashlimit",
		"--hashlimit-above", fmt.Sprintf("%d/sec", spec.PerSec),
		"--hashlimit-burst", fmt.Sprint(burst),
		"--hashlimit-mode", "srcip",
		"--hashlimit-name", "frpfirewall_rl",
		"--hashlimit-htable-expire", "60000",
		"-j", "DROP",
	)
	return args, true
}
