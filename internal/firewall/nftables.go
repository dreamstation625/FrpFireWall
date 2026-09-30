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
// 关键约束：**不自己创建带 hook 的 base chain**。
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
// 白名单不落内核：白名单的语义是"豁免本程序封禁"，而 return verdict 在 base chain
// 里的行为依赖上下文，不可靠。改为在生成黑名单集合时把白名单地址减掉，
// 效果等价且零歧义。

type nftablesDriver struct {
	report *Report
	target nftTarget
	ready  bool
}

type nftTarget struct {
	Family string
	Table  string
	Chain  string
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

// EnsureBase 定位（或创建）input base chain，并保证集合存在。
func (d *nftablesDriver) EnsureBase() error {
	ctx := context.Background()

	if t, ok := d.findInputChain(ctx); ok {
		d.target = t
	} else {
		if _, err := run(ctx, "nft", "add", "table", "inet", "filter"); err != nil && !isAlreadyExists(err) {
			return fmt.Errorf("创建 table inet filter 失败: %w", err)
		}
		if _, err := run(ctx, "nft", "add", "chain", "inet", "filter", "input",
			"{", "type", "filter", "hook", "input", "priority", "filter", ";",
			"policy", "accept", ";", "}"); err != nil && !isAlreadyExists(err) {
			return fmt.Errorf("创建 input 链失败: %w", err)
		}
		d.target = nftTarget{Family: "inet", Table: "filter", Chain: "input"}
	}

	for _, s := range []struct {
		name string
		typ  string
	}{{setBlack, "ipv4_addr"}, {setBlack6, "ipv6_addr"}} {
		if err := d.ensureSet(ctx, s.name, s.typ, false); err != nil {
			return err
		}
	}
	d.ready = true
	return nil
}

func (d *nftablesDriver) ensureSet(ctx context.Context, name, typ string, dynamic bool) error {
	if _, err := run(ctx, "nft", "list", "set", d.target.Family, d.target.Table, name); err == nil {
		return nil
	}
	spec := fmt.Sprintf("{ type %s; flags interval; }", typ)
	if dynamic {
		spec = fmt.Sprintf("{ type %s; flags dynamic,timeout; timeout 10s; }", typ)
	}
	if _, err := run(ctx, "nft", "add", "set", d.target.Family, d.target.Table, name, spec); err != nil {
		return fmt.Errorf("创建集合 %s 失败: %w", name, err)
	}
	return nil
}

// findInputChain 在 ruleset 里定位负责 INPUT 的 base chain。
// 优先 inet 家族（同时覆盖 v4/v6），其次 ip；多个候选取 priority 最小的（最先执行）。
func (d *nftablesDriver) findInputChain(ctx context.Context) (nftTarget, bool) {
	out, err := run(ctx, "nft", "-j", "list", "ruleset")
	if err != nil {
		return nftTarget{}, false
	}

	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nftTarget{}, false
	}

	type cand struct {
		t    nftTarget
		prio int
		inet bool
	}
	var best *cand

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
		if ch.Family != "inet" && ch.Family != "ip" {
			continue
		}
		c := cand{
			t:    nftTarget{Family: ch.Family, Table: ch.Table, Chain: ch.Name},
			prio: ch.Prio,
			inet: ch.Family == "inet",
		}
		if best == nil {
			best = &c
			continue
		}
		// inet 优先；同族比 priority
		if c.inet && !best.inet {
			best = &c
		} else if c.inet == best.inet && c.prio < best.prio {
			best = &c
		}
	}
	if best == nil {
		return nftTarget{}, false
	}
	return best.t, true
}

// Sync 全量对齐：重建归属本程序的规则 + 重填黑名单集合。整个操作在一个 nft 事务里原子提交。
func (d *nftablesDriver) Sync(des Desired) error {
	if err := d.EnsureBase(); err != nil {
		return err
	}
	ctx := context.Background()

	handles := d.managedRuleHandles(ctx)

	black4 := filterByFamily(des.Blacklist, 32)
	black6 := filterByFamily(des.Blacklist, 128)

	var b strings.Builder

	// 1. 删掉旧的受管规则（同一个事务里会重新插入，所以没有空窗）
	for _, h := range handles {
		fmt.Fprintf(&b, "delete rule %s %s %s handle %d\n",
			d.target.Family, d.target.Table, d.target.Chain, h)
	}

	// 2. 重填黑名单集合
	fmt.Fprintf(&b, "flush set %s %s %s\n", d.target.Family, d.target.Table, setBlack)
	if len(black4) > 0 {
		fmt.Fprintf(&b, "add element %s %s %s { %s }\n",
			d.target.Family, d.target.Table, setBlack, strings.Join(black4, ", "))
	}
	fmt.Fprintf(&b, "flush set %s %s %s\n", d.target.Family, d.target.Table, setBlack6)
	if len(black6) > 0 {
		fmt.Fprintf(&b, "add element %s %s %s { %s }\n",
			d.target.Family, d.target.Table, setBlack6, strings.Join(black6, ", "))
	}

	// 3. 重新插入规则。insert 始终插到链首，所以按目标顺序倒着插。
	if des.RateLimit != nil && des.RateLimit.Enabled && d.Capability().RateLimit {
		if expr, ok := nftRateLimitExpr(des.RateLimit, des.ProtectPorts); ok {
			if err := d.ensureSet(ctx, setRate, "ipv4_addr", true); err == nil {
				fmt.Fprintf(&b, "insert rule %s %s %s %s comment \"%s\"\n",
					d.target.Family, d.target.Table, d.target.Chain, expr, commentRate)
			} else {
				d.report.Warnings = append(d.report.Warnings,
					"当前 nftables 不支持动态集合，已跳过 per-IP 连接速率限制")
			}
		}
	}
	fmt.Fprintf(&b, "insert rule %s %s %s ip6 saddr @%s drop comment \"%s\"\n",
		d.target.Family, d.target.Table, d.target.Chain, setBlack6, commentBlack6)
	fmt.Fprintf(&b, "insert rule %s %s %s ip saddr @%s drop comment \"%s\"\n",
		d.target.Family, d.target.Table, d.target.Chain, setBlack, commentBlack)

	script := b.String()

	// 语法预检：不通过就整个放弃，绝不带着半截规则上生产。
	if _, err := runStdin(ctx, script, "nft", "-c", "-f", "-"); err != nil {
		return fmt.Errorf("规则语法预检失败，已放弃本次下发: %w\n%s", err, script)
	}
	if _, err := runStdin(ctx, script, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("下发规则失败: %w", err)
	}
	return nil
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
	setName := setBlack
	if p.Addr().Is6() {
		setName = setBlack6
	}
	// add element 幂等，重复添加不报错
	_, err = run(ctx, "nft", "add", "element", d.target.Family, d.target.Table, setName,
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
	setName := setBlack
	if p.Addr().Is6() {
		setName = setBlack6
	}
	if _, err := run(ctx, "nft", "delete", "element", d.target.Family, d.target.Table, setName,
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

	out, err := run(ctx, "nft", "-a", "list", "chain", d.target.Family, d.target.Table, d.target.Chain)
	if err == nil {
		var b strings.Builder
		fmt.Fprintf(&b, "# nft -a list chain %s %s %s\n", d.target.Family, d.target.Table, d.target.Chain)
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, commentPrefix) {
				b.WriteString(strings.TrimSpace(line) + "\n")
				res.Summary = append(res.Summary, strings.TrimSpace(line))
			}
		}
		res.Raw = b.String()
	}

	for _, s := range []struct{ name, label string }{
		{setBlack, "IPv4 黑名单"},
		{setBlack6, "IPv6 黑名单"},
	} {
		cnt := d.setSize(ctx, s.name)
		res.Summary = append(res.Summary,
			fmt.Sprintf("%s: 集合 %s 内 %d 个元素", s.label, s.name, cnt))
	}
	return res, nil
}

func (d *nftablesDriver) setSize(ctx context.Context, name string) int {
	out, err := run(ctx, "nft", "-j", "list", "set", d.target.Family, d.target.Table, name)
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
func (d *nftablesDriver) Preview(des Desired) (string, error) {
	t := d.target
	if t.Family == "" {
		t = nftTarget{Family: "inet", Table: "filter", Chain: "input"}
	}
	black4 := filterByFamily(des.Blacklist, 32)
	black6 := filterByFamily(des.Blacklist, 128)

	var b strings.Builder
	fmt.Fprintf(&b, "# nftables 规则预览（受管规则插入 %s %s %s 链首）\n\n", t.Family, t.Table, t.Chain)
	fmt.Fprintf(&b, "# --- 集合定义（首次创建）---\n")
	fmt.Fprintf(&b, "add set %s %s %s { type ipv4_addr; flags interval; }\n", t.Family, t.Table, setBlack)
	fmt.Fprintf(&b, "add set %s %s %s { type ipv6_addr; flags interval; }\n\n", t.Family, t.Table, setBlack6)

	fmt.Fprintf(&b, "# --- 本次下发的原子事务 ---\n")
	fmt.Fprintf(&b, "flush set %s %s %s\n", t.Family, t.Table, setBlack)
	if len(black4) > 0 {
		fmt.Fprintf(&b, "add element %s %s %s { %s }\n", t.Family, t.Table, setBlack, strings.Join(black4, ", "))
	}
	fmt.Fprintf(&b, "flush set %s %s %s\n", t.Family, t.Table, setBlack6)
	if len(black6) > 0 {
		fmt.Fprintf(&b, "add element %s %s %s { %s }\n", t.Family, t.Table, setBlack6, strings.Join(black6, ", "))
	}
	if des.RateLimit != nil && des.RateLimit.Enabled {
		if expr, ok := nftRateLimitExpr(des.RateLimit, des.ProtectPorts); ok {
			fmt.Fprintf(&b, "insert rule %s %s %s %s comment \"%s\"\n", t.Family, t.Table, t.Chain, expr, commentRate)
		}
	}
	fmt.Fprintf(&b, "insert rule %s %s %s ip6 saddr @%s drop comment \"%s\"\n", t.Family, t.Table, t.Chain, setBlack6, commentBlack6)
	fmt.Fprintf(&b, "insert rule %s %s %s ip saddr @%s drop comment \"%s\"\n", t.Family, t.Table, t.Chain, setBlack, commentBlack)

	fmt.Fprintf(&b, "\n# 白名单不写入内核：生成黑名单时会剔除白名单地址，效果等价且无 verdict 歧义。\n")
	return b.String(), nil
}

func (d *nftablesDriver) Snapshot() (string, error) {
	ctx := context.Background()
	var b strings.Builder
	for _, s := range []string{setBlack, setBlack6} {
		if out, err := run(ctx, "nft", "list", "set", d.target.Family, d.target.Table, s); err == nil {
			fmt.Fprintf(&b, "# set %s\n%s\n", s, out)
		}
	}
	if out, err := run(ctx, "nft", "-a", "list", "chain", d.target.Family, d.target.Table, d.target.Chain); err == nil {
		fmt.Fprintf(&b, "# chain\n%s\n", out)
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
	for _, s := range []string{setBlack, setBlack6, setRate} {
		_, _ = run(ctx, "nft", "flush", "set", d.target.Family, d.target.Table, s)
	}
	for _, h := range d.managedRuleHandles(ctx) {
		_, _ = run(ctx, "nft", "delete", "rule", d.target.Family, d.target.Table, d.target.Chain,
			"handle", strconv.Itoa(h))
	}
	return nil
}

// managedRuleHandles 找出链里归属本程序的规则 handle（靠 comment 标记识别）。
func (d *nftablesDriver) managedRuleHandles(ctx context.Context) []int {
	out, err := run(ctx, "nft", "-a", "list", "chain", d.target.Family, d.target.Table, d.target.Chain)
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

// nftRateLimitExpr 生成 per-IP 连接速率限制表达式。
//
// nftables 没有 hashlimit 等价物，标准做法是用带 timeout 的动态集合计数：
//
//	tcp dport { 7000 } ct state new add @frpfirewall_rate { ip saddr limit rate over 20/second burst 40 packets } drop
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

var _ = netip.Prefix{}
