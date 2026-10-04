package guard

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/config"
	"github.com/dreamstation625/FrpFireWall/internal/model"
	"github.com/dreamstation625/FrpFireWall/internal/portrange"
	"github.com/dreamstation625/FrpFireWall/internal/store"
)

// newManagerWith 造一个用指定配置启动的 manager。
//
// 受保护端口是 bind_port 与代理端口的并集，默认配置下永远是 7000 + 80,443，
// 想验证"端口集合为空时怎么退化"就必须能自己指定这两个值。
func newManagerWith(t *testing.T, mutate func(c *config.Config)) *Manager {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("打开测试库失败：%v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := config.Default()
	if mutate != nil {
		mutate(cfg)
	}
	m := New(cfg, st, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := m.Refresh(); err != nil {
		t.Fatalf("加载状态失败：%v", err)
	}
	return m
}

// groupByKey 把端口限定分组按 Key 摊平，方便直接查表断言。
func groupByKey(m *Manager) map[string]struct {
	label    string
	prefixes []string
	ports    string
} {
	out := map[string]struct {
		label    string
		prefixes []string
		ports    string
	}{}
	for _, g := range m.desired().PortBlacklists {
		out[g.Key] = struct {
			label    string
			prefixes []string
			ports    string
		}{g.Label, g.Prefixes, g.Ports.String()}
	}
	return out
}

// 黑名单封禁的"范围"最终落成两类东西：全端口那条链，和一组"端口集合 → 地址"的分组。
//
// 这条测试盯的是分组本身：同一个端口集合必须合成一组，不同集合**必须**分开。
// 合成一组的后果是 A 组的地址在 B 组的端口上也被封 —— 而两组规则长得一模一样，
// 只有把地址和端口对上号才看得出来。
func TestDesiredPortBlacklistGroups(t *testing.T) {
	m := newTestManager(t) // bind_port 7000 + proxy_ports 80,443

	add := func(target, scope string, ports portrange.Set) {
		t.Helper()
		if _, err := m.BanManual(target, "测试", "tester", time.Hour, scope, ports); err != nil {
			t.Fatalf("封禁 %s 失败：%v", target, err)
		}
	}

	add("203.0.113.10", model.ScopeAll, nil)
	add("203.0.113.11", model.ScopeFrp, nil)
	add("203.0.113.12", model.ScopeCustom, portrange.Ports(8080))
	add("203.0.113.13", model.ScopeCustom, portrange.Ports(8080)) // 与上一条同集合
	add("203.0.113.14", model.ScopeCustom, portrange.Span(9000, 9100))
	add("203.0.113.15", model.ScopeFrp, nil) // 与 .11 同集合

	des := m.desired()

	// 全端口的那条不进端口分组：它已经覆盖了所有端口，再进任何分组都是冗余，
	// 而且会变成"这个地址为什么出现在两处"这种需要解释的问题。
	wantAll := []string{"203.0.113.10/32"}
	if len(des.Blacklist) != 1 || des.Blacklist[0] != wantAll[0] {
		t.Errorf("全端口黑名单 = %v，期望 %v", des.Blacklist, wantAll)
	}

	groups := groupByKey(m)
	if len(groups) != 3 {
		t.Fatalf("应有 3 个端口分组（frp / 8080 / 9000-9100），实际 %d 个：%v", len(groups), groups)
	}

	// frp 范围那一组：端口取全局受保护端口，与条目自带的端口无关。
	frp, ok := groups["80,443,7000"]
	if !ok {
		t.Fatalf("缺少 frp 端口分组，实际分组：%v", groups)
	}
	if frp.label != frpGroupLabel {
		t.Errorf("frp 分组的标签 = %q，期望 %q", frp.label, frpGroupLabel)
	}
	if len(frp.prefixes) != 2 || frp.prefixes[0] != "203.0.113.11/32" || frp.prefixes[1] != "203.0.113.15/32" {
		t.Errorf("frp 分组的地址 = %v，期望两条", frp.prefixes)
	}

	// 同一个端口集合必须合成一组，否则同一个端口集合会在内核里生成多份重复规则。
	custom, ok := groups["8080"]
	if !ok {
		t.Fatalf("缺少 8080 分组，实际分组：%v", groups)
	}
	if len(custom.prefixes) != 2 {
		t.Errorf("8080 分组的地址 = %v，期望两条合成一组", custom.prefixes)
	}
	if custom.label != customGroupLabel("8080") {
		t.Errorf("8080 分组的标签 = %q，期望 %q", custom.label, customGroupLabel("8080"))
	}

	// 不同端口集合必须是两个分组，且地址不能混进对方。
	span, ok := groups["9000-9100"]
	if !ok {
		t.Fatalf("缺少 9000-9100 分组，实际分组：%v", groups)
	}
	if len(span.prefixes) != 1 || span.prefixes[0] != "203.0.113.14/32" {
		t.Errorf("9000-9100 分组的地址 = %v，期望只有 203.0.113.14/32", span.prefixes)
	}

	// 全端口优先：同一地址同时以"全端口"躺在名单里、又按"仅 frp 端口"被封禁
	// （名单条目与封禁记录是两条独立的路，这种组合在真实使用里很常见）。
	// 内核里同一地址只能有一个结论，冲突时取更严的那个 —— 反过来的话，
	// "这个地址到底封没封住"就得靠人比对两组规则才能回答。
	if err := m.store.UpsertACL(&model.ACLEntry{
		Kind:       model.KindBlack,
		Target:     "203.0.113.11/32",
		TargetType: model.TargetTypeOf("203.0.113.11"),
		Scope:      model.ScopeAll,
		Source:     model.SourceManual,
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(); err != nil {
		t.Fatal(err)
	}
	for key, g := range groupByKey(m) {
		for _, p := range g.prefixes {
			if p == "203.0.113.11/32" {
				t.Errorf("已按全端口封禁的地址又出现在端口分组 %q 里", key)
			}
		}
	}
	found := false
	for _, p := range m.desired().Blacklist {
		if p == "203.0.113.11/32" {
			found = true
		}
	}
	if !found {
		t.Error("冲突时应当按全端口封禁，但全端口名单里没有它")
	}
}

// 库里被手工改坏的条目（范围是自定义却没有端口）必须退化成"全端口封禁"，
// 而不是被丢掉。
//
// 丢掉一条本该生效的封禁，是这套系统里最难发现的错误：名单上它在、界面上它在，
// 只有去数内核规则才会发现少了一条。兜底方向一律取更严的那一侧。
func TestDesiredCustomScopeWithoutPortsDegradesToAll(t *testing.T) {
	m := newTestManager(t)

	if err := m.store.UpsertACL(&model.ACLEntry{
		Kind:       model.KindBlack,
		Target:     "203.0.113.20/32",
		TargetType: model.TargetTypeOf("203.0.113.20"),
		Scope:      model.ScopeCustom,
		Ports:      "", // 手工改库改出来的坏行
		Source:     model.SourceManual,
	}); err != nil {
		t.Fatal(err)
	}
	// 端口写的是解析不出来的文本，同样只能退化
	if err := m.store.UpsertACL(&model.ACLEntry{
		Kind:       model.KindBlack,
		Target:     "203.0.113.21/32",
		TargetType: model.TargetTypeOf("203.0.113.21"),
		Scope:      model.ScopeCustom,
		Ports:      "8080~9000",
		Source:     model.SourceManual,
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(); err != nil {
		t.Fatal(err)
	}

	des := m.desired()
	if len(des.PortBlacklists) != 0 {
		t.Errorf("没有可用端口的自定义范围不该产生端口分组：%v", des.PortBlacklists)
	}
	want := map[string]bool{"203.0.113.20/32": true, "203.0.113.21/32": true}
	if len(des.Blacklist) != len(want) {
		t.Fatalf("两条坏行都应退化成全端口封禁，实际 = %v", des.Blacklist)
	}
	for _, p := range des.Blacklist {
		if !want[p] {
			t.Errorf("出现了预期外的地址：%s", p)
		}
	}
}

// 受保护端口被清空时（bind_port 为 0 且没有代理端口），"仅 frp 端口"的条目
// 没有端口可落，也必须退化成全端口 —— 空端口集合会让整条封禁静默失效。
func TestDesiredFrpScopeWithoutProtectPortsDegradesToAll(t *testing.T) {
	m := newManagerWith(t, func(c *config.Config) {
		c.Frps.BindPort = 0
		c.Frps.ProxyPorts = portrange.Set{}
	})
	if _, err := m.BanManual("203.0.113.30", "测试", "tester", time.Hour, model.ScopeFrp, nil); err != nil {
		t.Fatal(err)
	}

	des := m.desired()
	if len(des.PortBlacklists) != 0 {
		t.Errorf("受保护端口为空时不该产生端口分组：%v", des.PortBlacklists)
	}
	if len(des.Blacklist) != 1 || des.Blacklist[0] != "203.0.113.30/32" {
		t.Errorf("应退化成全端口封禁，实际 = %v", des.Blacklist)
	}
}

// 代理端口热更后，受保护端口、frp 分组的 Key、全局限速的兜底端口必须同时跟着变。
//
// 三处漏一处就是"改了等于没改"，而且漏哪一处都不报错：
// 端口分组还挂在旧端口上，封禁会照旧生效在已经被改掉的端口上。
func TestSetFrpsProxyPortsHotUpdate(t *testing.T) {
	m := newTestManager(t)
	setPolicy(t, m, func(p *model.Policy) {
		p.RateLimitEnabled = true
		p.RateLimitPerSec = 20
		p.RateLimitBurst = 40
	})
	if _, err := m.BanManual("203.0.113.40", "测试", "tester", time.Hour, model.ScopeFrp, nil); err != nil {
		t.Fatal(err)
	}

	// 故意选两个不相邻的端口，免得"归一化把 9100,9101 合成 9100-9101"这件事
	// 混进来：这里要验的是"热更有没有传到下面"，不是归一化。
	m.SetFrpsProxyPorts(portrange.Ports(9100, 9200))

	bindPort, proxyPorts, protect := m.FrpsPorts()
	if bindPort != 7000 {
		t.Errorf("bind_port = %d，期望 7000（这一项不支持热改）", bindPort)
	}
	if proxyPorts.String() != "9100,9200" {
		t.Errorf("热更后的代理端口 = %q，期望 9100,9200", proxyPorts.String())
	}
	if protect.String() != "7000,9100,9200" {
		t.Errorf("热更后的受保护端口 = %q，期望 7000,9100,9200", protect.String())
	}

	des := m.desired()
	if len(des.PortBlacklists) != 1 {
		t.Fatalf("应有 1 个端口分组，实际 %v", des.PortBlacklists)
	}
	if got := des.PortBlacklists[0].Key; got != "7000,9100,9200" {
		t.Errorf("frp 分组的 Key = %q，仍是旧端口的话内核规则就挂在废弃端口上了", got)
	}
	if got := des.PortBlacklists[0].Ports.String(); got != "7000,9100,9200" {
		t.Errorf("frp 分组的端口 = %q", got)
	}

	last := des.RateLimits[len(des.RateLimits)-1]
	if last.Key != globalRateKey {
		t.Fatalf("最后一条应当是全局限速兜底，实际 Key=%q", last.Key)
	}
	if last.Ports.String() != "7000,9100,9200" {
		t.Errorf("全局限速兜底的端口 = %q，期望跟着热更一起变", last.Ports.String())
	}
}

// 自建函数会打印端口集合，别在测试里拼字符串字面量比对：归一化（合并相邻区间、
// 排序）是这一层的职责，写死字面量只能证明"我抄对了"，证明不了归一化对不对。
// 上面几处 Key 都用了这种现算的写法，这里把 Ports 的形状也钉一遍。
func TestPortGroupPortsAreNormalized(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.BanManual("203.0.113.50", "测试", "tester", time.Hour,
		model.ScopeCustom, portrange.Set{{Lo: 9000, Hi: 9002}, {Lo: 9003, Hi: 9005}}); err != nil {
		t.Fatal(err)
	}
	groups := groupByKey(m)
	if _, ok := groups["9000-9005"]; !ok {
		t.Errorf("相邻区间应合并成 9000-9005，实际分组：%v", groups)
	}
}
