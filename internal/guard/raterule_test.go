package guard

import (
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/config"
	"github.com/dreamstation625/FrpFireWall/internal/geoip"
	"github.com/dreamstation625/FrpFireWall/internal/model"
	"github.com/dreamstation625/FrpFireWall/internal/portrange"
	"github.com/dreamstation625/FrpFireWall/internal/store"
)

// ---------- 编译 ----------

// 落点由"有没有端口条件"决定，不是由"有没有地区条件"决定。
// 这条错了的表现是：规则看着配好了，实际落在一层里什么都不做。
func TestCompileRulesSplitsByLayer(t *testing.T) {
	rows := []model.RateRule{
		{ID: 1, Name: "香港限速", Enabled: true, Countries: "HK", PerSec: 5},
		{ID: 2, Name: "某段限速", Enabled: true, CIDRs: "203.0.113.0/24", PerSec: 5},
		{ID: 3, Name: "扫描限速", Enabled: true, Ports: "20000-30000", PerSec: 5},
		{ID: 4, Name: "停用的", Enabled: false, Countries: "US", PerSec: 5},
	}

	app, kernel, skipped := compileRules(rows)
	if len(skipped) != 0 {
		t.Fatalf("不该有跳过项：%v", skipped)
	}
	if len(app) != 2 {
		t.Fatalf("应用层应有 2 条（地区、网段），实际 %d 条", len(app))
	}
	if len(kernel) != 1 {
		t.Fatalf("内核层应有 1 条（带端口），实际 %d 条", len(kernel))
	}
	if app[0].name != "香港限速" || app[1].name != "某段限速" {
		t.Errorf("应用层顺序被改动了：%v", []string{app[0].name, app[1].name})
	}
	if kernel[0].name != "扫描限速" {
		t.Errorf("内核层规则不对：%q", kernel[0].name)
	}
}

// 一条坏规则不能把整个引擎带下水：剩下的必须照常生效，坏的那条要留下原因。
// 规则存在库里，手工改库、降级、换属地库之后都可能出现编译不过的行。
func TestCompileRulesSkipsBadRowsWithoutFailing(t *testing.T) {
	rows := []model.RateRule{
		{ID: 1, Name: "好的", Enabled: true, Countries: "HK", PerSec: 5},
		{ID: 2, Name: "混搭", Enabled: true, Countries: "HK", Ports: "443", PerSec: 5}, // 地区 + 端口
		{ID: 3, Name: "坏端口", Enabled: true, Ports: "70000", PerSec: 5},
		{ID: 4, Name: "没有条件", Enabled: true, PerSec: 5},
	}

	app, kernel, skipped := compileRules(rows)
	if len(app) != 1 || app[0].name != "好的" {
		t.Fatalf("应当只剩「好的」这一条应用层规则，实际 %v", app)
	}
	if len(kernel) != 0 {
		t.Fatalf("不该有内核层规则，实际 %v", kernel)
	}
	if len(skipped) != 3 {
		t.Fatalf("应当有 3 条被跳过并给出原因，实际 %d 条：%v", len(skipped), skipped)
	}
	for i, want := range []string{"无法生效", "无法识别", "没有任何匹配条件"} {
		if !strings.Contains(skipped[i], want) {
			t.Errorf("第 %d 条原因里没有 %q：%s", i+1, want, skipped[i])
		}
	}
}

// 应用规则的限速与封禁参数要按各自配置装进运行时结构。
func TestCompileRulesCarriesActions(t *testing.T) {
	rows := []model.RateRule{
		{
			ID: 7, Name: "组合", Enabled: true, Countries: "HK",
			PerSec: 5, Burst: 9,
			WindowSeconds: 30, Threshold: 12, BanDurations: "60,120",
		},
		{ID: 8, Name: "只限速", Enabled: true, Countries: "US", PerSec: 3},
	}
	app, _, _ := compileRules(rows)
	if len(app) != 2 {
		t.Fatalf("应有 2 条，实际 %d 条", len(app))
	}

	full := app[0]
	if full.threshold != 12 || full.window != 30*time.Second {
		t.Errorf("窗口/阈值没装对：%v / %v", full.window, full.threshold)
	}
	if len(full.steps) != 2 || full.steps[0] != 60 {
		t.Errorf("阶梯没装对：%v", full.steps)
	}
	if full.bucket == nil || full.perSec != 5 {
		t.Errorf("令牌桶没装对：bucket=%v perSec=%d", full.bucket, full.perSec)
	}
	if full.bucket.burst != 9 {
		t.Errorf("突发额度应为显式配置的 9，实际 %v", full.bucket.burst)
	}

	rateOnly := app[1]
	if rateOnly.threshold != 0 || rateOnly.window != 0 {
		t.Errorf("只限速的规则不该有窗口/阈值：%v / %v", rateOnly.window, rateOnly.threshold)
	}
	if rateOnly.bucket.burst != 6 { // PerSec*2
		t.Errorf("未配突发额度应按 PerSec*2 = 6 补齐，实际 %v", rateOnly.bucket.burst)
	}
}

// 阶梯填了分隔符却没填数字，属于"看起来配了封禁、实际封 0 秒"，
// 必须被 Validate 拦下并说明原因，而不是静默地兜一个默认值。
func TestCompileRulesRejectsGarbageLadder(t *testing.T) {
	rows := []model.RateRule{{
		ID: 1, Name: "空阶梯", Enabled: true, Countries: "HK",
		PerSec: 5, WindowSeconds: 30, Threshold: 3, BanDurations: " , ",
	}}
	app, _, skipped := compileRules(rows)
	if len(app) != 0 {
		t.Fatalf("阶梯填不出数字就不该编译出规则，实际 %+v", app)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0], "封禁配置不完整") {
		t.Fatalf("应当带「封禁配置不完整」被跳过，实际 %v", skipped)
	}
}

// 阶梯的两级兜底：规则自己没写就用全局策略的，全局也没有才用内置值。
//
// 这条不变量只能有**一处**实现（nextDuration），compileRules 那边不许再兜一遍 ——
// 两处都兜的话，"规则没写阶梯"会拿到 compileRules 里硬编码的那个值，
// 而不是全局策略里配的那个，改了一处另一处不动，表现成"全局阶梯改了没用"。
//
// 兜底值不能是 0：nextDuration 里 0 表示**永久封禁**，
// 兜底成 0 等于"漏配阶梯就把人永久封了"。
func TestNextDurationLadderFallback(t *testing.T) {
	m := newTestManager(t)

	p, err := m.store.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	p.EscalateWindowHours = 24
	p.BanDurations = "60,300"
	if err := m.store.SavePolicy(p); err != nil {
		t.Fatal(err)
	}

	// 规则没写阶梯 → 用全局策略的
	if d, step := m.nextDuration("never-banned", p, nil); d != 60*time.Second || step != 1 {
		t.Errorf("规则阶梯为空时应回退到全局策略的 60 秒（第 1 级），实际 %v（第 %d 级）", d, step)
	}
	// 规则自己写了 → 用规则自己的，不看全局
	if d, _ := m.nextDuration("never-banned", p, []int64{86400}); d != 86400*time.Second {
		t.Errorf("规则自己的阶梯应当优先，实际 %v", d)
	}
	// 两级都空 → 内置 600 秒，不能是 0（0 = 永久）
	if d, _ := m.nextDuration("never-banned", &model.Policy{}, nil); d != 600*time.Second {
		t.Errorf("两级都空时应兜底 600 秒，实际 %v（0 表示永久封禁）", d)
	}
}

// ---------- 匹配 ----------

func TestAppRuleMatchSemantics(t *testing.T) {
	// 注意两边的写法是**故意不一致**的：规则里存的是归一化之后的「广东」，
	// 而属地库这边返回的是全称「广东省」。匹配必须照样命中 —— 这正是
	// CanonicalProvince 存在的理由（见 model/province.go）。
	hk := &geoip.Info{Country: "HK", Province: "广东省"}
	us := &geoip.Info{Country: "US", Province: "California"}
	addr := netip.MustParseAddr("203.0.113.7")

	cases := []struct {
		name string
		rule appRule
		geo  *geoip.Info
		want bool
	}{
		{"无条件：全命中", appRule{}, hk, true},
		{"国家命中", appRule{countries: map[string]bool{"HK": true}}, hk, true},
		{"国家不命中", appRule{countries: map[string]bool{"HK": true}}, us, false},
		{"多国家取或", appRule{countries: map[string]bool{"HK": true, "US": true}}, us, true},
		{"省份命中（规则存简称、库返回全称）", appRule{provinces: map[string]bool{"广东": true}}, hk, true},
		{"省份不命中", appRule{provinces: map[string]bool{"福建": true}}, hk, false},
		{
			"不同维度之间是且：国家中了省份不中 → 不命中",
			appRule{countries: map[string]bool{"HK": true}, provinces: map[string]bool{"福建": true}},
			hk, false,
		},
		{
			"不同维度之间是且：两个都中 → 命中",
			appRule{countries: map[string]bool{"HK": true}, provinces: map[string]bool{"广东": true}},
			hk, true,
		},
		{
			"网段命中",
			appRule{prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}},
			hk, true,
		},
		{
			"网段不命中",
			appRule{prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}},
			hk, false,
		},
		{
			"多个网段取或",
			appRule{prefixes: []netip.Prefix{
				netip.MustParsePrefix("198.51.100.0/24"),
				netip.MustParsePrefix("203.0.113.0/24"),
			}},
			hk, true,
		},
		{
			"属地查不到时算不命中，而不是把所有地址都卷进来",
			appRule{countries: map[string]bool{"HK": true}},
			&geoip.Info{}, false,
		},
		{
			"属地库没加载（geo 为 nil）时同样不命中",
			appRule{countries: map[string]bool{"HK": true}},
			nil, false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.rule.match(addr, c.geo, ""); got != c.want {
				t.Fatalf("match = %v，期望 %v", got, c.want)
			}
		})
	}
}

// 代理（隧道）名作为匹配维度：写了就必须对得上。
//
// 关键一条是 **Login 回调传空串时不命中** —— 隧道是 NewUserConn 那一刻才定的，
// 登录阶段没有这个信息。这不是缺陷，是那一刻确实不知道；留空比拿别的维度凑合
// 诚实。用户侧的表现是"给某代理配的规则在登录阶段不生效"，界面与文档都要讲明。
func TestAppRuleMatchProxyName(t *testing.T) {
	hk := &geoip.Info{Country: "HK"}
	addr := netip.MustParseAddr("203.0.113.7")

	cases := []struct {
		name  string
		rule  appRule
		proxy string
		want  bool
	}{
		{"不限代理：任何隧道都命中", appRule{}, "web-ssh", true},
		{"不限代理：登录阶段（无代理名）也命中", appRule{}, "", true},
		{"指定代理且一致", appRule{proxy: "web-ssh"}, "web-ssh", true},
		{"指定代理但不一致", appRule{proxy: "web-ssh"}, "web-1", false},
		{"指定代理、登录阶段没有代理名 → 不命中", appRule{proxy: "web-ssh"}, "", false},
		{"代理与其它维度是且：代理中、地区不中", appRule{
			proxy: "web-ssh", countries: map[string]bool{"US": true},
		}, "web-ssh", false},
		{"代理与其它维度是且：都中", appRule{
			proxy: "web-ssh", countries: map[string]bool{"HK": true},
		}, "web-ssh", true},
		// frp 的代理名区分大小写，匹配也就必须区分。
		{"大小写不同算两个代理", appRule{proxy: "Web-SSH"}, "web-ssh", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.rule.match(addr, hk, c.proxy); got != c.want {
				t.Fatalf("match = %v，期望 %v", got, c.want)
			}
		})
	}
}

// 不同代理配不同力度：靠"顺序 + 各自的条件"分流，第一条命中的取代全局。
func TestPickAppRulePicksPerProxy(t *testing.T) {
	addr := netip.MustParseAddr("203.0.113.7")
	geo := &geoip.Info{Country: "HK"}
	rules := []appRule{
		{id: 1, name: "不限代理的兜底", countries: map[string]bool{"HK": true}},
		{id: 2, name: "web-ssh 专用", proxy: "web-ssh"},
	}
	// 顺序在前的不限代理规则会先命中，所以"专用"规则要排在它前面 ——
	// 这正是界面上顺序可调的意义：同一个来源在不同隧道上会落进不同的规则。
	if got := pickAppRule(rules, addr, geo, "web-ssh"); got == nil || got.name != "不限代理的兜底" {
		t.Fatalf("顺序在前的不限代理规则应当先命中，实际 %v", got)
	}

	reordered := []appRule{rules[1], rules[0]}
	if got := pickAppRule(reordered, addr, geo, "web-ssh"); got == nil || got.name != "web-ssh 专用" {
		t.Fatalf("专用规则排到前面之后应当先命中，实际 %v", got)
	}
	// 别的隧道不受这条专用规则影响，仍然走不限代理那条
	if got := pickAppRule(reordered, addr, geo, "web-1"); got == nil || got.name != "不限代理的兜底" {
		t.Fatalf("别的隧道不该命中 web-ssh 专用规则，实际 %v", got)
	}
}

// 按顺序取第一条命中的：细分规则"命中即取代全局"就靠这个顺序。
func TestPickAppRuleUsesOrder(t *testing.T) {
	hk := &geoip.Info{Country: "HK"}
	rules := []appRule{
		{id: 1, name: "第一条", countries: map[string]bool{"US": true}},
		{id: 2, name: "第二条", countries: map[string]bool{"HK": true}},
		{id: 3, name: "第三条", countries: map[string]bool{"HK": true}},
	}
	got := pickAppRule(rules, netip.MustParseAddr("203.0.113.7"), hk, "")
	if got == nil || got.name != "第二条" {
		t.Fatalf("应当命中「第二条」，实际 %v", got)
	}

	if pickAppRule(rules, netip.MustParseAddr("203.0.113.7"), &geoip.Info{Country: "JP"}, "") != nil {
		t.Error("都不命中时应当返回 nil，交给全局策略")
	}
}

// ---------- 令牌桶 ----------

func TestTokenBucket(t *testing.T) {
	b := newTokenBucket(10, 3)
	now := time.Now()

	// 新来源从满桶开始：否则每个新 IP 的第一次连接都会被拒。
	for i := 0; i < 3; i++ {
		if !b.allow("1.2.3.4", now) {
			t.Fatalf("第 %d 个请求应当放行（突发额度 3）", i+1)
		}
	}
	if b.allow("1.2.3.4", now) {
		t.Fatal("额度用完后应当拒绝")
	}

	// 别的来源不受影响 —— 桶是按来源 IP 分的。
	if !b.allow("5.6.7.8", now) {
		t.Fatal("另一个来源应当有自己的额度")
	}

	// 过 200ms，按 10/s 补 2 个令牌。
	later := now.Add(200 * time.Millisecond)
	if !b.allow("1.2.3.4", later) || !b.allow("1.2.3.4", later) {
		t.Fatal("补充的令牌应当可用")
	}
	if b.allow("1.2.3.4", later) {
		t.Fatal("补充的令牌只有 2 个，第三个应当被拒")
	}

	// 长时间空闲后不该超过桶容量。
	long := now.Add(time.Hour)
	for i := 0; i < 3; i++ {
		if !b.allow("1.2.3.4", long) {
			t.Fatalf("空闲后第 %d 个请求应当放行", i+1)
		}
	}
	if b.allow("1.2.3.4", long) {
		t.Fatal("令牌不该超过桶容量")
	}
}

func TestTokenBucketNilAndPrune(t *testing.T) {
	var nilBucket *tokenBucket
	if !nilBucket.allow("1.2.3.4", time.Now()) {
		t.Error("没有令牌桶（不限速）时应当一律放行")
	}

	b := newTokenBucket(10, 3)
	now := time.Now()
	b.allow("1.2.3.4", now)
	b.allow("5.6.7.8", now)
	b.prune(now.Add(-time.Minute)) // 全部都是"新"的，不该被清
	if len(b.state) != 2 {
		t.Fatalf("不该清掉活跃条目，实际剩 %d 条", len(b.state))
	}
	b.prune(now.Add(time.Minute)) // 全部过期
	if len(b.state) != 0 {
		t.Fatalf("过期条目应当被清空，实际剩 %d 条", len(b.state))
	}
}

// ---------- 判定端到端 ----------

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("打开测试库失败：%v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	m := New(config.Default(), st, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := m.Refresh(); err != nil {
		t.Fatalf("加载状态失败：%v", err)
	}
	return m
}

func setPolicy(t *testing.T, m *Manager, mutate func(p *model.Policy)) {
	t.Helper()
	p, err := m.store.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	mutate(p)
	if err := m.store.SavePolicy(p); err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(); err != nil {
		t.Fatal(err)
	}
}

// 命中细分规则后，窗口、阈值、阶梯全部换成规则的 —— 这就是"命中即取代全局"。
func TestJudgeRuleOverridesGlobal(t *testing.T) {
	m := newTestManager(t)
	setPolicy(t, m, func(p *model.Policy) {
		p.AutoBanEnabled = true
		p.ObserveOnly = false
		p.WindowSeconds = 3600
		p.Threshold = 9999 // 全局阈值高到不可能触发，用来证明用的是规则那份
		p.BanDurations = "9999"
	})

	if err := m.store.ReplaceRateRules([]model.RateRule{{
		Name: "坏来源", Enabled: true, CIDRs: "203.0.113.0/24",
		WindowSeconds: 60, Threshold: 2, BanDurations: "120",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(); err != nil {
		t.Fatal(err)
	}

	addr := netip.MustParseAddr("203.0.113.7")
	if v := m.JudgeLogin(addr, "u", "h"); !v.Allow {
		t.Fatalf("第 1 次不该拦：%+v", v)
	}
	if v := m.JudgeLogin(addr, "u", "h"); v.Allow || v.Reason != "rate-exceeded" {
		t.Fatalf("第 2 次应当按规则阈值（2 次）触发封禁，实际 %+v", v)
	}

	bans := m.Bans()
	if len(bans) != 1 {
		t.Fatalf("应当产生 1 条封禁，实际 %d 条", len(bans))
	}
	// 阶梯用的是规则自己的 120 秒，不是全局的 9999。
	if bans[0].RemainingSec <= 0 || bans[0].RemainingSec > 121 {
		t.Errorf("封禁时长应来自规则自己的阶梯（120 秒），实际 %d 秒", bans[0].RemainingSec)
	}
	if !strings.Contains(bans[0].Reason, "坏来源") {
		t.Errorf("封禁原因里应带上规则名，实际 %q", bans[0].Reason)
	}
}

// 没有细分规则命中时，一切照旧走全局策略。
func TestJudgeFallsBackToGlobal(t *testing.T) {
	m := newTestManager(t)
	setPolicy(t, m, func(p *model.Policy) {
		p.AutoBanEnabled = true
		p.ObserveOnly = false
		p.WindowSeconds = 60
		p.Threshold = 2
		p.BanDurations = "300"
	})

	if err := m.store.ReplaceRateRules([]model.RateRule{{
		Name: "只对某个网段", Enabled: true, CIDRs: "198.51.100.0/24",
		WindowSeconds: 60, Threshold: 99, BanDurations: "60",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(); err != nil {
		t.Fatal(err)
	}

	addr := netip.MustParseAddr("203.0.113.7") // 不在规则网段内
	if v := m.JudgeLogin(addr, "u", "h"); !v.Allow {
		t.Fatalf("第 1 次不该拦：%+v", v)
	}
	if v := m.JudgeLogin(addr, "u", "h"); v.Allow {
		t.Fatalf("第 2 次应当按全局阈值（2 次）触发，实际 %+v", v)
	}
	bans := m.Bans()
	if len(bans) != 1 || bans[0].RemainingSec > 301 {
		t.Fatalf("应当按全局阶梯封 300 秒，实际 %+v", bans)
	}
}

// 只配了限速、没配封禁的规则：超过速率立刻拒，不产生封禁记录。
func TestJudgeRuleRateLimitOnly(t *testing.T) {
	m := newTestManager(t)
	setPolicy(t, m, func(p *model.Policy) {
		p.AutoBanEnabled = true
		p.ObserveOnly = false
		p.WindowSeconds = 60
		p.Threshold = 2
		p.BanDurations = "300"
	})

	if err := m.store.ReplaceRateRules([]model.RateRule{{
		Name: "只限速", Enabled: true, CIDRs: "203.0.113.0/24", PerSec: 1, Burst: 2,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(); err != nil {
		t.Fatal(err)
	}

	addr := netip.MustParseAddr("203.0.113.7")
	// 突发额度 2：前两次放行，第三次被限速拒掉。
	if v := m.JudgeLogin(addr, "u", "h"); !v.Allow {
		t.Fatalf("第 1 次不该拦：%+v", v)
	}
	if v := m.JudgeLogin(addr, "u", "h"); !v.Allow {
		t.Fatalf("第 2 次不该拦（突发额度 2）：%+v", v)
	}
	v := m.JudgeLogin(addr, "u", "h")
	if v.Allow || v.Reason != "rate-limited" {
		t.Fatalf("第 3 次应当被限速拦下，实际 %+v", v)
	}
	// 规则没有配阈值，所以不该封禁；全局的阈值 2 也不该被用上。
	if bans := m.Bans(); len(bans) != 0 {
		t.Fatalf("只限速的规则不该产生封禁记录，实际 %+v", bans)
	}
}

// 规则只作用在自己的网段上，网段外照常走全局。
func TestJudgeRuleScopedToItsCIDR(t *testing.T) {
	m := newTestManager(t)
	setPolicy(t, m, func(p *model.Policy) {
		p.AutoBanEnabled = true
		p.ObserveOnly = false
		p.WindowSeconds = 60
		p.Threshold = 2
		p.BanDurations = "300"
	})

	if err := m.store.ReplaceRateRules([]model.RateRule{{
		Name: "宽网段", Enabled: true, CIDRs: "10.0.0.0/8",
		WindowSeconds: 60, Threshold: 100, BanDurations: "60",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(); err != nil {
		t.Fatal(err)
	}

	// 规则网段外：按全局阈值 2 次封禁。
	outside := netip.MustParseAddr("203.0.113.7")
	m.JudgeLogin(outside, "u", "h")
	if v := m.JudgeLogin(outside, "u", "h"); v.Allow {
		t.Fatalf("规则网段外应当走全局阈值，实际 %+v", v)
	}
}

// 内核限速规则的顺序：细分规则在前，全局兜底在最后。
// 反过来的话，全局那条会先把所有连接吃掉，细分规则永远轮不到。
func TestDesiredRateLimitsOrder(t *testing.T) {
	m := newTestManager(t)
	setPolicy(t, m, func(p *model.Policy) {
		p.RateLimitEnabled = true
		p.RateLimitPerSec = 20
		p.RateLimitBurst = 40
	})
	if err := m.store.ReplaceRateRules([]model.RateRule{
		{Name: "第一条", Enabled: true, Ports: "20000-30000", PerSec: 5},
		{Name: "第二条", Enabled: true, CIDRs: "203.0.113.0/24", Ports: "443", PerSec: 50},
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(); err != nil {
		t.Fatal(err)
	}

	des := m.desired()
	if len(des.RateLimits) != 3 {
		t.Fatalf("应有 2 条细分 + 1 条全局 = 3 条，实际 %d 条", len(des.RateLimits))
	}
	if des.RateLimits[0].Name != "第一条" || des.RateLimits[1].Name != "第二条" {
		t.Errorf("细分规则的顺序被改动了：%+v", des.RateLimits)
	}
	last := des.RateLimits[2]
	if last.Key != globalRateKey {
		t.Errorf("最后一条应当是全局兜底，实际 Key=%q", last.Key)
	}
	if last.PerSec != 20 || last.Burst != 40 {
		t.Errorf("全局兜底参数不对：%+v", last)
	}
	// 全局兜底作用在受保护端口上（bind_port 7000 + proxy_ports 80,443）。
	if got := last.Ports.String(); got != "80,443,7000" {
		t.Errorf("全局兜底的端口应为受保护端口，实际 %q", got)
	}

	// 细分那条带网段的规则要把网段带上，否则会变成"全网限速"。
	if len(des.RateLimits[1].Sources) != 1 || des.RateLimits[1].Sources[0] != "203.0.113.0/24" {
		t.Errorf("来源段没带上：%+v", des.RateLimits[1].Sources)
	}
}

// 关掉全局限速后就不该再产生全局兜底那条 —— 否则"关掉了还在限"比不关更糟。
func TestDesiredRateLimitsGlobalOff(t *testing.T) {
	m := newTestManager(t)
	setPolicy(t, m, func(p *model.Policy) { p.RateLimitEnabled = false })

	if err := m.store.ReplaceRateRules([]model.RateRule{
		{Name: "细分", Enabled: true, Ports: "20000-30000", PerSec: 5},
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(); err != nil {
		t.Fatal(err)
	}

	des := m.desired()
	if len(des.RateLimits) != 1 || des.RateLimits[0].Name != "细分" {
		t.Fatalf("全局关掉后应当只剩细分那条，实际 %+v", des.RateLimits)
	}
}

// 停用的规则完全不下发。
func TestDisabledRuleProducesNothing(t *testing.T) {
	m := newTestManager(t)
	if err := m.store.ReplaceRateRules([]model.RateRule{
		{Name: "停用的", Enabled: false, Ports: "443", PerSec: 5},
		{Name: "停用的应用规则", Enabled: false, Countries: "HK", PerSec: 5},
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(); err != nil {
		t.Fatal(err)
	}

	des := m.desired()
	if len(des.RateLimits) != 0 {
		t.Fatalf("停用的内核规则不该下发，实际 %+v", des.RateLimits)
	}
	if m.AppRuleCount() != 0 {
		t.Fatalf("停用的应用规则不该生效，实际 %d 条", m.AppRuleCount())
	}
}

// 解封要把该地址在**所有规则**下的窗口一并清零。
// 只清全局那一个的话，刚解封的人下一次访问就带着上次攒满的计数，立刻又被封。
func TestUnbanClearsAllRuleWindows(t *testing.T) {
	m := newTestManager(t)
	addr := netip.MustParseAddr("203.0.113.7")

	m.mu.Lock()
	m.windows[windowKey("", addr.String())] = &hitWindow{hits: []int64{1, 2, 3}, last: time.Now()}
	m.windows[windowKey("r1", addr.String())] = &hitWindow{hits: []int64{1, 2, 3}, last: time.Now()}
	m.windows[windowKey("r2", addr.String())] = &hitWindow{hits: []int64{1, 2, 3}, last: time.Now()}
	m.mu.Unlock()

	m.mu.Lock()
	m.resetWindowsForLocked(addr.String())
	m.mu.Unlock()

	m.mu.RLock()
	defer m.mu.RUnlock()
	for k, w := range m.windows {
		if w.count(time.Now(), time.Hour) != 0 {
			t.Errorf("窗口 %q 没被清零", k)
		}
	}
}

// 端口条件与地区条件不可能同时生效，编译时也不能偷偷只留一边。
func TestCompileRulesRejectsMixedConditions(t *testing.T) {
	rows := []model.RateRule{{
		ID: 1, Name: "混搭", Enabled: true,
		Countries: "HK", Ports: "20000-30000", PerSec: 5,
	}}
	app, kernel, skipped := compileRules(rows)
	if len(app) != 0 || len(kernel) != 0 {
		t.Fatalf("混搭条件不该落到任何一层：app=%v kernel=%v", app, kernel)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0], "无法生效") {
		t.Fatalf("应当给出明确原因，实际 %v", skipped)
	}
}

// 内核规则的 Key 由 ID 派生，必须稳定且互不相同。
func TestRuleKeyStability(t *testing.T) {
	if ruleKey(1) != ruleKey(1) {
		t.Error("同一个 ID 应派生出同一个 Key")
	}
	seen := map[string]uint{}
	for id := uint(1); id <= 200; id++ {
		k := ruleKey(id)
		if prev, dup := seen[k]; dup {
			t.Fatalf("ID %d 与 %d 撞成同一个 Key %q", id, prev, k)
		}
		seen[k] = id
	}
	if ruleKey(1) == globalRateKey {
		t.Error("细分规则的 Key 不能和全局兜底撞")
	}
}

// 确保 portrange 被用到（受保护端口的合并结果），避免测试文件出现无用的 import。
var _ = portrange.Ports

// 不同代理不同力度：一条只对 web-ssh 生效的规则，端到端走一遍判定。
//
// 这里钉的是**整条链**：库 → compileRules → judge → 匹配。只测 appRule.match
// 的话，中间任何一层忘了把代理名传下去（比如 judge 调用 matchAppRule 时少传
// 一个参数），用例照样是绿的，而功能实际不存在。
func TestJudgeRuleScopedToProxy(t *testing.T) {
	m := newTestManager(t)
	setPolicy(t, m, func(p *model.Policy) {
		p.AutoBanEnabled = true
		p.ObserveOnly = false
		p.WindowSeconds = 3600
		p.Threshold = 9999 // 全局阈值高到不可能触发，用来证明命中的是规则那份
		p.BanDurations = "9999"
	})

	if err := m.store.ReplaceRateRules([]model.RateRule{{
		Name: "web-ssh 专用", Enabled: true, ProxyName: "web-ssh",
		WindowSeconds: 60, Threshold: 2, BanDurations: "120",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(); err != nil {
		t.Fatal(err)
	}

	addr := netip.MustParseAddr("203.0.113.7")
	conn := func(proxy string) Verdict {
		return m.JudgeUserConn(addr, addr.String()+":1234", "u", proxy)
	}

	// 别的隧道不受这条规则影响：全局阈值是 9999，两次连接不会触发任何东西
	if v := conn("web-1"); !v.Allow {
		t.Fatalf("别的隧道不该被这条规则命中，实际 %+v", v)
	}
	if v := conn("web-1"); !v.Allow {
		t.Fatalf("别的隧道第二次也不该被拦，实际 %+v", v)
	}
	if len(m.Bans()) != 0 {
		t.Fatalf("不该产生封禁，实际 %+v", m.Bans())
	}

	// web-ssh 上按规则自己的阈值（2 次）触发
	if v := conn("web-ssh"); !v.Allow {
		t.Fatalf("第 1 次不该拦：%+v", v)
	}
	if v := conn("web-ssh"); v.Allow || v.Reason != "rate-exceeded" {
		t.Fatalf("第 2 次应当按规则阈值触发封禁，实际 %+v", v)
	}
	bans := m.Bans()
	if len(bans) != 1 {
		t.Fatalf("应当产生 1 条封禁，实际 %d 条", len(bans))
	}
	if bans[0].RemainingSec <= 0 || bans[0].RemainingSec > 121 {
		t.Errorf("封禁时长应来自规则自己的阶梯（120 秒），实际 %d 秒", bans[0].RemainingSec)
	}

	// 登录阶段没有代理名，带代理条件的规则不参与 —— 这是那一刻没有这个信息，
	// 不是规则没配好。
	if v := m.JudgeLogin(netip.MustParseAddr("198.51.100.9"), "u", "h"); !v.Allow {
		t.Fatalf("登录阶段（无代理名）不该被代理规则拦，实际 %+v", v)
	}
}
