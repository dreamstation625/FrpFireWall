package guard

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/geoip"
	"github.com/dreamstation625/FrpFireWall/internal/model"
)

// 地区条目**一条内核规则都不产生**。
//
// 内核认不出属地（mmdb / ip2region 都是查询型库，没法反向枚举出一个国家的
// CIDR 列表），所以地区条目的落地方式是"命中之后把这个具体 IP 封掉"，由判定链做。
// 这条要是错了，表现是内核里凭空多出一堆解析不出来的源、或者干脆整个同步失败。
func TestGeoEntriesProduceNoKernelRules(t *testing.T) {
	m := newTestManager(t)

	rows := []model.ACLEntry{
		{Kind: model.KindBlack, Target: "CN,HK", TargetType: model.TargetGeoCountry, Scope: model.ScopeAll, Source: model.SourceManual},
		{Kind: model.KindBlack, Target: "广东,福建", TargetType: model.TargetGeoProvince, Scope: model.ScopeAll, Source: model.SourceManual},
		{Kind: model.KindBlack, Target: "深圳", TargetType: model.TargetGeoCity, Scope: model.ScopeAll, Source: model.SourceManual},
		{Kind: model.KindWhite, Target: "US", TargetType: model.TargetGeoCountry, Scope: model.ScopeAll, Source: model.SourceManual},
		// 一条普通地址条目做对照：它必须照常进内核，证明上面那几条是被
		// "类型是地区"筛掉的，而不是因为别的什么原因整批都没进来。
		{Kind: model.KindBlack, Target: "203.0.113.9", TargetType: "ipv4", Scope: model.ScopeAll, Source: model.SourceManual},
	}
	for i := range rows {
		if err := m.store.UpsertACL(&rows[i]); err != nil {
			t.Fatalf("写入名单失败：%v", err)
		}
	}
	if err := m.Refresh(); err != nil {
		t.Fatalf("重载失败：%v", err)
	}

	if len(m.geoBlack) != 3 {
		t.Fatalf("黑名单地区条目应有 3 条，实际 %d 条：%+v", len(m.geoBlack), m.geoBlack)
	}
	if len(m.geoWhite) != 1 {
		t.Fatalf("白名单地区条目应有 1 条，实际 %d 条", len(m.geoWhite))
	}

	d := m.desired()
	if len(d.Blacklist) != 1 || d.Blacklist[0] != "203.0.113.9/32" {
		t.Fatalf("内核黑名单里应当只有那条普通地址，实际 %v", d.Blacklist)
	}
	if len(d.PortBlacklists) != 0 {
		t.Fatalf("不该产生端口分组，实际 %d 组", len(d.PortBlacklists))
	}
	if len(d.Whitelist) != 0 {
		t.Fatalf("地区白名单条目不该进内核白名单，实际 %v", d.Whitelist)
	}

	// 也不该凭空封谁：地区条目只在**命中**时才封那个具体 IP。
	if bans := m.Bans(); len(bans) != 0 {
		t.Fatalf("只加载名单不该产生封禁，实际 %+v", bans)
	}
}

// 过期与空值的地区条目要在加载时就被筛掉，不能留到判定链里每次白比一遍。
func TestToGeoEntriesSkipsExpiredAndEmpty(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	rows := []model.ACLEntry{
		{ID: 1, Target: "CN", TargetType: model.TargetGeoCountry, Enabled: true},
		{ID: 2, Target: "US", TargetType: model.TargetGeoCountry, ExpiresAt: &past, Enabled: true},
		{ID: 3, Target: "JP", TargetType: model.TargetGeoCountry, ExpiresAt: &future, Enabled: true},
		{ID: 4, Target: "   ", TargetType: model.TargetGeoCountry, Enabled: true},
		// 手工改坏的库：类型是地区、值是地址。筛不掉的话判定时只会白比一遍。
		{ID: 5, Target: "203.0.113.9", TargetType: "ipv4", Enabled: true},
		// 停用的条目与"不在名单里"等价，哪怕还没到期也不参与判定。
		{ID: 6, Target: "DE", TargetType: model.TargetGeoCountry, ExpiresAt: &future},
	}
	got := toGeoEntries(rows, now)
	if len(got) != 2 {
		t.Fatalf("应当只剩 2 条有效的地区条目，实际 %d 条：%+v", len(got), got)
	}
	if got[0].id != 1 || got[1].id != 3 {
		t.Errorf("留下的应当是 ID 1 与 3，实际 %d 与 %d", got[0].id, got[1].id)
	}
	if got[0].kind != model.TargetGeoCountry || got[0].list != "CN" {
		t.Errorf("条目内容被改动了：%+v", got[0])
	}
}

// 停用的地址条目在三条装载路径上都等于"不在名单里"：不进内核白名单、
// 不进内核黑名单，也没有端口分组可留。
func TestDisabledEntriesSkippedEverywhere(t *testing.T) {
	now := time.Now()
	rows := []model.ACLEntry{
		{ID: 1, Kind: model.KindBlack, Target: "203.0.113.9", TargetType: "ipv4", Scope: model.ScopeAll, Enabled: true},
		{ID: 2, Kind: model.KindBlack, Target: "203.0.113.10", TargetType: "ipv4", Scope: model.ScopeAll},
	}
	if got := toPrefixes(rows, now); len(got) != 1 || got[0].String() != "203.0.113.9/32" {
		t.Fatalf("toPrefixes 应当只留启用的那条，实际 %v", got)
	}
	got := toBlockTargets(rows, now)
	if len(got) != 1 || got[0].Prefix.String() != "203.0.113.9/32" {
		t.Fatalf("toBlockTargets 应当只留启用的那条，实际 %+v", got)
	}
}

// 查询侧（属地库返回的原始值）必须过与名单侧同一套归一化，否则永远对不上，
// 而且是静默不命中 —— 界面上那条条目看着好好的，实际一次都没生效过。
func TestMatchGeoLockedNormalisesQuerySide(t *testing.T) {
	m := newTestManager(t)

	list := []geoEntry{
		{id: 1, kind: model.TargetGeoProvince, list: "广东,福建"},
		{id: 2, kind: model.TargetGeoCity, list: "深圳"},
	}

	// 属地库返回全称「广东省」；名单里存的是归一后的「广东」。
	hit := m.matchGeoLocked(list, &geoip.Info{Country: "CN", Province: "广东省", City: "深圳市"})
	if hit == nil || hit.id != 1 {
		t.Fatalf("省份条目应当命中（广东省 → 广东），实际 %+v", hit)
	}
	if !strings.HasPrefix(list[0].kind, "geo_") {
		t.Fatalf("条目类型被改动了：%q", list[0].kind)
	}

	// 同一份属地换一份名单：城市条目也该命中。
	city := m.matchGeoLocked([]geoEntry{{id: 9, kind: model.TargetGeoCity, list: "深圳"}},
		&geoip.Info{Country: "CN", Province: "广东省", City: "深圳市"})
	if city == nil || city.id != 9 {
		t.Fatalf("城市条目应当命中（深圳市 → 深圳），实际 %+v", city)
	}

	// 属地为空（库没加载 / 内网地址）时一律不命中。反过来做的话，
	// "只封某省"会在属地库没加载的机器上变成"封住所有人"。
	if got := m.matchGeoLocked(list, &geoip.Info{IP: "10.0.0.1"}); got != nil {
		t.Errorf("属地查不到时不该命中，实际 %+v", got)
	}
	if got := m.matchGeoLocked(list, nil); got != nil {
		t.Errorf("属地信息为 nil 时不该命中，实际 %+v", got)
	}
}

// 命中即拦截：规则命中就拒绝，并把这个具体 IP 封进内核，来源引用指向规则本身。
//
// 这里不依赖属地库 —— 用网段条件就能走完"命中 → 封禁 → 记录来源"整条链，
// 而来源引用正是"规则被删/停用之后要反向解禁"的唯一依据。
func TestRuleBlockBansAndReleasesByRef(t *testing.T) {
	m := newTestManager(t)
	setPolicy(t, m, func(p *model.Policy) {
		p.AutoBanEnabled = true
		p.ObserveOnly = false
		p.WindowSeconds = 60
		p.Threshold = 9999 // 全局阈值高到不可能触发，证明这次封禁来自规则
		p.BanDurations = "600"
	})

	rule := model.RateRule{
		Name: "整段拉黑", Enabled: true, CIDRs: "203.0.113.0/24", Block: true,
	}
	if err := m.store.ReplaceRateRules([]model.RateRule{rule}); err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(); err != nil {
		t.Fatal(err)
	}

	addr := netip.MustParseAddr("203.0.113.7")
	v := m.JudgeLogin(addr, "u", "h")
	if v.Allow || v.Reason != "rule-blocked" {
		t.Fatalf("命中即拦截应当直接拒绝，实际 %+v", v)
	}

	bans := m.Bans()
	if len(bans) != 1 {
		t.Fatalf("应当产生 1 条封禁，实际 %d 条", len(bans))
	}
	if bans[0].Source != model.SourceRule {
		t.Errorf("封禁来源应为 %q，实际 %q", model.SourceRule, bans[0].Source)
	}
	// 前端就是靠这个字段判断"手动解封要不要连带清掉背后那条规则/条目"，
	// 不暴露出来的话，那句提醒永远不会出现。
	ref := bans[0].SourceRef
	if model.BanSourceRefKind(ref) != model.BanRefRule {
		t.Fatalf("来源引用应指向规则，实际 %q", ref)
	}
	// 规则引用里的标识是内容签名（十六进制），不是自增 ID —— 所以判断类型
	// 只能用 BanSourceRefKind，不能靠 ParseBanSourceRef 的成败（见它与
	// TestBanSourceRefKind 里的说明）。
	if !strings.Contains(ref, ":") {
		t.Fatalf("来源引用应当形如 rule:xxxx，实际 %q", ref)
	}

	// 规则停用（等价于"依据消失"）之后，由它封掉的地址要能按引用一次性解禁。
	n, err := m.ReleaseBansByRef(ref, "tester", "规则已停用")
	if err != nil {
		t.Fatalf("按来源解禁失败：%v", err)
	}
	if n != 1 {
		t.Fatalf("应当解禁 1 条，实际 %d 条", n)
	}
	if bans := m.Bans(); len(bans) != 0 {
		t.Fatalf("解禁后不该还有活跃封禁，实际 %+v", bans)
	}
	if left, err := m.store.CountActiveBansOfRef(ref); err != nil || left != 0 {
		t.Fatalf("库里的活跃封禁也应清零，实际 %d 条（err=%v）", left, err)
	}

	// 解禁要落进内核可见的状态里：防火墙规则是 banState 的投影，
	// 只清库不清内存的话，地址在界面与库里都"已解禁"，实际仍连不进来。
	if d := m.desired(); len(d.Blacklist) != 0 {
		t.Fatalf("解禁后内核黑名单应为空，实际 %v", d.Blacklist)
	}
}

// 按来源解禁时没有命中任何封禁，不算错误：删条目、停用规则这些动作都会
// 顺手调一次，绝大多数时候本来就没有被它封过的地址。
func TestReleaseBansByRefNoMatch(t *testing.T) {
	m := newTestManager(t)

	n, err := m.ReleaseBansByRef(model.BanSourceRef(model.BanRefACL, 999), "tester", "没事发生")
	if err != nil {
		t.Fatalf("无命中不该报错：%v", err)
	}
	if n != 0 {
		t.Fatalf("无命中应返回 0，实际 %d", n)
	}
}

// 黑名单地区条目命中时的来源引用要指向**那一条条目**，不是"地区"这种笼统说法。
//
// 界面上的"删除条目会一并解禁"、以及后端 clearBanSourceEntry 的"解封时清掉
// 背后那条条目"，全靠这个引用找到具体是哪一条。这里直接构造属地信息，
// 不依赖属地库文件（仓库里没有 xdb / mmdb）。
func TestGeoBanSourceRefPointsAtEntry(t *testing.T) {
	m := newTestManager(t)

	entry := &model.ACLEntry{
		Kind: model.KindBlack, Target: "CN", TargetType: model.TargetGeoCountry,
		Scope: model.ScopeAll, Source: model.SourceManual,
	}
	if err := m.store.UpsertACL(entry); err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(); err != nil {
		t.Fatal(err)
	}

	hit := m.matchGeoLocked(m.geoBlack, &geoip.Info{Country: "CN", Found: true})
	if hit == nil {
		t.Fatal("应当命中刚写入的国家条目")
	}
	if hit.id != entry.ID {
		t.Fatalf("命中的条目 ID 应为 %d，实际 %d", entry.ID, hit.id)
	}

	ref := model.BanSourceRef(model.BanRefACL, hit.id)
	m.triggerBan(netip.MustParseAddr("203.0.113.77"), model.SourceGeoIP,
		"来源属地命中黑名单条目", "u", "web-ssh", &geoip.Info{Country: "CN"}, nil, ref)

	bans := m.Bans()
	if len(bans) != 1 {
		t.Fatalf("应当产生 1 条封禁，实际 %d 条", len(bans))
	}
	if bans[0].SourceRef != ref {
		t.Fatalf("封禁来源引用应为 %q，实际 %q", ref, bans[0].SourceRef)
	}

	// 删掉那条条目时的联动解禁，走的就是同一个引用。
	n, err := m.ReleaseBansByRef(ref, "tester", "名单条目已删除")
	if err != nil || n != 1 {
		t.Fatalf("应当解禁 1 条（err=%v），实际 %d 条", err, n)
	}
	if bans := m.Bans(); len(bans) != 0 {
		t.Fatalf("解禁后不该还有活跃封禁，实际 %+v", bans)
	}
}

func timePtr(t time.Time) *time.Time { return &t }

// banStepsForEntry 把"条目的到期时刻"翻译成 triggerBan 要的阶梯表。
//
// 它必须是**单元素**的：多一个元素就等于开了升级，而升级正是"同一个条目封出
// 两种时长"的来源（见下一个用例）。
func TestBanStepsForEntry(t *testing.T) {
	now := time.Now()

	cases := []struct {
		name string
		exp  *time.Time
		want int64
	}{
		{"永久条目 → 永久封（0 就是阶梯里的永久）", nil, 0},
		{"还有 30 分钟 → 封 30 分钟", timePtr(now.Add(30 * time.Minute)), 1800},
		{"还有 1 天 → 封 1 天", timePtr(now.Add(24 * time.Hour)), 86400},
	}
	for _, tc := range cases {
		got := banStepsForEntry(tc.exp, now)
		if len(got) != 1 {
			t.Errorf("%s：应当只有一个阶梯元素（不升级），实际 %v", tc.name, got)
			continue
		}
		// 允许几秒误差：剩余期是拿 now 与绝对到期时刻相减算出来的。
		if d := got[0] - tc.want; d > 2 || d < -2 {
			t.Errorf("%s：期望 %d 秒，实际 %d 秒", tc.name, tc.want, got[0])
		}
	}

	// 已过期（并发下快照刚加载完、条目正好在这一瞬间到期）：封 1 秒，
	// 也就是立刻解除。回落全局阶梯会封 10 分钟，那是实打实的误伤。
	got := banStepsForEntry(timePtr(now.Add(-time.Minute)), now)
	if len(got) != 1 || got[0] != 1 {
		t.Errorf("已过期条目应当落到 1 秒，实际 %v", got)
	}
}

// 地区条目命中后封多久 = **条目自己的剩余有效期**，且不受该地址封禁历史的影响。
//
// 曾经的写法是给 triggerBan 传 nil，让 nextDuration 回落全局阶梯。于是同一个
// 条目的命中会封出两种时长：阶梯本身 10 分钟起步，而"24 小时内再次触发"会把
// 序号顶到第二级、变成 1 小时。用户看到的就是"条目上明明选了有效期，一批地址
// 里有的封 10 分钟、有的封 1 小时，怎么都对不上那条设置"。
func TestGeoEntryBanDurationFollowsEntry(t *testing.T) {
	m := newTestManager(t)
	setPolicy(t, m, func(p *model.Policy) {
		p.AutoBanEnabled = true
		p.ObserveOnly = false
		// 与出厂默认一致：第一级 10 分钟、第二级 1 小时。
		p.BanDurations = "600,3600"
		p.EscalateWindowHours = 24
	})

	// 条目有效期取 30 分钟：与阶梯的两级都不相等，一旦回落阶梯就会被下面的
	// 断言抓住（600 或 3600，都不是 1800）。
	exp := time.Now().Add(30 * time.Minute)
	entry := &model.ACLEntry{
		Kind: model.KindBlack, Target: "CN", TargetType: model.TargetGeoCountry,
		Scope: model.ScopeAll, Source: model.SourceManual, ExpiresAt: &exp,
	}
	if err := m.store.UpsertACL(entry); err != nil {
		t.Fatal(err)
	}
	// 一条永久条目，用来验证"条目永久 ⇒ 封永久"这一侧。
	perm := &model.ACLEntry{
		Kind: model.KindBlack, Target: "US", TargetType: model.TargetGeoCountry,
		Scope: model.ScopeAll, Source: model.SourceManual,
	}
	if err := m.store.UpsertACL(perm); err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(); err != nil {
		t.Fatal(err)
	}

	addr := netip.MustParseAddr("203.0.113.77")
	target := addr.String() + "/32"

	// 给这个地址造一段"24 小时内已被封过一次"的历史，好让全局阶梯升到第二级。
	//
	// 用 released 而不是 active：active 会被 rebuildBans 装回内存，triggerBan
	// 见到"已在封禁中"就直接返回、什么都测不到；而 LastBanOfTarget 不看状态，
	// released 的记录一样会被 nextDuration 当成升级依据。
	if err := m.store.CreateBan(&model.BanRecord{
		Target: target, TargetType: model.TargetTypeOf(target), Scope: model.ScopeAll,
		Reason: "历史封禁", Source: model.SourceAuto, Status: model.BanReleased,
		HitCount: 1, BannedAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	hit := m.matchGeoLocked(m.geoBlack, &geoip.Info{Country: "CN", Found: true})
	if hit == nil {
		t.Fatal("应当命中刚写入的国家条目")
	}
	if hit.expiresAt == nil {
		t.Fatal("geoEntry 丢掉了条目的到期时刻 —— 封禁时长就没得可依了")
	}

	// 走真实接线（banGeoBlackHit），不是自己拼参数：这条用例要钉住的正是
	// "judge 那一步把条目有效期传下去"这件事。直接调 triggerBan 的话，
	// 有人把接线改回 nil，用例照样绿。
	m.banGeoBlackHit(addr, &geoip.Info{Country: "CN"}, "u", "", hit, time.Now())

	bans := m.Bans()
	if len(bans) != 1 {
		t.Fatalf("应当产生 1 条封禁，实际 %d 条", len(bans))
	}
	if bans[0].Permanent {
		t.Fatal("30 分钟的条目不该封成永久")
	}
	if got := bans[0].RemainingSec; got < 1740 || got > 1800 {
		t.Fatalf("封禁时长应当跟条目走（约 1800 秒），实际 %d 秒 —— "+
			"600 是阶梯第一级、3600 是按历史升级后的第二级，两者都说明没看条目", got)
	}

	// 条目永久 ⇒ 封永久。与地址黑名单条目一致：那种条目在内核里也是
	// "条目在就封着、条目删掉才放行"，没有第二种存续期。
	hitPerm := m.matchGeoLocked(m.geoBlack, &geoip.Info{Country: "US", Found: true})
	if hitPerm == nil {
		t.Fatal("应当命中永久国家条目")
	}
	m.banGeoBlackHit(netip.MustParseAddr("203.0.113.88"), &geoip.Info{Country: "US"},
		"u", "", hitPerm, time.Now())

	for _, b := range m.Bans() {
		if b.Target == "203.0.113.88/32" {
			if !b.Permanent {
				t.Fatalf("永久条目应当封永久，实际剩余 %d 秒", b.RemainingSec)
			}
			return
		}
	}
	t.Fatal("永久条目命中后没有产生封禁")
}

// 停用地区条目 = 立即不再拦 + 由它封掉的地址能按来源引用解禁。
//
// API 层"停用联动解禁"走的正是 ReleaseBansByRef(ref)（与删除同一个机制），
// 这里把两半都钉住：Refresh 之后停用条目不再出现在 geoBlack，按引用解禁恰好
// 解掉停用前产生的那一条封禁。
func TestDisabledGeoEntryStopsMatchingAndReleasesBans(t *testing.T) {
	m := newTestManager(t)

	if err := m.store.UpsertACL(&model.ACLEntry{
		Kind: model.KindBlack, Target: "CN", TargetType: model.TargetGeoCountry,
		Scope: model.ScopeAll, Source: model.SourceManual,
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(); err != nil {
		t.Fatal(err)
	}

	hit := m.matchGeoLocked(m.geoBlack, &geoip.Info{Country: "CN", Found: true})
	if hit == nil {
		t.Fatal("启用的条目应当命中")
	}
	ref := model.BanSourceRef(model.BanRefACL, hit.id)
	m.banGeoBlackHit(netip.MustParseAddr("203.0.113.77"), &geoip.Info{Country: "CN"},
		"u", "", hit, time.Now())
	if bans := m.Bans(); len(bans) != 1 {
		t.Fatalf("应当产生 1 条封禁，实际 %d 条", len(bans))
	}

	// 停用：落库 + 重载（与接口层开关做的事一致）
	entry, err := m.store.GetACL(hit.id)
	if err != nil {
		t.Fatal(err)
	}
	entry.Enabled = false
	if err := m.store.UpdateACL(entry); err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(); err != nil {
		t.Fatal(err)
	}

	if hit := m.matchGeoLocked(m.geoBlack, &geoip.Info{Country: "CN", Found: true}); hit != nil {
		t.Fatalf("停用的条目不该再命中：%+v", m.geoBlack)
	}

	// 停用前产生的封禁，按引用应当能一次性解掉（API 层开关调用的同一入口）。
	n, err := m.ReleaseBansByRef(ref, "tester", "名单条目已停用")
	if err != nil || n != 1 {
		t.Fatalf("应当解禁 1 条（err=%v），实际 %d 条", err, n)
	}
	if bans := m.Bans(); len(bans) != 0 {
		t.Fatalf("解禁后不该还有活跃封禁，实际 %+v", bans)
	}
}
