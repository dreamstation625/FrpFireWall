package store

import (
	"fmt"
	"testing"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/model"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("打开测试库失败：%v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// 停用的规则必须真的以 enabled=false 落库。
//
// 这条看着废话，但它挡的是一个**踩过的坑**：Enabled 曾经带 gorm 的
// `default:true` 标签，而 GORM 的规则是"带默认值的字段在 INSERT 时若是零值，
// 就从 SQL 里省掉、让数据库默认值生效"。布尔字段的零值恰好是 false，
// 两条规则叠起来的结果是：**写进去的 false 被丢掉，存下来变成 true**。
//
// 表现是"把规则停用、保存，它还是启用的"，库里也看不出任何痕迹
// （`Select("*")` 也绕不过去，那个判断在 selectColumns 之前）。
// 所以这条测试的意义是：谁要是哪天觉得应该给 Enabled 补个 default:true，
// 这里立刻会红。
func TestRateRuleDisabledIsPersisted(t *testing.T) {
	s := openTemp(t)

	if err := s.ReplaceRateRules([]model.RateRule{
		{Name: "停用的", Enabled: false, Ports: "443", PerSec: 5},
		{Name: "启用的", Enabled: true, Ports: "8443", PerSec: 5},
	}); err != nil {
		t.Fatal(err)
	}

	rows, err := s.RateRules()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range rows {
		got[r.Name] = r.Enabled
	}
	if got["停用的"] {
		t.Error("停用的规则存回来变成了启用 —— Enabled 又被加回 default 了？")
	}
	if !got["启用的"] {
		t.Error("启用的规则存回来变成停用了")
	}

	// 再确认一次库里存的原始值，避免是 GORM 读的时候做了手脚。
	var raw []struct {
		Name    string
		Enabled bool
	}
	if err := s.db.Raw("select name, enabled from rate_rules order by name").Scan(&raw).Error; err != nil {
		t.Fatal(err)
	}
	for _, r := range raw {
		want := r.Name == "启用的"
		if r.Enabled != want {
			t.Errorf("库里 %q 的 enabled = %v，期望 %v", r.Name, r.Enabled, want)
		}
	}
}

// 规则按 priority 升序返回 —— 顺序本身就是配置（第一条命中的生效）。
func TestRateRulesKeepOrder(t *testing.T) {
	s := openTemp(t)

	// 故意倒着传，验证顺序是按数组下标定的，不是按名字或 ID
	if err := s.ReplaceRateRules([]model.RateRule{
		{Name: "最先", Countries: "HK", PerSec: 5},
		{Name: "其次", Ports: "443", PerSec: 5},
		{Name: "最后", CIDRs: "203.0.113.0/24", PerSec: 5},
	}); err != nil {
		t.Fatal(err)
	}

	rows, err := s.RateRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("应当有 3 条，实际 %d 条", len(rows))
	}
	for i, want := range []string{"最先", "其次", "最后"} {
		if rows[i].Name != want {
			t.Errorf("第 %d 位应当是 %q，实际 %q", i, want, rows[i].Name)
		}
		if rows[i].Priority != i {
			t.Errorf("%q 的 priority 应当是 %d，实际 %d", want, i, rows[i].Priority)
		}
	}
}

// 策略和规则必须落在同一个事务里。
//
// 界面上它们是同一个"保存"按钮。分开写的话，规则写失败会留下
// "策略已经改了、规则还是旧的"这种半截状态，而用户看到的只是一句"保存失败"，
// 他并不知道策略其实已经生效了。
func TestSavePolicyWithRulesIsAtomic(t *testing.T) {
	s := openTemp(t)

	before, err := s.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	beforeThreshold := before.Threshold

	// 把规则表弄坏，让规则写入必然失败
	if err := s.db.Exec("drop table rate_rules").Error; err != nil {
		t.Fatal(err)
	}

	p := before
	p.Threshold = beforeThreshold + 111
	err = s.SavePolicyWithRules(p, []model.RateRule{{Name: "写不进去", Countries: "HK", PerSec: 5}})
	if err == nil {
		t.Fatal("规则表都没了，保存应当报错")
	}

	after, err := s.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if after.Threshold != beforeThreshold {
		t.Errorf("规则写入失败时策略不该被写进去（事务没回滚）：阈值 %d → %d",
			beforeThreshold, after.Threshold)
	}
}

// 不带规则的保存路径不能被顺手改坏：老客户端、脚本还在用它。
func TestSavePolicyKeepsRateRules(t *testing.T) {
	s := openTemp(t)

	if err := s.ReplaceRateRules([]model.RateRule{{Name: "留着", Countries: "HK", PerSec: 5}}); err != nil {
		t.Fatal(err)
	}

	p, err := s.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	p.Threshold = 42
	if err := s.SavePolicy(p); err != nil {
		t.Fatal(err)
	}

	rows, err := s.RateRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Name != "留着" {
		t.Errorf("保存策略不该动到细分规则，实际 %+v", rows)
	}
}

// c_id_rs 那个坑：GORM 的命名策略会把 CIDRs 拆成 C + ID + Rs，
// 不加 column 标签的话列名就是 c_id_rs，写 raw SQL 的人一定会踩。
func TestRateRuleColumnNames(t *testing.T) {
	s := openTemp(t)

	var cols []struct{ Name string }
	if err := s.db.Raw("pragma table_info(rate_rules)").Scan(&cols).Error; err != nil {
		t.Fatal(err)
	}
	has := map[string]bool{}
	for _, c := range cols {
		has[c.Name] = true
	}
	for _, want := range []string{"cidrs", "ports", "per_sec", "ban_durations", "window_seconds"} {
		if !has[want] {
			t.Errorf("rate_rules 缺少列 %q（实际列：%v）", want, has)
		}
	}
	if has["c_id_rs"] {
		t.Error("CIDRs 又被命名策略拆成了 c_id_rs，column 标签丢了")
	}
}

// 事件列表的页码分页。
//
// 盯的是「翻页不重不漏」：offset 算错（少减 1、拿 page 当 offset、size 传错）
// 的表现是第二页重复第一页的尾条或漏掉一条，一页一页翻不容易看出来，
// 只有把几页拼起来按 id 比对才会露馅。
func TestListEventsPage(t *testing.T) {
	s := openTemp(t)

	for i := 1; i <= 7; i++ {
		if err := s.AddEvent(&model.Event{
			Category: "login_blocked",
			IP:       fmt.Sprintf("203.0.113.%d", i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	// 另一个类别：用来验证筛选改变的是 total，而不是只筛当前页
	if err := s.AddEvent(&model.Event{Category: "ban", IP: "198.51.100.1"}); err != nil {
		t.Fatal(err)
	}

	pages := make([]*Page[model.Event], 0, 3)
	for page := 1; page <= 3; page++ {
		p, err := s.ListEventsPage("", "", nil, page, 3)
		if err != nil {
			t.Fatal(err)
		}
		pages = append(pages, p)
	}

	if pages[0].Total != 8 {
		t.Errorf("total = %d，期望 8（不筛选时是全表）", pages[0].Total)
	}
	if len(pages[0].Items) != 3 {
		t.Fatalf("第 1 页 %d 条，期望 3", len(pages[0].Items))
	}
	// id 倒序 = 最新在前，所以首条是最后写入的那条
	if got := pages[0].Items[0].IP; got != "198.51.100.1" {
		t.Errorf("首条应是最后写入的 198.51.100.1，得到 %q", got)
	}

	seen := map[uint]bool{}
	ids := make([]uint, 0, 8)
	for i, p := range pages {
		for _, e := range p.Items {
			if seen[e.ID] {
				t.Errorf("id %d 在第 %d 页重复出现 —— offset 算错了", e.ID, i+1)
			}
			seen[e.ID] = true
			ids = append(ids, e.ID)
		}
	}
	if len(ids) != 8 {
		t.Errorf("三页合计 %d 条，期望 8（不重不漏）", len(ids))
	}
	for i := 1; i < len(ids); i++ {
		if ids[i] >= ids[i-1] {
			t.Errorf("id 不是严格递减：%d 后面是 %d", ids[i-1], ids[i])
			break
		}
	}

	// 越界页：条目为空，但 total 必须照旧 —— 分页器要靠它算总页数，
	// 返回 0 会让页数变成 1 页、把用户直接弹回第一页。
	beyond, err := s.ListEventsPage("", "", nil, 9, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(beyond.Items) != 0 {
		t.Errorf("越界页返回了 %d 条，期望 0", len(beyond.Items))
	}
	if beyond.Items == nil {
		t.Error("越界页的 items 是 nil，序列化成 JSON 会变成 null")
	}
	if beyond.Total != 8 {
		t.Errorf("越界页 total = %d，期望仍是 8", beyond.Total)
	}

	// 筛选与分页组合
	filtered, err := s.ListEventsPage("ban", "", nil, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if filtered.Total != 1 || len(filtered.Items) != 1 {
		t.Errorf("按类别筛选得 total=%d len=%d，期望 1/1", filtered.Total, len(filtered.Items))
	}

	// 非法入参必须被夹住，而不是把整张表倒出来
	if big, err := s.ListEventsPage("", "", nil, 1, 100000); err != nil {
		t.Fatal(err)
	} else if len(big.Items) > 500 {
		t.Errorf("size 未被夹到上限：返回 %d 条", len(big.Items))
	}
	if zero, err := s.ListEventsPage("", "", nil, 0, 3); err != nil {
		t.Fatal(err)
	} else if len(zero.Items) != 3 {
		t.Errorf("page=0 应被当成第 1 页，得到 %d 条", len(zero.Items))
	}
}

// 事件清理只删除保留线之前的那部分。
//
// 用 31 / 29 天而不是恰好 30 天来构造数据：SQLite 里 time.Time 是存成
// datetime 文本的，边界上相等的那条会落到"删或留都对"的模糊地带，
// 断言它只会让这条测试变成随机红。这里只钉住明确的两侧。
func TestPurgeEventsRemovesOnlyExpired(t *testing.T) {
	s := openTemp(t)
	now := time.Now()

	for i, ts := range []time.Time{
		now.AddDate(0, 0, -31), // 超期，该删
		now.AddDate(0, 0, -29), // 未超期，该留
		now.Add(-time.Minute),  // 刚写入，该留
	} {
		if err := s.AddEvent(&model.Event{
			Category: model.EvtLoginBlocked,
			IP:       fmt.Sprintf("203.0.113.%d", i+1),
			Ts:       ts,
		}); err != nil {
			t.Fatal(err)
		}
	}

	n, err := s.PurgeEvents(now.AddDate(0, 0, -30))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("删除了 %d 条，期望 1 条", n)
	}

	left, err := s.ListEventsPage("", "", nil, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if left.Total != 2 {
		t.Fatalf("清理后剩 %d 条，期望 2 条", left.Total)
	}
	for _, e := range left.Items {
		if e.IP == "203.0.113.1" {
			t.Error("31 天前的那条没被清掉")
		}
	}
}

// 联动解禁只动"由这条来源封的"那几条，别的必须原样留着。
//
// 这一步错了的后果不对称：多解禁 = 该封的地址被放进来（还查不出原因，
// 因为界面上那条依据已经删了）；少解禁 = 用户以为删干净了、地址却还是进不来。
// 两个方向都要钉住。
func TestReleaseBansIsScopedToGivenIDs(t *testing.T) {
	s := openTemp(t)

	now := time.Now()
	mustCreate := func(target, ref string) *model.BanRecord {
		t.Helper()
		b := &model.BanRecord{
			Target: target, TargetType: model.TargetTypeOf(target),
			Scope: model.ScopeAll, Reason: "测试", Source: model.SourceGeoIP,
			SourceRef: ref, Status: model.BanActive, BannedAt: now,
		}
		if err := s.CreateBan(b); err != nil {
			t.Fatal(err)
		}
		return b
	}

	ref := model.BanSourceRef(model.BanRefACL, 12)
	mine := mustCreate("203.0.113.1/32", ref)
	mustCreate("203.0.113.2/32", ref)
	other := mustCreate("198.51.100.1/32", model.BanSourceRef(model.BanRefACL, 99))
	noRef := mustCreate("192.0.2.1/32", "")

	// 空 ids 直接返回，不发空 UPDATE（空 UPDATE 在 GORM 里会报
	// "WHERE conditions required"，把这个约束写死在这里）。
	if err := s.ReleaseBans(nil, "tester", model.BanReleased); err != nil {
		t.Fatalf("空 ids 不该报错：%v", err)
	}

	if err := s.ReleaseBans([]uint{mine.ID}, "tester", model.BanReleased); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetBan(mine.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.BanReleased || got.ReleasedBy != "tester" || got.ReleasedAt == nil {
		t.Errorf("被封禁记录没有被正确标记：%+v", got)
	}

	for _, id := range []uint{other.ID, noRef.ID} {
		b, err := s.GetBan(id)
		if err != nil {
			t.Fatal(err)
		}
		if b.Status != model.BanActive {
			t.Errorf("第 %d 条不该被解禁，实际状态 %q", id, b.Status)
		}
	}

	// 还留在同一来源上的那一条，也必须还是活跃的 —— 统计口径是
	// "这条来源上还有多少没解的"，少算一条会让调用方以为已经清干净了。
	left, err := s.CountActiveBansOfRef(ref)
	if err != nil {
		t.Fatal(err)
	}
	if left != 1 {
		t.Fatalf("同一来源上应还剩 1 条活跃封禁，实际 %d 条", left)
	}
}

// CountActiveBansOfRef 的口径：只数活跃的，且是精确匹配来源引用。
//
// 不存在（比如规则被删光了）时返回 0 而不是报错 —— 调用方拿它做的是
// "报个数给用户"，不是"据此决定要不要动数据"。
func TestCountActiveBansOfRef(t *testing.T) {
	s := openTemp(t)

	ref := model.BanSourceRef(model.BanRefRule, 0) // 拼不出来，是空串
	if ref != "" {
		t.Fatalf("ID 为 0 的引用应当是空串，实际 %q", ref)
	}

	now := time.Now()
	for _, b := range []*model.BanRecord{
		{Target: "203.0.113.1/32", Status: model.BanActive, SourceRef: "rule:abc", BannedAt: now},
		{Target: "203.0.113.2/32", Status: model.BanReleased, SourceRef: "rule:abc", BannedAt: now},
		{Target: "203.0.113.3/32", Status: model.BanActive, SourceRef: "acl:1", BannedAt: now},
	} {
		if err := s.CreateBan(b); err != nil {
			t.Fatal(err)
		}
	}

	n, err := s.CountActiveBansOfRef("rule:abc")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("应当只数活跃的那 1 条，实际 %d 条", n)
	}

	// 空引用不能把所有"没有来源"的封禁一网打尽，否则频次自动封禁会被
	// 误算到任何一次联动解禁里。
	empty, err := s.CountActiveBansOfRef("")
	if err != nil {
		t.Fatal(err)
	}
	if empty != 0 {
		t.Fatalf("空引用不该匹配到任何东西，实际 %d 条", empty)
	}
}
