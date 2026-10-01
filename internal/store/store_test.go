package store

import (
	"testing"

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
