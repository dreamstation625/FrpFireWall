package guard

import (
	"testing"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/config"
	"github.com/dreamstation625/FrpFireWall/internal/model"
)

// 改保留期要立刻清一次，而不是等下一个 5 分钟清理周期。
//
// 用户刚把 30 改成 7，界面上那些更老的记录还挂着，他没法判断到底是没生效、
// 还是没到清理时间 —— 这两件事看起来一模一样。
func TestSetEventRetentionPurgesImmediately(t *testing.T) {
	m := newManagerWith(t, nil)

	add := func(age time.Duration) {
		t.Helper()
		if err := m.store.AddEvent(&model.Event{
			Category: model.EvtLoginBlocked,
			IP:       "203.0.113.1",
			Ts:       time.Now().Add(-age),
		}); err != nil {
			t.Fatal(err)
		}
	}
	total := func() int64 {
		t.Helper()
		p, err := m.store.ListEventsPage("", "", nil, 1, 100)
		if err != nil {
			t.Fatal(err)
		}
		return p.Total
	}

	add(40 * 24 * time.Hour)
	add(10 * 24 * time.Hour)
	add(time.Minute)

	if got := m.EventRetention(); got != config.DefaultEventRetentionDays {
		t.Fatalf("初始保留天数 = %d，期望 %d", got, config.DefaultEventRetentionDays)
	}

	// 默认 30 天：40 天前那条该走
	m.SetEventRetention(config.DefaultEventRetentionDays)
	if n := total(); n != 2 {
		t.Fatalf("按 30 天清理后剩 %d 条，期望 2", n)
	}

	// 改成 7 天：10 天前那条也要走
	m.SetEventRetention(7)
	if got := m.EventRetention(); got != 7 {
		t.Fatalf("保留天数 = %d，期望 7", got)
	}
	if n := total(); n != 1 {
		t.Fatalf("按 7 天清理后剩 %d 条，期望 1", n)
	}

	// 0 = 永久保留：此后不再自动清理
	m.SetEventRetention(0)
	add(400 * 24 * time.Hour)
	if got := m.EventRetention(); got != 0 {
		t.Fatalf("保留天数 = %d，期望 0（永久保留）", got)
	}
	if n := total(); n != 2 {
		t.Fatalf("保留期为 0 时不该清理，剩 %d 条，期望 2", n)
	}
}

// SetEventRetention 是导出方法，负数必须在入口就夹成 0。
//
// 不夹的后果很重：before 会算到"未来"去，PurgeEvents 的 ts < before 命中整张表，
// 一次手滑传个 -1 就把历史事件全删了。
func TestSetEventRetentionClampsNegative(t *testing.T) {
	m := newManagerWith(t, nil)

	if err := m.store.AddEvent(&model.Event{Category: model.EvtBan, IP: "198.51.100.9"}); err != nil {
		t.Fatal(err)
	}

	m.SetEventRetention(-1)

	if got := m.EventRetention(); got != 0 {
		t.Fatalf("负数应被夹成 0，得到 %d", got)
	}
	p, err := m.store.ListEventsPage("", "", nil, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if p.Total != 1 {
		t.Errorf("负保留期不该删除任何数据，剩 %d 条，期望 1", p.Total)
	}
}

// 启动时的生效值来自配置，不是写死的 30。
//
// 0 尤其要盯住：它表示永久保留，如果被当成"没配置"而回落默认值，
// 用户明确关掉的自动清理会在重启之后自己回来，然后开始删他的历史数据。
func TestEventRetentionStartsFromConfig(t *testing.T) {
	m := newManagerWith(t, func(c *config.Config) { c.Event.RetentionDays = 3 })
	if got := m.EventRetention(); got != 3 {
		t.Fatalf("启动后的保留天数 = %d，期望 3", got)
	}

	m0 := newManagerWith(t, func(c *config.Config) { c.Event.RetentionDays = 0 })
	if got := m0.EventRetention(); got != 0 {
		t.Fatalf("保留天数 = %d，期望 0（永久保留，不能被当成未配置）", got)
	}
}
