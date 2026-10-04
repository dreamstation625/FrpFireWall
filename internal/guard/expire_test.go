package guard

import (
	"testing"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/model"
)

// 造一条封禁记录直接落库，不进内存。
//
// 这正是"程序重启后 rebuildBans 读到它"的形状：库里有、内存里还没有。
func seedBan(t *testing.T, m *Manager, target string, expiresAt *time.Time) {
	t.Helper()
	if err := m.store.CreateBan(&model.BanRecord{
		Target:    target,
		Reason:    "测试数据",
		Source:    model.SourceAuto,
		Status:    model.BanActive,
		BannedAt:  time.Now().Add(-2 * time.Hour),
		ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatalf("造测试数据失败：%v", err)
	}
}

// 重启恢复时，已到期的封禁不该进内存 —— 更不该被写回内核规则。
//
// 这是"内核会不会自动解封"这条链的第一环：内存里的封禁是内核规则的唯一来源
// （desired() 从 m.bans 构建），它们进不来，随后的全量重建就不会再把它们写下去。
func TestRebuildBansSkipsExpiredRows(t *testing.T) {
	m := newTestManager(t)

	past := time.Now().Add(-time.Minute)
	future := time.Now().Add(time.Hour)
	seedBan(t, m, "203.0.113.66", &past)   // 停机期间就到期了
	seedBan(t, m, "203.0.113.67", &future) // 停机期间还活着
	seedBan(t, m, "203.0.113.68", nil)     // 永久封禁

	if err := m.rebuildBans(); err != nil {
		t.Fatalf("恢复封禁失败：%v", err)
	}

	bans := m.Bans()
	if len(bans) != 2 {
		t.Fatalf("应当只恢复 2 条（未到期 + 永久），实际 %d 条：%+v", len(bans), bans)
	}
	for _, b := range bans {
		if b.Target == "203.0.113.66" {
			t.Fatal("已到期的封禁被恢复进内存了 —— 下一轮 Reconcile 会把它当成活跃规则重新写进内核")
		}
	}
}

// 程序没运行的那段时间里到期的封禁，库里的行会一直挂着 status=active。
//
// 它们不会进内存（rebuildBans 会跳过），而 expireBans 早年在内存里找不到任何
// 到期项就直接 return，压根走不到落库那一步 —— 于是这些行永远卡在 active：
// 封禁记录页一直显示「封禁中」，而内核里其实早已没有对应规则，
// 变成"界面说封着、实际没封"。
func TestExpireBansRetiresRowsMissedByRebuild(t *testing.T) {
	m := newTestManager(t)

	past := time.Now().Add(-time.Minute)
	seedBan(t, m, "203.0.113.66", &past)

	// 前置条件：只落库、不进内存（等价于重启后那批被跳过的行）。
	if bans := m.Bans(); len(bans) != 0 {
		t.Fatalf("前置条件不成立：内存里不该有封禁，实际 %+v", bans)
	}

	m.expireBans()

	got, err := m.store.FindActiveBan("203.0.113.66")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("库里仍留着 active 的过期封禁（expires=%v）："+
			"封禁记录页会一直显示「封禁中」，而内核里早已没有对应规则", got.ExpiresAt)
	}

	row, err := m.store.LastBanOfTarget("203.0.113.66")
	if err != nil || row == nil {
		t.Fatalf("查封禁记录失败：%v", err)
	}
	if row.Status != model.BanExpired {
		t.Fatalf("状态应为 %s，实际 %s", model.BanExpired, row.Status)
	}
	if row.ReleasedAt == nil || row.ReleasedBy != "system" {
		t.Fatalf("应当记下解封时刻与执行者，实际 released_at=%v released_by=%q",
			row.ReleasedAt, row.ReleasedBy)
	}
}

// 顺带确认不会误伤：未到期与永久的封禁必须原样留着。
func TestExpireBansKeepsLiveRows(t *testing.T) {
	m := newTestManager(t)

	future := time.Now().Add(time.Hour)
	seedBan(t, m, "203.0.113.67", &future)
	seedBan(t, m, "203.0.113.68", nil)

	m.expireBans()

	for _, target := range []string{"203.0.113.67", "203.0.113.68"} {
		got, err := m.store.FindActiveBan(target)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil {
			t.Fatalf("%s 不该被封禁清理掉", target)
		}
	}
}
