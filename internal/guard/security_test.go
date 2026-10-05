package guard

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/model"
)

func TestConcurrentBanHasOneDurableRecord(t *testing.T) {
	m := newTestManager(t)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			m.triggerBan(netip.MustParseAddr("203.0.113.9"), model.SourceAuto, "test", "", "", nil, []int64{600}, "")
		})
	}
	wg.Wait()
	rows, err := m.store.ActiveBans()
	if err != nil || len(rows) != 1 || len(m.Bans()) != 1 {
		t.Fatalf("封禁应只有一条记录，rows=%v err=%v", rows, err)
	}
}

func TestSourceReleaseAlsoRemovesHistoricalDuplicateRecords(t *testing.T) {
	m := newTestManager(t)
	for range 2 {
		if err := m.store.CreateBan(&model.BanRecord{Target: "203.0.113.9/32", Source: model.SourceRule, SourceRef: "rule:test", Status: model.BanActive, BannedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	// 即使重复记录未出现在内存 map 中，也必须解除，避免重启复活。
	if n, err := m.ReleaseBansByRef("rule:test", "admin", "停用规则"); err != nil || n != 2 {
		t.Fatalf("未解除全部历史行: %d %v", n, err)
	}
	if rows, err := m.store.ActiveBans(); err != nil || len(rows) != 0 {
		t.Fatalf("活跃行残留: %v %v", rows, err)
	}
}

func TestObserveKeepsManualBlocksAndAllowsAutomaticRules(t *testing.T) {
	m := newTestManager(t)
	m.policy.ObserveOnly = true
	m.policy.Threshold = 1
	m.black = []blockTarget{{Prefix: netip.MustParsePrefix("203.0.113.10/32"), Scope: model.ScopeAll}}
	if m.JudgeLogin(netip.MustParseAddr("203.0.113.10"), "", "").Allow {
		t.Fatal("人工黑名单应继续生效")
	}
	if !m.JudgeLogin(netip.MustParseAddr("203.0.113.11"), "", "").Allow {
		t.Fatal("观察模式应放行频次策略")
	}
	if len(m.Bans()) != 0 || len(m.desired().RateLimits) != 0 {
		t.Fatal("观察模式不应新增自动封禁或内核限速")
	}
	m.appRules = []appRule{{name: "direct", block: true}}
	if !m.JudgeLogin(netip.MustParseAddr("203.0.113.12"), "", "").Allow {
		t.Fatal("观察模式应放行直接拦截规则")
	}
}

func TestDisableAutoBanStillRejectsDirectRule(t *testing.T) {
	m := newTestManager(t)
	m.policy.AutoBanEnabled = false
	m.appRules = []appRule{{name: "direct", block: true}}
	if m.JudgeLogin(netip.MustParseAddr("203.0.113.13"), "", "").Allow {
		t.Fatal("直接拦截仍应拒绝本次连接")
	}
	rows, err := m.store.ActiveBans()
	if err != nil || len(rows) != 0 {
		t.Fatalf("不应创建持久记录: %v %v", rows, err)
	}
}

func TestRateLimitedHitsReachBanThreshold(t *testing.T) {
	m := newTestManager(t)
	m.appRules = []appRule{{name: "limit", perSec: 1, bucket: newTokenBucket(1, 1), window: time.Minute, threshold: 3, steps: []int64{600}}}
	a := netip.MustParseAddr("203.0.113.14")
	for range 3 {
		m.JudgeLogin(a, "", "")
	}
	if len(m.Bans()) != 1 {
		t.Fatal("被限速的连接也必须参与封禁阈值")
	}
}

func TestCIDRUnbanResetsMembersAndPreservesOtherWindows(t *testing.T) {
	m := newTestManager(t)
	now := time.Now()
	m.countWindow("r1", "203.0.113.4", now, time.Minute)
	m.countWindow("r2", "203.0.113.99", now, time.Minute)
	m.countWindow("r1", "203.0.114.4", now, time.Minute)
	m.mu.Lock()
	m.resetWindowsForLocked("203.0.113.0/24")
	m.mu.Unlock()
	if m.windowCount("r1", "203.0.113.4", now, time.Minute) != 0 || m.windowCount("r2", "203.0.113.99", now, time.Minute) != 0 {
		t.Fatal("未重置网段成员")
	}
	if m.windowCount("r1", "203.0.114.4", now, time.Minute) != 1 {
		t.Fatal("误清了其它网段")
	}
}

func TestUnbanDatabaseFailureKeepsMemory(t *testing.T) {
	m := newTestManager(t)
	b, err := m.BanManual("203.0.113.15", "test", "test", time.Minute, model.ScopeAll, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.store.Close(); err != nil {
		t.Fatal(err)
	}
	if m.UnbanByRecordID(b.ID, "test") == nil {
		t.Fatal("数据库失败应返回错误")
	}
	if m.Unban("203.0.113.15", "test") == nil || len(m.Bans()) != 1 {
		t.Fatal("数据库失败不应删掉内存封禁")
	}
}

func TestWhitelistCarvesSingleAddressFromCIDR(t *testing.T) {
	m := newTestManager(t)
	m.black = []blockTarget{{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Scope: model.ScopeAll}}
	m.white = []netip.Prefix{netip.MustParsePrefix("203.0.113.4/32")}
	d := m.desired()
	for _, x := range d.Blacklist {
		if netip.MustParsePrefix(x).Contains(netip.MustParseAddr("203.0.113.4")) {
			t.Fatal("白名单仍在内核黑名单中")
		}
	}
	for _, ip := range []string{"203.0.113.0", "203.0.113.3", "203.0.113.5", "203.0.113.255"} {
		found := false
		for _, x := range d.Blacklist {
			found = found || netip.MustParsePrefix(x).Contains(netip.MustParseAddr(ip))
		}
		if !found {
			t.Fatalf("错误放行相邻地址 %s", ip)
		}
	}
}

func TestACLExpiryIsCheckedWithoutRefresh(t *testing.T) {
	m := newTestManager(t)
	past := time.Now().Add(-time.Second)
	p := netip.MustParsePrefix("203.0.113.16/32")
	m.black = []blockTarget{{Prefix: p, ExpiresAt: &past, Scope: model.ScopeAll}}
	m.white = []netip.Prefix{p}
	m.whiteExpiry = map[netip.Prefix]time.Time{p: past}
	if m.Whitelisted(p.Addr()) || len(m.desired().Blacklist) != 0 {
		t.Fatal("到期名单仍生效")
	}
	if !m.JudgeLogin(p.Addr(), "", "").Allow {
		t.Fatal("到期黑名单应放行")
	}
}

func TestHighThresholdAndLongWindowRetention(t *testing.T) {
	m := newTestManager(t)
	m.policy.WindowSeconds = 86400
	now := time.Now().Add(-time.Hour)
	for range 5000 {
		m.countWindow("", "203.0.113.17", now, 24*time.Hour)
	}
	m.pruneWindows()
	if n := m.windowCount("", "203.0.113.17", time.Now(), 24*time.Hour); n != 5000 {
		t.Fatalf("计数被截断或窗口被提前清理: %d", n)
	}
}
