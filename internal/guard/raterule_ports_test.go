package guard

import (
	"net/netip"
	"testing"

	"github.com/dreamstation625/FrpFireWall/internal/model"
)

func setupPortRule(t *testing.T, rule model.RateRule) *Manager {
	t.Helper()
	m := newTestManager(t)
	setPolicy(t, m, func(p *model.Policy) {
		p.AutoBanEnabled = true
		p.ObserveOnly = false
		p.WindowSeconds = 60
		p.Threshold = 9999
		p.RateLimitEnabled = false
		p.BanGranularity = "ip"
	})
	rule.Enabled = true
	if err := m.store.ReplaceRateRules([]model.RateRule{rule}); err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPortThresholdIncludesRateRejectedConnections(t *testing.T) {
	m := setupPortRule(t, model.RateRule{Name: "连接频控", Ports: "8443", PerSec: 1, Burst: 1, WindowSeconds: 60, Threshold: 3, BanDurations: "120"})
	addr := netip.MustParseAddr("203.0.113.7")
	connect := func() Verdict { return m.judge(addr, "user", model.EvtUserConn, "user-conn", "web", 8443) }
	if !connect().Allow {
		t.Fatal("首个连接应放行")
	}
	if v := connect(); v.Allow || v.Reason != "rate-limited" {
		t.Fatalf("第二次应仅限速: %+v", v)
	}
	if d := m.desired(); len(d.Blacklist) != 0 || len(d.RateLimits) != 0 {
		t.Fatal("限速不能预先写内核")
	}
	if v := connect(); v.Allow || v.Reason != "rate-exceeded" {
		t.Fatalf("限速拒绝也应累计并在第三次封禁: %+v", v)
	}
	d := m.desired()
	if len(d.Blacklist) != 1 || d.Blacklist[0] != "203.0.113.7/32" || len(d.RateLimits) != 0 {
		t.Fatalf("仅触发来源进入全端口封禁: %+v", d)
	}
	records, err := m.store.ActiveBans()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Scope != model.ScopeAll || records[0].SourceRef == "" {
		t.Fatalf("应保留默认范围和规则来源引用: %+v", records)
	}
	if _, err = m.ReleaseBansByRef(records[0].SourceRef, "test", "规则删除"); err != nil {
		t.Fatal(err)
	}
	if !connect().Allow {
		t.Fatal("规则联动解封后应清理窗口与令牌桶")
	}
}

func TestPortRuleCountersAreSeparatedAndUnbanResetsAll(t *testing.T) {
	m := setupPortRule(t, model.RateRule{Name: "端口计数", Ports: "8443,9443", WindowSeconds: 60, Threshold: 3, BanDurations: "120"})
	addr := netip.MustParseAddr("203.0.113.8")
	connect := func(port int) Verdict { return m.judge(addr, "user", model.EvtUserConn, "user-conn", "web", port) }
	for _, port := range []int{8443, 9443, 8443, 9443} {
		if !connect(port).Allow {
			t.Fatal("不同目的端口的计数不能合并")
		}
	}
	if connect(0).Reason != "ok" || connect(443).Reason != "ok" {
		t.Fatal("未知端口或不匹配端口不能扩大匹配")
	}
	if v := connect(8443); v.Reason != "rate-exceeded" {
		t.Fatalf("同一端口达到阈值应封禁: %+v", v)
	}
	if err := m.Unban(addr.String(), "test"); err != nil {
		t.Fatal(err)
	}
	if !connect(9443).Allow || !connect(8443).Allow {
		t.Fatal("解封需清理所有端口窗口")
	}
}

func TestPortDirectBlockWaitsForActualMatch(t *testing.T) {
	m := setupPortRule(t, model.RateRule{Name: "直接拦截", CIDRs: "203.0.113.0/24", Ports: "8443", Block: true})
	addr := netip.MustParseAddr("203.0.113.9")
	for _, c := range []struct {
		proxy string
		port  int
	}{{"web", 0}, {"web", 443}} {
		if v := m.judge(addr, "u", model.EvtUserConn, "user-conn", c.proxy, c.port); !v.Allow {
			t.Fatalf("非匹配连接应放行: %+v", v)
		}
	}
	if len(m.desired().Blacklist) != 0 {
		t.Fatal("规则保存和非匹配连接不能预写封禁")
	}
	if v := m.judge(addr, "u", model.EvtUserConn, "user-conn", "web", 8443); v.Reason != "rule-blocked" {
		t.Fatalf("匹配后应封禁: %+v", v)
	}
	if len(m.desired().Blacklist) != 1 {
		t.Fatal("触发后应生成内核封禁")
	}
}

func TestGlobalApplicationRateCountsTowardThreshold(t *testing.T) {
	m := newTestManager(t)
	setPolicy(t, m, func(p *model.Policy) {
		p.AutoBanEnabled = true
		p.ObserveOnly = false
		p.Threshold = 3
		p.WindowSeconds = 60
		p.RateLimitEnabled = true
		p.RateLimitPerSec = 1
		p.RateLimitBurst = 1
	})
	addr := netip.MustParseAddr("203.0.113.10")
	if !m.JudgeLogin(addr, "u", "").Allow {
		t.Fatal("首个连接应放行")
	}
	if v := m.JudgeLogin(addr, "u", ""); v.Reason != "rate-limited" {
		t.Fatalf("全局应在应用层限速: %+v", v)
	}
	if v := m.JudgeLogin(addr, "u", ""); v.Reason != "rate-exceeded" {
		t.Fatalf("全局限速不得遮蔽封禁阈值: %+v", v)
	}
}
