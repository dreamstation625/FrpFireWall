package guard

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/dreamstation625/FrpFireWall/internal/geoip"
	"github.com/dreamstation625/FrpFireWall/internal/model"
)

func TestProxyPortAndOtherConditions(t *testing.T) {
	rules, skipped := compileRules([]model.RateRule{{Name: "地区端口代理组合", Enabled: true, Countries: "HK", CIDRs: "203.0.113.0/24", Ports: "25666-25668", ProxyName: "web", PerSec: 5}})
	if len(skipped) != 0 || len(rules) != 1 {
		t.Fatalf("无法编译组合规则: %v", skipped)
	}
	for _, tc := range []struct {
		name, ip, country, proxy string
		port                     int
		want                     bool
	}{
		{"全部匹配", "203.0.113.7", "HK", "web", 25666, true},
		{"区间端口", "203.0.113.7", "HK", "web", 25668, true},
		{"地区不同", "203.0.113.7", "US", "web", 25666, false},
		{"来源不同", "198.51.100.7", "HK", "web", 25666, false},
		{"代理不同", "203.0.113.7", "HK", "other", 25666, false},
		{"端口不同", "203.0.113.7", "HK", "web", 25669, false},
		{"端口未知", "203.0.113.7", "HK", "web", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := rules[0].match(netip.MustParseAddr(tc.ip), &geoip.Info{Country: tc.country}, tc.proxy, tc.port); got != tc.want {
				t.Fatalf("组合匹配=%v，期望%v", got, tc.want)
			}
		})
	}
}

func TestProxyPortMappingBounded(t *testing.T) {
	m := newTestManager(t)
	if err := m.RegisterProxyPort("u", "", "web", "tcp", 25666, ""); err == nil {
		t.Fatal("缺少会话不能建立映射")
	}
	for i := 0; i < maxProxyPortMappings; i++ {
		if err := m.RegisterProxyPort("u", "session", fmt.Sprint(i), "tcp", 25666, ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.RegisterProxyPort("u", "session", "overflow", "tcp", 25666, ""); err == nil {
		t.Fatal("注册失败的代理也不能使映射无限增长")
	}
	if got := m.ResolveProxyPort("u", "session", "0", "tcp"); got != 25666 {
		t.Fatal("容量上限不应挤掉已有映射")
	}
	m.RemoveProxyPort("u", "session", "0")
	if err := m.RegisterProxyPort("u", "session", "overflow", "tcp", 25666, ""); err != nil {
		t.Fatal("关闭后应释放映射容量")
	}
}

func TestProxyPortMappingConcurrentLifecycle(t *testing.T) {
	m := newTestManager(t)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			session := fmt.Sprint(id)
			for n := 0; n < 20; n++ {
				if err := m.RegisterProxyPort("u", session, "shared-name", "tcp", 25000+id, ""); err != nil {
					t.Error(err)
					return
				}
				if got := m.ResolveProxyPort("u", session, "shared-name", "tcp"); got != 25000+id {
					t.Errorf("会话 %s 读取了错误端口 %d", session, got)
				}
				_ = m.ProxyPortMappings()
				m.RemoveProxyPort("u", session, "shared-name")
			}
		}(i)
	}
	wg.Wait()
	if len(m.ProxyPortMappings()) != 0 {
		t.Fatal("关闭后应无遗留映射")
	}
}
