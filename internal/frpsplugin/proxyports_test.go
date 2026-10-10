package frpsplugin

import (
	"testing"

	"github.com/dreamstation625/FrpFireWall/internal/model"
)

func registerTCP(t *testing.T, s *Server, proxy, session string, port int) {
	t.Helper()
	r := pluginCall(t, s, opNewProxy, newProxyContent{
		User: userInfo{User: "user", RunID: session}, ProxyName: proxy, ProxyType: "tcp", RemotePort: port,
	})
	if r.Reject || !r.Unchange {
		t.Fatalf("端口元数据回调不应拦截或改变代理配置: %+v", r)
	}
}

func portUserConn(proxy, session, remote string) newUserConnContent {
	c := userConn(proxy, remote)
	c.User.RunID = session
	return c
}

func TestProxyPortConditionsThroughPlugin(t *testing.T) {
	for _, tc := range []struct {
		name, proxy, ports string
	}{
		{"只有端口", "", "25666"},
		{"只有代理名", "web-a", ""},
		{"端口与代理名同时匹配", "web-a", "25666"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, st := proxyRuleServer(t, false, true, false)
			rule := model.RateRule{Name: tc.name, Enabled: true, ProxyName: tc.proxy, Ports: tc.ports, CIDRs: "203.0.113.0/24", Block: true}
			if err := st.ReplaceRateRules([]model.RateRule{rule}); err != nil {
				t.Fatal(err)
			}
			if err := s.mgr.Refresh(); err != nil {
				t.Fatal(err)
			}
			registerTCP(t, s, "web-a", "right", 25666)
			registerTCP(t, s, "web-a", "wrong-port", 25667)
			otherPort := 25666
			if tc.proxy == "" {
				otherPort = 25667
			}
			registerTCP(t, s, "web-b", "right", otherPort)
			if pluginCall(t, s, opNewUserConn, portUserConn("web-b", "right", "203.0.113.7:40000")).Reject {
				t.Fatal("不同代理或不匹配端口不应命中")
			}
			if tc.ports != "" {
				for _, session := range []string{"wrong-port", "unknown"} {
					if pluginCall(t, s, opNewUserConn, portUserConn("web-a", session, "203.0.113.7:25666")).Reject {
						t.Fatal("未知或不匹配的目的端口不能借来源端口命中规则")
					}
				}
			}
			if pluginCall(t, s, opNewUserConn, portUserConn("web-a", "right", "198.51.100.7:40000")).Reject {
				t.Fatal("来源条件也必须同时命中")
			}
			records, err := st.ActiveBans()
			if err != nil || len(records) != 0 {
				t.Fatalf("实际匹配前不能新增封禁: %v %v", records, err)
			}
			if !pluginCall(t, s, opNewUserConn, portUserConn("web-a", "right", "203.0.113.7:40001")).Reject {
				t.Fatal("完整匹配应触发直接拦截")
			}
			records, err = st.ActiveBans()
			if err != nil || len(records) != 1 || records[0].Scope != model.ScopeAll {
				t.Fatalf("触发后应保持全端口自动封禁: %v %v", records, err)
			}
		})
	}
}

func TestFixedTCPPortFrequencyThroughPlugin(t *testing.T) {
	s, st := proxyRuleServer(t, false, true, false)
	rule := model.RateRule{Name: "端口频控", Enabled: true, Ports: "25666", PerSec: 1, Burst: 1, WindowSeconds: 60, Threshold: 3, BanDurations: "120"}
	if err := st.ReplaceRateRules([]model.RateRule{rule}); err != nil {
		t.Fatal(err)
	}
	if err := s.mgr.Refresh(); err != nil {
		t.Fatal(err)
	}
	registerTCP(t, s, "web-a", "right", 25666)
	registerTCP(t, s, "web-b", "right", 25667)
	for i := 0; i < 5; i++ {
		if pluginCall(t, s, opNewUserConn, portUserConn("web-b", "right", "203.0.113.8:25666")).Reject {
			t.Fatal("不同目的端口的连接不应消耗规则额度")
		}
	}
	for i := 0; i < 3; i++ {
		r := pluginCall(t, s, opNewUserConn, portUserConn("web-a", "right", "203.0.113.8:40000"))
		if r.Reject != (i > 0) {
			t.Fatalf("第 %d 次应先放行再限速再封禁: %+v", i+1, r)
		}
		records, err := st.ActiveBans()
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		if i == 2 {
			want = 1
		}
		if len(records) != want {
			t.Fatalf("第 %d 次活跃封禁应为 %d 条，实际 %v", i+1, want, records)
		}
	}
}

func TestProxyPortLifecycleThroughPlugin(t *testing.T) {
	s, _ := proxyRuleServer(t, false, true, false)
	registerTCP(t, s, "web-a", "old", 25666)
	registerTCP(t, s, "web-a", "new", 25667)
	pluginCall(t, s, opCloseProxy, closeProxyContent{User: userInfo{User: "user", RunID: "old"}, ProxyName: "web-a"})
	if s.mgr.ResolveProxyPort("user", "new", "web-a", "tcp") != 25667 {
		t.Fatal("旧会话的关闭不能删除新会话的映射")
	}
	if s.mgr.ResolveProxyPort("user", "old", "web-a", "tcp") != 0 {
		t.Fatal("关闭后不应继续匹配端口")
	}
	if s.mgr.ResolveProxyPort("other-user", "new", "web-a", "tcp") != 0 || s.mgr.ResolveProxyPort("user", "new", "web-a", "https") != 0 {
		t.Fatal("不同用户或类型不能借用端口映射")
	}
	registerTCP(t, s, "web-a", "new", 25668)
	if s.mgr.ResolveProxyPort("user", "new", "web-a", "tcp") != 0 {
		t.Fatal("冲突申报不能覆盖原映射后错误匹配")
	}
	for _, c := range []newProxyContent{
		{ProxyName: "random", ProxyType: "tcp"},
		{ProxyName: "https", ProxyType: "https", RemotePort: 443},
		{ProxyName: "group", ProxyType: "tcp", RemotePort: 25666, Group: "shared"},
	} {
		c.User = userInfo{User: "user", RunID: "new"}
		pluginCall(t, s, opNewProxy, c)
		if s.mgr.ResolveProxyPort("user", "new", c.ProxyName, c.ProxyType) != 0 {
			t.Fatal("不可靠的端口不能用于匹配")
		}
	}
	if len(s.mgr.ProxyPortMappings()) != 4 {
		t.Fatal("映射与不支持的原因应当可查询")
	}
	fresh, _ := proxyRuleServer(t, false, true, false)
	if len(fresh.mgr.ProxyPortMappings()) != 0 {
		t.Fatal("重启不能复用旧会话的端口快照")
	}
}
