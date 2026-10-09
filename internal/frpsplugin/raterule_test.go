package frpsplugin

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dreamstation625/FrpFireWall/internal/config"
	"github.com/dreamstation625/FrpFireWall/internal/guard"
	"github.com/dreamstation625/FrpFireWall/internal/model"
	"github.com/dreamstation625/FrpFireWall/internal/store"
)

// 用实际插件 JSON、真实 SQLite 与判定引擎验证代理名的传递和计数，不写系统防火墙。
func proxyRuleServer(t *testing.T, observe, autoBan, block bool) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	p, err := st.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	p.ObserveOnly = observe
	p.AutoBanEnabled = autoBan
	p.Threshold = 9999
	p.WindowSeconds = 60
	p.RateLimitEnabled = false
	p.BanGranularity = "ip"
	if err = st.SavePolicy(p); err != nil {
		t.Fatal(err)
	}
	rules := []model.RateRule{}
	for _, name := range []string{"web-a", "web-b"} {
		r := model.RateRule{Name: name, Enabled: true, ProxyName: name, Block: block}
		if !block {
			r.PerSec = 1
			r.Burst = 1
			r.WindowSeconds = 60
			r.Threshold = 3
			r.BanDurations = "120"
		}
		rules = append(rules, r)
	}
	if err = st.ReplaceRateRules(rules); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.Default()
	cfg.Guard.Enabled = false
	mgr := guard.New(cfg, st, nil, nil, log)
	if err = mgr.Refresh(); err != nil {
		t.Fatal(err)
	}
	return New("127.0.0.1:9100", "/frps/handler", mgr, log, func() bool { return false }), st
}

func pluginCall(t *testing.T, s *Server, op string, content any) pluginResponse {
	t.Helper()
	b, err := json.Marshal(map[string]any{"version": "0.1.0", "op": op, "content": content})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/frps/handler?op="+op, bytes.NewReader(b))
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handle(w, req)
	if w.Code != 200 {
		t.Fatalf("插件 HTTP 返回 %d: %s", w.Code, w.Body.String())
	}
	var resp pluginResponse
	if err = json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(resp.RejectReason, "插件异常") {
		t.Fatalf("插件内部异常: %s", resp.RejectReason)
	}
	return resp
}

func userConn(proxy, remote string) newUserConnContent {
	return newUserConnContent{ProxyName: proxy, ProxyType: "tcp", RemoteAddr: remote, User: userInfo{User: "user"}}
}

func TestProxyFrequencyThroughPlugin(t *testing.T) {
	s, st := proxyRuleServer(t, false, true, false)
	for i := 0; i < 4; i++ {
		if pluginCall(t, s, opLogin, loginContent{User: "user", ClientAddress: "203.0.113.7:40000"}).Reject {
			t.Fatal("Login 无代理名，不能计入代理规则窗口")
		}
	}
	for _, name := range []string{"other", "web-a", "web-b"} {
		if pluginCall(t, s, opNewUserConn, userConn(name, "203.0.113.7:40001")).Reject {
			t.Fatalf("%s 第一次应放行", name)
		}
	}
	if pluginCall(t, s, opNewUserConn, userConn("web-a", "198.51.100.9:40001")).Reject {
		t.Fatal("同一代理的不同来源 IP 需要独立计数")
	}
	if !pluginCall(t, s, opNewUserConn, userConn("web-a", "203.0.113.7:40002")).Reject {
		t.Fatal("来源端口改变不能绕过按来源 IP 的限速")
	}
	records, err := st.ActiveBans()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatal("限速拒绝还不能产生持久封禁")
	}
	if !pluginCall(t, s, opNewUserConn, userConn("web-a", "203.0.113.7:40003")).Reject {
		t.Fatal("限速拒绝必须计数并触发封禁")
	}
	records, err = st.ActiveBans()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Scope != model.ScopeAll || records[0].SourceRef == "" {
		t.Fatalf("应产生一条带规则来源的全端口封禁: %+v", records)
	}
	if !pluginCall(t, s, opNewUserConn, userConn("web-b", "203.0.113.7:40004")).Reject {
		t.Fatal("已触发全端口封禁后其它代理也应拦截")
	}
	if _, err = s.mgr.ReleaseBansByRef(records[0].SourceRef, "test", "规则已移除"); err != nil {
		t.Fatal(err)
	}
	if pluginCall(t, s, opNewUserConn, userConn("web-a", "203.0.113.7:40005")).Reject {
		t.Fatal("解封后需要清理窗口和令牌桶")
	}
}

func TestProxyRuleObserveAndAutoBanSwitches(t *testing.T) {
	for _, tc := range []struct {
		name             string
		observe, autoBan bool
	}{{"观察模式", true, true}, {"关闭自动封禁", false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			s, st := proxyRuleServer(t, tc.observe, tc.autoBan, false)
			for i := 0; i < 3; i++ {
				r := pluginCall(t, s, opNewUserConn, userConn("web-a", "203.0.113.8:40000"))
				if r.Reject != (i > 0 && !tc.observe) {
					t.Fatalf("第 %d 次响应不符合开关配置: %+v", i+1, r)
				}
			}
			records, err := st.ActiveBans()
			if err != nil {
				t.Fatal(err)
			}
			if len(records) != 0 {
				t.Fatal("观察或关闭自动封禁不能新增持久封禁")
			}
		})
	}
}

func TestProxyDirectBlockThroughPlugin(t *testing.T) {
	s, st := proxyRuleServer(t, false, true, true)
	if pluginCall(t, s, opNewUserConn, userConn("other", "203.0.113.9:40000")).Reject {
		t.Fatal("其它代理不命中直接拦截规则")
	}
	records, err := st.ActiveBans()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatal("直接拦截不能在实际匹配前持久化封禁")
	}
	if !pluginCall(t, s, opNewUserConn, userConn("web-a", "203.0.113.9:40001")).Reject {
		t.Fatal("代理名命中后应直接拦截")
	}
	records, err = st.ActiveBans()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Scope != model.ScopeAll {
		t.Fatalf("首次匹配后应产生来源的全端口封禁: %+v", records)
	}
}
