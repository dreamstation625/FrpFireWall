package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/model"
	"github.com/dreamstation625/FrpFireWall/internal/myip"
)

// echoServer 起一个"回显服务"，返回指定内容。
func echoServer(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// useEcho 把探测源换成本地的回显服务 —— 真去问公网服务既慢又依赖网络。
func (h *harness) useEcho(t *testing.T, body string) {
	t.Helper()
	h.srv.myip = myip.New(
		myip.WithSources([]myip.Source{{Name: "test", URL: echoServer(t, body)}}),
		myip.WithTTL(time.Minute),
	)
}

func TestPublicIPEndpointReturnsIPAndWhitelistState(t *testing.T) {
	h := newHarness(t)
	h.useEcho(t, "203.0.113.7\n")

	code, r := h.call(http.MethodGet, "/api/v1/system/public-ip", nil)
	if code != http.StatusOK {
		t.Fatalf("状态码 %d，错误 %s", code, r.Error)
	}
	d := h.data(r)
	if d["ip"] != "203.0.113.7" {
		t.Fatalf("ip 不对: %v", d["ip"])
	}
	if d["source"] != "test" {
		t.Fatalf("source 不对: %v", d["source"])
	}
	// 白名单是空的，此时必须明确回答"没放行"，否则界面上的提示弹不出来
	if d["whitelisted"] != false {
		t.Fatalf("空白名单下 whitelisted 应为 false，实际 %v", d["whitelisted"])
	}
}

// TestPublicIPWhitelistedByExactAndCIDR 精确条目与 CIDR 条目都要算"已放行"。
//
// 只看精确相等是不够的：实际配置里白名单常写整段（机房段、办公网），
// 一个"在段里但没单独列出来"的地址被判成未放行，界面就会反复弹提示。
func TestPublicIPWhitelistedByExactAndCIDR(t *testing.T) {
	cases := []struct{ target, typ string }{
		{"203.0.113.7", "ipv4"},
		{"203.0.113.0/24", "cidr4"},
	}
	for _, c := range cases {
		h := newHarness(t)
		h.useEcho(t, "203.0.113.7\n")

		if err := h.srv.store.UpsertACL(&model.ACLEntry{
			Kind:       model.KindWhite,
			Target:     c.target,
			TargetType: c.typ,
			Scope:      model.ScopeAll,
			Source:     model.SourceManual,
			Enabled:    true,
		}); err != nil {
			t.Fatalf("写白名单失败: %v", err)
		}
		// 名单判定走的是 guard 的内存副本，改完库必须让它重新装载
		if err := h.srv.guard.Refresh(); err != nil {
			t.Fatalf("Refresh 失败: %v", err)
		}

		_, r := h.call(http.MethodGet, "/api/v1/system/public-ip", nil)
		d := h.data(r)
		if d["whitelisted"] != true {
			t.Fatalf("%s 应被判为已放行，实际 %v（%s）", c.target, d["whitelisted"], r.Error)
		}
	}
}

// TestPublicIPDisabledEntryDoesNotCount 停用的白名单条目不算放行。
func TestPublicIPDisabledEntryDoesNotCount(t *testing.T) {
	h := newHarness(t)
	h.useEcho(t, "203.0.113.7\n")

	// 停用只能"先建后改"：ACLEntry.Enabled 带 default:true，直接插入 false
	// 会被 GORM 当零值省略、落库成 true（模型注释里记着这个坑）。
	e := &model.ACLEntry{
		Kind:       model.KindWhite,
		Target:     "203.0.113.7",
		TargetType: "ipv4",
		Scope:      model.ScopeAll,
		Source:     model.SourceManual,
		Enabled:    true,
	}
	if err := h.srv.store.UpsertACL(e); err != nil {
		t.Fatalf("写白名单失败: %v", err)
	}
	e.Enabled = false
	if err := h.srv.store.UpdateACL(e); err != nil {
		t.Fatalf("停用失败: %v", err)
	}
	if err := h.srv.guard.Refresh(); err != nil {
		t.Fatalf("Refresh 失败: %v", err)
	}

	_, r := h.call(http.MethodGet, "/api/v1/system/public-ip", nil)
	if d := h.data(r); d["whitelisted"] != false {
		t.Fatalf("停用条目不该算放行，实际 %v", d["whitelisted"])
	}
}

// TestPublicIPFailureIsNotAnError 探测不到时接口仍要 200，只是 ip 为空。
func TestPublicIPFailureIsNotAnError(t *testing.T) {
	h := newHarness(t)
	h.useEcho(t, "这里没有地址")

	code, r := h.call(http.MethodGet, "/api/v1/system/public-ip", nil)
	if code != http.StatusOK {
		t.Fatalf("探测失败不该让整个请求失败: %d %s", code, r.Error)
	}
	d := h.data(r)
	if d["ip"] != "" {
		t.Fatalf("失败时 ip 应为空，实际 %v", d["ip"])
	}
	if d["error"] == "" || d["error"] == nil {
		t.Fatal("失败时必须带原因，界面要显示它")
	}
}
