package api

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/config"
)

func TestConcurrentLoginCannotExceedFailureBudget(t *testing.T) {
	h := newHarness(t)
	h.srv.authMu.Lock()
	router := h.srv.Routes()
	var wg sync.WaitGroup
	codes := make(chan int, 24)
	for range 24 {
		wg.Go(func() {
			req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"wrong","password":"wrong"}`))
			req.RemoteAddr = "203.0.113.8:1234"
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			codes <- w.Code
		})
	}
	time.Sleep(50 * time.Millisecond)
	h.srv.authMu.Unlock()
	wg.Wait()
	close(codes)
	failed, blocked := 0, 0
	for c := range codes {
		if c == 401 {
			failed++
		} else if c == 429 {
			blocked++
		} else {
			t.Fatalf("非预期响应: %d", c)
		}
	}
	if failed != loginMaxFailures || blocked != 24-loginMaxFailures {
		t.Fatalf("并发绕过失败预算: failed=%d blocked=%d", failed, blocked)
	}
}

type slowUploadReader struct {
	io.Reader
	delayed bool
}

func (r *slowUploadReader) Read(p []byte) (int, error) {
	if !r.delayed {
		r.delayed = true
		time.Sleep(150 * time.Millisecond)
	}
	return r.Reader.Read(p)
}

func TestGeoUploadExtendsNativeServerDeadlines(t *testing.T) {
	h := newHarness(t)
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	_ = form.WriteField("name", "GeoLite2-Country.mmdb")
	f, err := form.CreateFormFile("file", "invalid.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("invalid database"))
	_ = form.Close()
	ts := httptest.NewUnstartedServer(h.srv.Routes())
	ts.Config.ReadTimeout = 50 * time.Millisecond
	ts.Config.WriteTimeout = 50 * time.Millisecond
	ts.Start()
	defer ts.Close()
	req, err := http.NewRequest("POST", ts.URL+"/api/v1/geoip/upload", &slowUploadReader{Reader: bytes.NewReader(body.Bytes())})
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", form.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+h.token)
	r, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("属地传输被普通截止时间中断: %v", err)
	}
	defer r.Body.Close()
	if r.StatusCode != 400 {
		t.Fatalf("应完成读取并因数据库格式错误返回 400，得到 %d", r.StatusCode)
	}
	data, err := io.ReadAll(r.Body)
	if err != nil || !bytes.Contains(data, []byte("mmdb")) {
		t.Fatalf("未完成格式校验: %s %v", data, err)
	}
}

func TestSpoofedForwardedHeadersCannotAvoidLoginLimit(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 9; i++ {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"wrong","password":"wrong"}`))
		req.RemoteAddr = "203.0.113.8:1234"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "198.51.100."+strconv.Itoa(i+1))
		w := httptest.NewRecorder()
		h.srv.Routes().ServeHTTP(w, req)
		want := 401
		if i == 8 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("第 %d 次得到 %d，期望 %d", i, w.Code, want)
		}
	}
}

func TestBodyLimitKnownAndChunked(t *testing.T) {
	h := newHarness(t)
	for _, length := range []int64{-1, 2 << 20} {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"`+strings.Repeat("x", 2<<20)+`","password":"x"}`))
		req.ContentLength = length
		w := httptest.NewRecorder()
		h.srv.Routes().ServeHTTP(w, req)
		if w.Code != 413 {
			t.Fatalf("超大请求应返回 413，实际 %d", w.Code)
		}
	}
}

func TestPasswordAndLogoutRevokeTokensAcrossServerInstances(t *testing.T) {
	h := newHarness(t)
	hash, err := config.HashPassword("old-password")
	if err != nil {
		t.Fatal(err)
	}
	h.srv.passHash = hash
	code, r := h.call("POST", "/api/v1/auth/password", map[string]string{"old_password": "old-password", "new_password": "new-password"})
	if code != 200 {
		t.Fatalf("改密失败 %d %s", code, r.Error)
	}
	if _, err = h.srv.parseToken(h.token); err == nil {
		t.Fatal("旧 token 未撤销")
	}
	h.token, _, err = h.srv.issueToken("admin")
	if err != nil {
		t.Fatal(err)
	}
	if code, _ = h.call("POST", "/api/v1/auth/logout", nil); code != 200 {
		t.Fatal("登出失败")
	}
	other := Server{store: h.srv.store, jwtSecret: h.srv.jwtSecret, username: h.srv.username}
	if _, err = other.parseToken(h.token); err == nil {
		t.Fatal("登出撤销未持久化")
	}
}

func TestQueryTokenIsRejectedAndExportHeaderWorks(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest("GET", h.ts.URL+"/api/v1/auth/me?token="+h.token, nil)
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 401 {
		t.Fatalf("query token 应拒绝，实际 %d", r.StatusCode)
	}
	req, _ = http.NewRequest("GET", h.ts.URL+"/api/v1/acl/black/export", nil)
	req.Header.Set("Authorization", "Bearer "+h.token)
	r, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("带认证头的导出失败: %d", r.StatusCode)
	}
}

func TestExtremePaginationAndHours(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"/api/v1/bans/active?page=9223372036854775807&size=500", "/api/v1/events?hours=9223372036854775807"} {
		code, r := h.call("GET", p, nil)
		if code != 200 && code != 400 {
			t.Fatalf("极端参数导致服务器错误: %d %s", code, r.Error)
		}
	}
}

func TestDurationOverflowRejected(t *testing.T) {
	h := newHarness(t)
	code, _ := h.call("POST", "/api/v1/bans", map[string]any{"target": "203.0.113.9", "duration_sec": int64(9223372036854775807)})
	if code != 400 {
		t.Fatalf("溢出时长应返回 400: %d", code)
	}
	p, err := h.srv.store.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	p.BanDurations = "600,-1,garbage"
	buf, _ := json.Marshal(p)
	req, _ := http.NewRequest("PUT", h.ts.URL+"/api/v1/policy", bytes.NewReader(buf))
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Content-Type", "application/json")
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	if r.StatusCode != 400 {
		t.Fatal("非法阶梯被静默过滤")
	}
}

func TestLoginStateIsBounded(t *testing.T) {
	l := newLoginLimiter()
	for i := 0; i < 11000; i++ {
		l.recordFail(strconv.Itoa(i))
	}
	if len(l.state) > 10000 {
		t.Fatal("登录状态无限增长")
	}
	if blocked, _ := l.blocked("new-address"); !blocked {
		t.Fatal("状态满时不能通过换 IP 绕过保护")
	}
}
