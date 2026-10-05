package myip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseIPv4FromPlainAndJSON(t *testing.T) {
	cases := map[string]string{
		"纯文本":     "203.0.113.7\n",
		"带前后说明":   "当前 IP：203.0.113.7  来自于：中国 上海\n",
		"JSON":    `{"ip":"203.0.113.7","country":"CN"}`,
		"多行文本":    "IP\t: 203.0.113.7\n地址\t: 中国 上海\n运营商\t: 阿里云\n",
		"HTML 片段": "<html><body>Your IP is 203.0.113.7 (thanks)</body></html>",
		"括号里":     "your ip (203.0.113.7)",
	}
	for name, body := range cases {
		addr, ok := ParseIPv4(body)
		if !ok {
			t.Fatalf("%s: 没解析出地址", name)
		}
		if addr.String() != "203.0.113.7" {
			t.Fatalf("%s: 得到 %s", name, addr)
		}
	}
}

func TestParseIPv4RejectsUnusableAddresses(t *testing.T) {
	// 私有 / 环回 / 组播 / 未指定都不算公网出口，遇到就跳到下一个候选
	cases := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"127.0.0.1",
		"169.254.1.1",
		"224.0.0.1",
		"0.0.0.0",
		"999.1.1.1",
		"没有地址的一段话",
	}
	for _, body := range cases {
		if _, ok := ParseIPv4(body); ok {
			t.Fatalf("%q 不该被当成公网出口", body)
		}
	}
}

// TestParseIPv4PicksFirstPublicCandidate 两个都是公网地址时取第一个。
//
// 这是既定策略而非"正确"：回显服务只会给一个地址，真出现两个时无从判断
// 哪个是出口。选第一个是因为所有源都把 IP 放在最前面，而 XFF 之类的
// 附加值是跟在后面的。
func TestParseIPv4PicksFirstPublicCandidate(t *testing.T) {
	addr, ok := ParseIPv4("198.51.100.9 203.0.113.7")
	if !ok || addr.String() != "198.51.100.9" {
		t.Fatalf("应取第一个公网地址，实际 %v %v", addr, ok)
	}
}

// TestParseIPv4SkipsPrivateThenPicksPublic 响应里先出现内网地址时应当跳过它。
func TestParseIPv4SkipsPrivateThenPicksPublic(t *testing.T) {
	// 有的服务会把 X-Forwarded-For 之类的东西一起吐出来，内网地址在前
	addr, ok := ParseIPv4("192.168.31.1, 203.0.113.7")
	if !ok || addr.String() != "203.0.113.7" {
		t.Fatalf("跳过内网地址失败: %v %v", addr, ok)
	}
}

// newSource 起一个回显服务，返回它的 URL 与被调用次数。
func newSource(t *testing.T, body string, status int) (string, *int) {
	t.Helper()
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if status != 200 {
			w.WriteHeader(status)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &n
}

func TestResolverUsesFirstWorkingSource(t *testing.T) {
	good, goodHits := newSource(t, "203.0.113.7\n", 200)
	bad, badHits := newSource(t, "", 500)

	r := New(
		WithSources([]Source{{Name: "bad", URL: bad}, {Name: "good", URL: good}}),
		WithTTL(time.Minute),
	)
	res := r.Lookup(context.Background(), false)
	if res.IP != "203.0.113.7" || res.Source != "good" {
		t.Fatalf("期望命中第二个源: %+v", res)
	}
	if *goodHits != 1 {
		t.Fatalf("good 应只被调一次，实际 %d", *goodHits)
	}
	if *badHits != 1 {
		t.Fatalf("bad 应被尝试一次，实际 %d", *badHits)
	}
}

func TestResolverReportsFailureWithoutIP(t *testing.T) {
	srv, _ := newSource(t, "not an ip", 200)
	r := New(WithSources([]Source{{Name: "junk", URL: srv}}), WithTTL(time.Minute))

	res := r.Lookup(context.Background(), false)
	if res.Ok() {
		t.Fatalf("不该解析出地址: %+v", res)
	}
	if res.Err == "" {
		t.Fatal("失败时必须带上原因，界面要靠它决定怎么提示")
	}
}

func TestResolverCachesUntilExpiry(t *testing.T) {
	url, hits := newSource(t, "203.0.113.7\n", 200)
	r := New(WithSources([]Source{{Name: "s", URL: url}}), WithTTL(time.Minute))

	_ = r.Lookup(context.Background(), false)
	_ = r.Lookup(context.Background(), false)
	_ = r.Lookup(context.Background(), false)
	if *hits != 1 {
		t.Fatalf("60 秒缓存内不该重复打外部服务，实际 %d 次", *hits)
	}

	// force 必须穿透缓存：设置页的「重新检测」就是这个语义
	_ = r.Lookup(context.Background(), true)
	if *hits != 2 {
		t.Fatalf("force 应重新探测，实际 %d 次", *hits)
	}
}

func TestResolverRefreshesAfterTTL(t *testing.T) {
	url, hits := newSource(t, "203.0.113.7\n", 200)
	// ttl=0 表示不缓存
	r := New(WithSources([]Source{{Name: "s", URL: url}}), WithTTL(0))

	_ = r.Lookup(context.Background(), false)
	_ = r.Lookup(context.Background(), false)
	if *hits != 2 {
		t.Fatalf("ttl=0 时每次都该重新探测，实际 %d 次", *hits)
	}
}

// TestResolverDropsStaleSuccess 上一次成功、这一次失败时，不该继续报旧地址。
func TestResolverDropsStaleSuccess(t *testing.T) {
	ok, _ := newSource(t, "203.0.113.7\n", 200)
	down, _ := newSource(t, "", 500)

	r := New(WithSources([]Source{{Name: "s", URL: ok}}), WithTTL(0))
	if res := r.Lookup(context.Background(), false); !res.Ok() {
		t.Fatalf("第一次应成功: %+v", res)
	}

	r2 := New(WithSources([]Source{{Name: "s", URL: down}}), WithTTL(0))
	// 同一个 Resolver 换源模拟"服务挂了"
	r.srcs = r2.srcs
	res := r.Lookup(context.Background(), true)
	if res.Ok() {
		t.Fatalf("探测失败后不该继续返回旧地址: %+v", res)
	}
}

func TestIsPublicIPv4(t *testing.T) {
	if !IsPublicIPv4(" 203.0.113.7 ") {
		t.Fatal("带空格的公网地址应被接受")
	}
	for _, s := range []string{"192.168.1.1", "127.0.0.1", "::1", "abc", ""} {
		if IsPublicIPv4(s) {
			t.Fatalf("%q 不该被接受", s)
		}
	}
}
