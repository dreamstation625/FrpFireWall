package geoip

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// assertNoLeftovers 断言数据目录里没留下任何文件。
// 安装失败必须把临时文件清掉 —— 留一个半截的 .tmp 在那，下次排障的人
// 会以为库已经装上了。
func assertNoLeftovers(t *testing.T, dir string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读数据目录失败: %v", err)
	}
	for _, e := range ents {
		t.Errorf("数据目录里残留了文件: %s", e.Name())
	}
}

func TestMirrorURL(t *testing.T) {
	cases := []struct {
		prefix, raw, want string
	}{
		{"", "https://github.com/a/b", "https://github.com/a/b"},
		{"https://ghproxy.net/", "https://github.com/a/b", "https://ghproxy.net/https://github.com/a/b"},
		// 前缀少写一个尾斜杠也要拼对，不然会拼出 ...nethttps://
		{"https://ghproxy.net", "https://github.com/a/b", "https://ghproxy.net/https://github.com/a/b"},
		{"https://hub.gitmirror.com/", "https://raw.githubusercontent.com/a/b", "https://hub.gitmirror.com/https://raw.githubusercontent.com/a/b"},
	}
	for _, c := range cases {
		if got := MirrorURL(c.prefix, c.raw); got != c.want {
			t.Errorf("MirrorURL(%q, %q) = %q，期望 %q", c.prefix, c.raw, got, c.want)
		}
	}
}

func TestMirrorChainAuto(t *testing.T) {
	chain, err := mirrorChain(MirrorAuto)
	if err != nil {
		t.Fatalf("auto 不应报错: %v", err)
	}
	if len(chain) != len(mirrors) {
		t.Fatalf("auto 应尝试全部 %d 个源，得到 %d 个", len(mirrors), len(chain))
	}
	// 国内环境下 raw.githubusercontent.com 基本不可达，直连放最后兜底，
	// 免得一上来就卡在超时上。
	if last := chain[len(chain)-1]; last.Prefix != "" {
		t.Errorf("直连应排在最后，实际最后是 %q", last.Name)
	}

	// 空字符串与 auto 同义。
	empty, err := mirrorChain("")
	if err != nil || len(empty) != len(chain) {
		t.Errorf("空 mirror 应等价于 auto，得到 %d 个源，err=%v", len(empty), err)
	}
}

// TestTimeoutBudgetCoversFullChain 加源时最容易忘的就是同步调总超时，
// 结果排在列表后面的源永远轮不到试。把两者绑在一起当守卫。
func TestTimeoutBudgetCoversFullChain(t *testing.T) {
	need := time.Duration(len(mirrors)) * perSourceTimeout
	if totalTimeout < need {
		t.Errorf("%d 个源 × %s = %s，超过总超时 %s，排在后面的源会被截断",
			len(mirrors), perSourceTimeout, need, totalTimeout)
	}
}

func TestMirrorChainByID(t *testing.T) {
	for _, m := range Mirrors() {
		chain, err := mirrorChain(m.ID)
		if err != nil {
			t.Fatalf("指定 %q 不应报错: %v", m.ID, err)
		}
		if len(chain) != 1 || chain[0].ID != m.ID {
			t.Errorf("指定 %q 应只返回它自己，得到 %+v", m.ID, chain)
		}
	}
}

// TestMirrorChainRejectsUnknown 加速源前缀只能来自内置表。
// 如果允许调用方随便传一段前缀，等于开放任意 URL 转发，面板能连到的
// 内网地址会被逐个探测一遍。
func TestMirrorChainRejectsUnknown(t *testing.T) {
	for _, id := range []string{
		"evil",
		"http://127.0.0.1:8080/",
		"https://attacker.example/",
		"../../etc",
	} {
		if _, err := mirrorChain(id); err == nil {
			t.Errorf("mirrorChain(%q) 应被拒绝", id)
		}
	}
}

func TestMirrorsUseHTTPS(t *testing.T) {
	for _, m := range Mirrors() {
		if m.Prefix != "" && !strings.HasPrefix(m.Prefix, "https://") {
			t.Errorf("加速源 %q 的前缀必须是 https，得到 %q", m.ID, m.Prefix)
		}
		if m.ID == "" || m.Name == "" {
			t.Errorf("加速源缺少 ID 或 Name: %+v", m)
		}
	}
}

// TestSourcesAreInstallable 每个下载源的落地文件名必须过 install 的白名单，
// 否则用户点了下载只会拿到「不支持的文件名」—— 加源时写错名字就会踩这个。
func TestSourcesAreInstallable(t *testing.T) {
	list := Sources()
	if len(list) != 3 {
		t.Fatalf("应提供 3 个下载源，得到 %d 个", len(list))
	}
	for _, s := range list {
		if !isKnownFile(s.Name) {
			t.Errorf("下载源 %q 的文件名不在白名单里", s.Name)
		}
		if !strings.HasPrefix(s.URL, "https://") {
			t.Errorf("下载源 %q 的地址必须是 https，得到 %q", s.Name, s.URL)
		}
		if s.Title == "" || s.From == "" {
			t.Errorf("下载源 %q 缺少 Title 或 From: %+v", s.Name, s)
		}
	}
}

// TestSourcesReturnsCopy 防外部改到内部表。
func TestSourcesReturnsCopy(t *testing.T) {
	got := Sources()
	got[0].Name = "hacked"
	if Sources()[0].Name == "hacked" {
		t.Error("Sources() 应返回副本")
	}
	m := Mirrors()
	m[0].Prefix = "https://evil/"
	if Mirrors()[0].Prefix == "https://evil/" {
		t.Error("Mirrors() 应返回副本")
	}
}

func TestDownloadRejectsUnknownName(t *testing.T) {
	r := New(t.TempDir())
	for _, name := range []string{"../evil.mmdb", "GeoLite2-ASN.mmdb", ""} {
		if _, err := r.Download(context.Background(), name, MirrorAuto); err == nil {
			t.Errorf("Download(%q) 应被拒绝", name)
		}
	}
}

func TestDownloadRejectsUnknownMirror(t *testing.T) {
	r := New(t.TempDir())
	_, err := r.Download(context.Background(), FileCountry, "不存在的源")
	if err == nil || !strings.Contains(err.Error(), "未知的加速源") {
		t.Fatalf("应报未知加速源，得到 %v", err)
	}
}

// TestDownloadRejectsConcurrent 同时只允许一个下载任务：
// 两个下载会撞在同一个 <file>.tmp 上。
func TestDownloadRejectsConcurrent(t *testing.T) {
	r := New(t.TempDir())
	r.downloadMu.Lock()
	defer r.downloadMu.Unlock()

	_, err := r.Download(context.Background(), FileCountry, MirrorAuto)
	if err == nil || !strings.Contains(err.Error(), "正在进行") {
		t.Fatalf("应拒绝并发下载，得到 %v", err)
	}
}

// TestFetchAndInstallRejectsGarbage 坏内容必须被文件头校验挡住，
// 且不能留下临时文件、不能让库变成「已加载」。
func TestFetchAndInstallRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	r := New(dir)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("这不是一个 mmdb 文件，只是一段文本"))
	}))
	defer srv.Close()

	_, err := r.fetchAndInstall(context.Background(), FileCountry, srv.URL, "test")
	if err == nil {
		t.Fatal("垃圾内容应被文件头校验拒绝")
	}
	if !strings.Contains(err.Error(), "校验失败") {
		t.Errorf("错误信息应指明是校验失败，得到 %v", err)
	}
	assertNoLeftovers(t, dir)
	if r.Available() {
		t.Error("校验失败后不应有任何库处于加载状态")
	}
	if r.Status().CountryLoaded {
		t.Error("CountryLoaded 不该被置为 true")
	}
}

// TestInstallRejectsOversize 超限要在写临时文件阶段就拦住，不碰旧库。
// 直接调 install 用小上限，免得真造 200MB 数据。
func TestInstallRejectsOversize(t *testing.T) {
	dir := t.TempDir()
	r := New(dir)

	const body = 4096
	const limit = 1024
	n, err := r.install(FileCountry, bytes.NewReader(make([]byte, body)), limit)
	if err == nil {
		t.Fatal("超过上限应报错")
	}
	if !strings.Contains(err.Error(), "超过上限") {
		t.Errorf("错误信息应提到上限，得到 %v", err)
	}
	// 读满 上限+1 就应该停下，不该把整个 body 读完。
	if n != limit+1 {
		t.Errorf("应在读到 %d 字节时停止，实际读了 %d", limit+1, n)
	}
	assertNoLeftovers(t, dir)
}

func TestInstallRejectsUnknownName(t *testing.T) {
	r := New(t.TempDir())
	if _, err := r.install("../evil.mmdb", strings.NewReader("x"), 1024); err == nil {
		t.Fatal("白名单外的文件名应被拒绝")
	}
}

func TestFetchAndInstallHTTPStatus(t *testing.T) {
	cases := []struct {
		code int
		want string
	}{
		{http.StatusNotFound, "上游没有这个文件"},
		{http.StatusForbidden, "被上游拒绝"},
		{http.StatusTooManyRequests, "限流"},
		{http.StatusBadGateway, "加速源不可用"},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(c.code)
		}))
		r := New(t.TempDir())
		_, err := r.fetchAndInstall(context.Background(), FileCountry, srv.URL, "test")
		srv.Close()

		if err == nil {
			t.Errorf("HTTP %d 应报错", c.code)
			continue
		}
		if !strings.Contains(err.Error(), strconv.Itoa(c.code)) {
			t.Errorf("错误信息应含状态码 %d，得到 %v", c.code, err)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("HTTP %d 的错误信息应含 %q，得到 %v", c.code, c.want, err)
		}
	}
}

func TestUpstreamVersion(t *testing.T) {
	mk := func(raw string) *http.Response {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("测试用 URL 写错了: %v", err)
		}
		return &http.Response{Request: &http.Request{URL: u}}
	}

	if got := upstreamVersion(mk("https://github.com/P3TERX/GeoLite.mmdb/releases/download/2026.10.01/GeoLite2-Country.mmdb")); got != "2026.10.01" {
		t.Errorf("应从 release 路径解析出 tag，得到 %q", got)
	}
	if got := upstreamVersion(mk("https://objects.githubusercontent.com/some/blob")); got != "" {
		t.Errorf("解析不到就返回空，得到 %q", got)
	}
	if got := upstreamVersion(&http.Response{}); got != "" {
		t.Errorf("Request 为 nil 时应返回空，得到 %q", got)
	}
}

func TestFriendlyNetErr(t *testing.T) {
	dnsErr := &net.DNSError{Name: "raw.githubusercontent.com", Err: "no such host"}
	msg := friendlyNetErr(dnsErr).Error()
	if !strings.Contains(msg, "DNS") || !strings.Contains(msg, "raw.githubusercontent.com") {
		t.Errorf("DNS 错误应给出可操作的提示，得到 %q", msg)
	}

	timeout := friendlyNetErr(context.DeadlineExceeded).Error()
	if !strings.Contains(timeout, "超时") {
		t.Errorf("超时应被识别，得到 %q", timeout)
	}
}
