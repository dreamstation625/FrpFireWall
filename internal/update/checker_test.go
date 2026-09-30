package update

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dreamstation625/FrpFireWall/internal/version"
)

// stubGitHub 起一个假的 GitHub API，按 tag 列表返回发布记录。
// 返回的计数器用于验证缓存是否真的生效。
func stubGitHub(t *testing.T, tags ...string) (*httptest.Server, *atomic.Int32) {
	t.Helper()

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if !strings.HasSuffix(r.URL.Path, "/releases") {
			http.NotFound(w, r)
			return
		}
		var items []string
		for i, tag := range tags {
			items = append(items, fmt.Sprintf(`{
				"tag_name": %q,
				"name": %q,
				"draft": false,
				"prerelease": %v,
				"published_at": "2026-09-30T10:00:00Z",
				"html_url": "https://example.test/releases/tag/%s",
				"body": "发布说明 %d",
				"assets": [{"name":"frpfirewall-linux-amd64","size":123,"browser_download_url":"https://example.test/dl/%s"}]
			}`, tag, tag, strings.Contains(tag, "-pre."), tag, i, tag))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, "[%s]", strings.Join(items, ","))
	}))
	t.Cleanup(srv.Close)

	old := apiBase
	apiBase = srv.URL
	t.Cleanup(func() { apiBase = old })

	return srv, &hits
}

// withCurrentVersion 临时改写构建注入的版本号。
func withCurrentVersion(t *testing.T, v string) {
	t.Helper()
	old := version.Version
	version.Version = v
	t.Cleanup(func() { version.Version = old })
}

func TestCheckStableIgnoresPrerelease(t *testing.T) {
	// ★ 需求核心：正式版不检查到 pre 的更新
	withCurrentVersion(t, "0.0.1")
	stubGitHub(t, "v0.0.2-pre.01", "v0.0.1-pre.05")

	res := New().Check(context.Background(), true)

	if res.Error != "" {
		t.Fatalf("意外错误: %s", res.Error)
	}
	if res.HasUpdate {
		t.Fatalf("正式版不应提示预发布更新，却拿到了 %s", res.Latest)
	}
	if res.Current != "0.0.1" || res.CurrentIsPre {
		t.Errorf("当前版本字段不对: %+v", res)
	}
}

func TestCheckStableTakesHigherStable(t *testing.T) {
	withCurrentVersion(t, "0.0.1")
	stubGitHub(t, "v0.0.2-pre.01", "v0.0.2", "v0.0.1-pre.05")

	res := New().Check(context.Background(), true)

	if !res.HasUpdate {
		t.Fatal("应当提示更新到 0.0.2")
	}
	if res.Latest != "0.0.2" {
		t.Errorf("选中版本 = %s，期望 0.0.2", res.Latest)
	}
	if res.LatestIsPre {
		t.Error("选中的不应是预发布版")
	}
	if res.PageURL == "" || res.PublishedAt == "" {
		t.Errorf("缺少发布页信息: %+v", res)
	}
	if len(res.Assets) != 1 {
		t.Errorf("应带回 1 个下载资源，实际 %d 个", len(res.Assets))
	}
}

func TestCheckPrereleaseSeesBothTracks(t *testing.T) {
	withCurrentVersion(t, "0.0.1-pre.01")

	t.Run("同号正式版优先", func(t *testing.T) {
		stubGitHub(t, "v0.0.1-pre.03", "v0.0.1")
		res := New().Check(context.Background(), true)
		if !res.HasUpdate || res.Latest != "0.0.1" {
			t.Fatalf("预发布版用户应被推到同号正式版，实际 %s", res.Latest)
		}
	})

	t.Run("更高序号的预发布", func(t *testing.T) {
		stubGitHub(t, "v0.0.1-pre.03")
		res := New().Check(context.Background(), true)
		if !res.HasUpdate || res.Latest != "0.0.1-pre.03" {
			t.Fatalf("应提示 0.0.1-pre.03，实际 %s", res.Latest)
		}
		if !res.LatestIsPre {
			t.Error("期望标记为预发布版")
		}
	})
}

func TestCheckCachesResult(t *testing.T) {
	withCurrentVersion(t, "0.0.1")
	_, hits := stubGitHub(t, "v0.0.2")

	c := New()
	first := c.Check(context.Background(), false)
	if first.FromCache {
		t.Error("首次检查不应标记为缓存")
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("首次检查应发起 1 次请求，实际 %d 次", n)
	}

	second := c.Check(context.Background(), false)
	if !second.FromCache {
		t.Error("TTL 内的第二次检查应命中缓存")
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("命中缓存后不应再发请求，实际共 %d 次", n)
	}
	if second.Latest != first.Latest || second.HasUpdate != first.HasUpdate {
		t.Error("缓存结果与首次结果不一致")
	}

	// 强制检查仍在最小间隔内，应继续返回缓存
	third := c.Check(context.Background(), true)
	if !third.FromCache {
		t.Error("最小间隔内的强制检查应返回缓存")
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("最小间隔内不应发请求，实际共 %d 次", n)
	}
}

func TestCheckFailureNegativeCache(t *testing.T) {
	withCurrentVersion(t, "0.0.1")

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	c := New()

	first := c.Check(context.Background(), true)
	if first.Error == "" {
		t.Fatal("应当返回错误")
	}
	if first.HasUpdate {
		t.Error("出错时不应报告有更新")
	}
	if hits.Load() != 1 {
		t.Fatalf("首次应发 1 次请求，实际 %d 次", hits.Load())
	}

	// 失败要短暂缓存，否则离线环境下每次页面加载都会挂一个 15 秒超时
	auto := c.Check(context.Background(), false)
	if !auto.FromCache {
		t.Error("自动检查应命中失败的负缓存")
	}
	if hits.Load() != 1 {
		t.Errorf("负缓存期间不应再发请求，实际 %d 次", hits.Load())
	}
}

func TestCheckForceBypassesNegativeCache(t *testing.T) {
	withCurrentVersion(t, "0.0.1")

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	// 把 minInterval 调到 0，模拟「距上次请求已经过了冷却期」
	c := New()
	c.minInterval = 0

	c.Check(context.Background(), false)
	if hits.Load() != 1 {
		t.Fatalf("首次应发 1 次请求，实际 %d 次", hits.Load())
	}

	// 用户手动点「重新检查」，必须真的重试，否则网络恢复后用户没辙
	retry := c.Check(context.Background(), true)
	if retry.FromCache {
		t.Error("手动强制检查不应返回缓存")
	}
	if hits.Load() != 2 {
		t.Errorf("手动检查应重新发起请求，实际共 %d 次", hits.Load())
	}
}

func TestPeekDoesNotFetch(t *testing.T) {
	withCurrentVersion(t, "0.0.1")
	_, hits := stubGitHub(t, "v0.0.2")

	c := New()
	if _, ok := c.Peek(); ok {
		t.Error("尚未检查过时 Peek 应返回 false")
	}
	if hits.Load() != 0 {
		t.Errorf("Peek 不应发起请求，实际 %d 次", hits.Load())
	}

	c.Check(context.Background(), false)
	got, ok := c.Peek()
	if !ok {
		t.Fatal("检查后 Peek 应返回结果")
	}
	if !got.HasUpdate || got.Latest != "0.0.2" {
		t.Errorf("Peek 结果不对: %+v", got)
	}
	if hits.Load() != 1 {
		t.Errorf("Peek 之后请求数不应增加，实际 %d 次", hits.Load())
	}
}

func TestCheckSkipsUnparsableTags(t *testing.T) {
	withCurrentVersion(t, "0.0.1")
	stubGitHub(t, "nightly", "v0.0.2")

	res := New().Check(context.Background(), true)

	if res.Error != "" {
		t.Fatalf("非法 tag 不应导致整体失败: %s", res.Error)
	}
	if res.Latest != "0.0.2" {
		t.Errorf("应忽略非法 tag 后取到 0.0.2，实际 %s", res.Latest)
	}
	if len(res.SkippedTags) != 1 || res.SkippedTags[0] != "nightly" {
		t.Errorf("应记录跳过的 tag，实际 %v", res.SkippedTags)
	}
}

func TestCheckNoReleases(t *testing.T) {
	withCurrentVersion(t, "0.0.1")
	stubGitHub(t)

	res := New().Check(context.Background(), true)
	if res.Error != "" {
		t.Fatalf("仓库无发布不应算错误: %s", res.Error)
	}
	if res.HasUpdate {
		t.Error("无发布时不应报告有更新")
	}
	if res.Latest != "0.0.1" {
		t.Errorf("Latest 应回落到当前版本，实际 %s", res.Latest)
	}
}

func TestCheckInvalidCurrentVersion(t *testing.T) {
	withCurrentVersion(t, "0.1.0-dev") // 旧格式，不可解析
	stubGitHub(t, "v0.0.2")

	res := New().Check(context.Background(), true)
	if res.Error == "" {
		t.Fatal("当前版本不可解析时应如实报错")
	}
	if res.HasUpdate {
		t.Error("版本号不可解析时不应报告更新")
	}
}

func TestTruncateByRunes(t *testing.T) {
	// 按字符截断，不能把多字节字符切坏
	got := truncate("中文说明内容", 3)
	if !strings.HasPrefix(got, "中文说") {
		t.Errorf("截断结果 = %q", got)
	}
	if !strings.Contains(got, "截断") {
		t.Errorf("截断后应有提示，实际 %q", got)
	}
	if got := truncate("短", 10); got != "短" {
		t.Errorf("未超长时不应截断，实际 %q", got)
	}
	if got := truncate("  带空白  ", 10); got != "带空白" {
		t.Errorf("应去掉首尾空白，实际 %q", got)
	}
}

func TestReleasesURL(t *testing.T) {
	c := New(WithRepo("foo/bar"))
	if got := c.ReleasesURL(); got != "https://github.com/foo/bar/releases" {
		t.Errorf("ReleasesURL = %q", got)
	}
	if got := New().Repo(); got != DefaultRepo {
		t.Errorf("默认仓库 = %q，期望 %q", got, DefaultRepo)
	}
}

func TestWithRepoIgnoresBlank(t *testing.T) {
	if got := New(WithRepo("   ")).Repo(); got != DefaultRepo {
		t.Errorf("空白仓库名应被忽略，实际 %q", got)
	}
}
