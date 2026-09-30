// Package update 通过 GitHub Releases 检查是否有新版本。
//
// 设计要点：
//
//   - **只读**。本包不会下载或替换任何文件，只在面板上提示有新版本并给出下载链接。
//     自更新涉及替换正在运行的可执行文件、校验签名、回滚，风险与复杂度都远超收益，
//     本面板刻意不做。
//   - **匿名访问**。仓库为公开仓库，无需 token。若将来转为私有，需要另行引入凭据。
//   - **带缓存**。GitHub 匿名 API 限流按 IP 计（60 次/小时），面板高频刷新很容易打满，
//     因此结果默认缓存一小时，手动触发也只在超过最小间隔时才真正发起请求。
//   - **失败不致命**。服务器在国内或纯内网时 api.github.com 经常连不通，此时如实返回
//     错误信息，绝不影响面板其它功能。
package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/version"
)

const (
	// DefaultRepo 是本项目的 GitHub 仓库。权威定义在 version 包，这里做个别名。
	DefaultRepo = version.DefaultRepo

	// defaultTTL 是成功结果的缓存时长。
	defaultTTL = time.Hour

	// defaultNegativeTTL 是失败结果的缓存时长。
	//
	// 失败必须也短暂缓存：纯内网或墙内服务器连不上 api.github.com，
	// 而前端每次打开面板都会自动查一次，若不缓存就会变成每次页面加载
	// 都挂一个 15 秒超时，把面板拖慢。手动点击「重新检查」可绕过它。
	defaultNegativeTTL = 10 * time.Minute

	// defaultMinInterval 是两次真实请求之间的最小间隔，防止连点把匿名配额打满。
	defaultMinInterval = 15 * time.Second

	// maxNotesRunes 限制返回给前端的发布说明长度。
	maxNotesRunes = 2000

	// maxReleases 单次拉取的发布记录条数。
	maxReleases = 30
)

// apiBase 是 GitHub API 的根地址。声明为变量是为了让测试指向本地桩服务。
var apiBase = "https://api.github.com"

// Asset 是 Release 附带的可下载文件。
type Asset struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	URL  string `json:"url"` // 浏览器可直接下载的地址
}

// Release 是从 GitHub 取回的单个发布记录。
type Release struct {
	Tag         string
	Version     version.Number
	Prerelease  bool
	PublishedAt time.Time
	PageURL     string
	Notes       string
	Assets      []Asset
}

// Result 是给前端的检查结果。字段全部带 json tag，直接序列化返回。
type Result struct {
	// 当前运行版本
	Current      string `json:"current"`
	CurrentIsPre bool   `json:"current_is_pre"`

	// 是否有可提示的更新
	HasUpdate   bool   `json:"has_update"`
	Latest      string `json:"latest,omitempty"`
	LatestIsPre bool   `json:"latest_is_pre"`
	PublishedAt string `json:"published_at,omitempty"`
	PageURL     string `json:"page_url,omitempty"`
	Notes       string `json:"notes,omitempty"`
	Assets      []Asset `json:"assets"`

	// 上下文：方便前端拼「查看全部版本」的链接
	Repo        string `json:"repo"`
	ReleasesURL string `json:"releases_url"`

	CheckedAt string `json:"checked_at,omitempty"`
	FromCache bool   `json:"from_cache"`
	// SkippedTags 记录 tag 不符合版本格式而被忽略的发布，便于排查。
	SkippedTags []string `json:"skipped_tags,omitempty"`

	// Error 非空表示本次检查失败（网络不通、限流等），不影响面板其它功能。
	Error string `json:"error,omitempty"`
}

// Checker 负责拉取并缓存发布信息。并发安全。
type Checker struct {
	repo        string
	client      *http.Client
	ttl         time.Duration
	negativeTTL time.Duration
	minInterval time.Duration
	// now 可在测试中替换，便于验证缓存行为。
	now func() time.Time

	mu       sync.Mutex
	cached   *Result
	cachedAt time.Time
	cachedOK bool
}

// Option 用于调整 Checker 行为。
type Option func(*Checker)

// WithRepo 覆盖默认仓库。
func WithRepo(repo string) Option {
	return func(c *Checker) {
		if strings.TrimSpace(repo) != "" {
			c.repo = strings.TrimSpace(repo)
		}
	}
}

// WithTTL 设置缓存时长。
func WithTTL(d time.Duration) Option {
	return func(c *Checker) {
		if d > 0 {
			c.ttl = d
		}
	}
}

// WithHTTPClient 注入自定义 HTTP 客户端（测试用）。
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Checker) { c.client = hc }
}

// New 构造一个检查器。默认走系统代理环境变量（HTTPS_PROXY 等）。
func New(opts ...Option) *Checker {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	c := &Checker{
		repo:        DefaultRepo,
		client:      &http.Client{Timeout: 15 * time.Second, Transport: transport},
		ttl:         defaultTTL,
		negativeTTL: defaultNegativeTTL,
		minInterval: defaultMinInterval,
		now:         time.Now,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Repo 返回当前使用的仓库。
func (c *Checker) Repo() string { return c.repo }

// ReleasesURL 返回供人浏览的发布页地址。
func (c *Checker) ReleasesURL() string {
	return "https://github.com/" + c.repo + "/releases"
}

// Check 检查更新。
//
// 缓存策略：
//
//   - force=false（前端自动检查）：成功结果缓存 ttl，失败结果缓存 negativeTTL，
//     期间一律直接返回缓存，不发请求。
//   - force=true（用户点「重新检查」）：绕过上述 TTL，但仍受 minInterval 约束，
//     避免连点。这样离线环境下的失败能立刻重试，又不会被打爆。
func (c *Checker) Check(ctx context.Context, force bool) Result {
	cur, err := version.Current()
	if err != nil {
		return Result{
			Current:     version.Version,
			Repo:        c.repo,
			ReleasesURL: c.ReleasesURL(),
			Assets:      []Asset{},
			Error:       "本机版本号 " + version.Version + " 无法解析: " + err.Error(),
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if hit, ok := c.lookupLocked(force); ok {
		out := *hit
		// 当前版本可能因进程重启而与缓存时不同，以实时值为准。
		out.Current = cur.String()
		out.CurrentIsPre = cur.IsPre()
		out.FromCache = true
		return out
	}

	res := c.fetch(ctx, cur)

	// 成功与失败都缓存，只是时长不同。
	copied := res
	c.cached = &copied
	c.cachedAt = c.now()
	c.cachedOK = res.Error == ""
	return res
}

// lookupLocked 判断是否可以直接用缓存。调用方必须已持有 c.mu。
func (c *Checker) lookupLocked(force bool) (*Result, bool) {
	if c.cached == nil {
		return nil, false
	}
	age := c.now().Sub(c.cachedAt)

	if force {
		// 手动触发：只做连点保护，不做业务缓存
		return c.cached, age < c.minInterval
	}
	if c.cachedOK {
		return c.cached, age < c.ttl
	}
	return c.cached, age < c.negativeTTL
}

// Peek 返回上一次检查的缓存结果，不发起任何网络请求。
// 第二个返回值为 false 表示还没有检查过。
func (c *Checker) Peek() (Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cached == nil {
		return Result{}, false
	}
	out := *c.cached
	out.FromCache = true
	if cur, err := version.Current(); err == nil {
		out.Current = cur.String()
		out.CurrentIsPre = cur.IsPre()
	}
	return out, true
}

func (c *Checker) fetch(ctx context.Context, cur version.Number) Result {
	out := Result{
		Current:      cur.String(),
		CurrentIsPre: cur.IsPre(),
		Repo:         c.repo,
		ReleasesURL:  c.ReleasesURL(),
		Assets:       []Asset{},
		CheckedAt:    time.Now().UTC().Format(time.RFC3339),
	}

	releases, err := c.listReleases(ctx)
	if err != nil {
		out.Error = err.Error()
		return out
	}

	cands := make([]version.Number, 0, len(releases))
	for _, r := range releases {
		if r.Version.IsZero() {
			out.SkippedTags = append(out.SkippedTags, r.Tag)
			continue
		}
		cands = append(cands, r.Version)
	}

	best, _, ok := version.SelectUpdate(cur, cands)
	if !ok {
		out.Latest = cur.String()
		return out
	}

	// SelectUpdate 的候选切片与 releases 之间可能因跳过非法 tag 而错位，
	// 这里按版本号反查真正的 Release 记录。
	picked := findRelease(releases, best)
	out.HasUpdate = true
	out.Latest = best.String()
	out.LatestIsPre = best.IsPre()
	if picked != nil {
		out.PublishedAt = picked.PublishedAt.UTC().Format(time.RFC3339)
		out.PageURL = picked.PageURL
		out.Notes = truncate(picked.Notes, maxNotesRunes)
		if len(picked.Assets) > 0 {
			out.Assets = picked.Assets
		}
	}
	return out
}

// findRelease 按版本号从发布记录里取出对应项。
func findRelease(releases []Release, n version.Number) *Release {
	for i := range releases {
		if version.Compare(releases[i].Version, n) == 0 {
			return &releases[i]
		}
	}
	return nil
}

// ---- GitHub API ----

type ghRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	HTMLURL     string    `json:"html_url"`
	Body        string    `json:"body"`
	Assets      []struct {
		Name               string `json:"name"`
		Size               int64  `json:"size"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func (c *Checker) listReleases(ctx context.Context) ([]Release, error) {
	url := fmt.Sprintf("%s/repos/%s/releases?per_page=%d", apiBase, c.repo, maxReleases)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("构造请求失败: %w", err)
	}
	// GitHub 要求带 User-Agent，缺失会直接 403
	req.Header.Set("User-Agent", "FrpFireWall/"+version.Version)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("连接 GitHub 失败（服务器可能无法访问外网）: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	switch {
	case resp.StatusCode == http.StatusOK:
		// 继续解析
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("仓库 %s 不存在或不可见（私有仓库无法匿名查询）", c.repo)
	case resp.StatusCode == http.StatusForbidden, resp.StatusCode == http.StatusTooManyRequests:
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return nil, fmt.Errorf("GitHub API 访问频率已达上限，请稍后再试")
		}
		return nil, fmt.Errorf("GitHub 拒绝了请求（HTTP %d）", resp.StatusCode)
	default:
		return nil, fmt.Errorf("GitHub 返回异常状态（HTTP %d）", resp.StatusCode)
	}

	var raw []ghRelease
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("解析发布列表失败: %w", err)
	}

	out := make([]Release, 0, len(raw))
	for _, r := range raw {
		if r.Draft {
			continue // 草稿不对用户可见
		}
		n, _ := version.Parse(r.TagName) // 解析失败留零值，由调用方计入 SkippedTags

		assets := make([]Asset, 0, len(r.Assets))
		for _, a := range r.Assets {
			assets = append(assets, Asset{Name: a.Name, Size: a.Size, URL: a.BrowserDownloadURL})
		}

		out = append(out, Release{
			Tag:         r.TagName,
			Version:     n,
			Prerelease:  r.Prerelease,
			PublishedAt: r.PublishedAt,
			PageURL:     r.HTMLURL,
			Notes:       r.Body,
			Assets:      assets,
		})
	}
	return out, nil
}

// truncate 按字符（而非字节）截断，避免把多字节字符切坏。
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "\n…（发布说明过长已截断，完整内容见发布页）"
}
