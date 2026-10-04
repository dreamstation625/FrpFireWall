package geoip

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// ---- 可下载的数据库 ----

// Source 是一个可以从上游拉取的数据库。
//
// 上游文件名和落地文件名**不一定相同**：ip2region 仓库里叫 ip2region_v4.xdb，
// 我们统一落成 ip2region.xdb（FileRegion），所以 URL 和 Name 要分开写。
type Source struct {
	Name  string `json:"name"`  // 落地文件名，同时也是接口的请求参数
	Title string `json:"title"` // 界面上显示的名字
	URL   string `json:"url"`   // 上游原始地址（未加速）
	// Repo 是上游仓库地址，界面上「前往下载源仓库」直接跳它。
	// 给完整 URL 而不是 owner/repo：跳转目标由后端说了算，前端不去拼域名，
	// 以后换到非 GitHub 的托管也不用改前端。
	Repo string `json:"repo"`
	// Size 是预估大小（带「约」），下载前让用户对耗时有个预期 ——
	// City 库有 64MB，点下去才发现要等半分钟体验很差。
	Size string `json:"size"`
}

var sources = []Source{
	{
		Name:  FileCountry,
		Title: "GeoLite2-Country（国家级）",
		URL:   "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-Country.mmdb",
		Repo:  "https://github.com/P3TERX/GeoLite.mmdb",
		Size:  "约 8MB",
	},
	{
		Name:  FileCity,
		Title: "GeoLite2-City（城市级）",
		URL:   "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-City.mmdb",
		Repo:  "https://github.com/P3TERX/GeoLite.mmdb",
		Size:  "约 64MB",
	},
	{
		Name:  FileRegion,
		Title: "ip2region（国内细化）",
		URL:   "https://raw.githubusercontent.com/lionsoul2014/ip2region/refs/heads/master/data/ip2region_v4.xdb",
		Repo:  "https://github.com/lionsoul2014/ip2region",
		Size:  "约 11MB",
	},
}

// Sources 返回可下载的库列表。
func Sources() []Source {
	out := make([]Source, len(sources))
	copy(out, sources)
	return out
}

func sourceByName(name string) (Source, bool) {
	for _, s := range sources {
		if s.Name == name {
			return s, true
		}
	}
	return Source{}, false
}

func sourceNames() string {
	names := make([]string, 0, len(sources))
	for _, s := range sources {
		names = append(names, s.Name)
	}
	return strings.Join(names, " / ")
}

// ---- 加速源 ----

// MirrorAuto 是「依次尝试全部来源」的保留值。它不是一个 Mirror。
const MirrorAuto = "auto"

// Mirror 是一个下载加速源。
//
// 用法只有一种：把原始 URL 原样拼在 Prefix 后面。ghproxy 类都是这个形状
// （https://ghproxy.net/https://github.com/...），所以不必为每个源写单独规则。
//
// Prefix 一律来自下面的内置表，**不接受请求参数传入**：如果让调用方随便给一段
// 前缀，等于开放任意 URL 转发，面板能连到的内网地址会被逐个探测一遍。
type Mirror struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Prefix string `json:"prefix"`
	Note   string `json:"note"`
}

// 内置加速源。这类服务随时可能挂掉或改域名，所以选择权交给用户，
// 并且提供「自动」模式依次尝试。
//
// 两条维护规则：
//   - 顺序即尝试顺序，按实测可用度和速度排，让 auto 第一枪大概率命中。
//   - 加源之前先实测，而且要**下下来验一遍文件头**。这个列表曾经放过三个源，
//     全部实测淘汰：hub.gitmirror.com 和 github.moeyy.xyz 连不上（curl 000）；
//     gitproxy.click 看着是通的（HTTP 200），但拿到的根本不是 xdb 文件，
//     openRegion 报 "invalid version"。只测状态码会把它当可用源留下。
//
// 直连（Prefix 为空）固定排最后：国内环境下 raw.githubusercontent.com 基本不可达，
// 先试加速源能少等一轮超时；机器本身能直连时它兜底。
var mirrors = []Mirror{
	{ID: "ghfast", Name: "ghfast.top", Prefix: "https://ghfast.top/", Note: "公共代理，实测较快"},
	{ID: "gh-proxy", Name: "gh-proxy.com", Prefix: "https://gh-proxy.com/", Note: "公共代理，实测较快"},
	{ID: "ghproxy", Name: "ghproxy.net", Prefix: "https://ghproxy.net/", Note: "公共代理，较知名"},
	{ID: "llkk", Name: "gh.llkk.cc", Prefix: "https://gh.llkk.cc/", Note: "公共代理"},
	{ID: "direct", Name: "直连 GitHub", Prefix: "", Note: "不走加速；机器本身能直连时最可靠"},
}

// Mirrors 返回内置加速源列表。
func Mirrors() []Mirror {
	out := make([]Mirror, len(mirrors))
	copy(out, mirrors)
	return out
}

// MirrorURL 把原始 URL 改写成走指定加速源的 URL。
// prefix 为空表示直连，原样返回。
func MirrorURL(prefix, raw string) string {
	if prefix == "" {
		return raw
	}
	return strings.TrimRight(prefix, "/") + "/" + raw
}

// mirrorChain 解析出这次要依次尝试的加速源。
//
// auto 的语义是「全都试一遍」，顺序即 mirrors 的顺序；指定某个 ID 就只试它。
// 这些加速源是公共的，随时可能挂，自动模式的容错主要靠这里。
func mirrorChain(id string) ([]Mirror, error) {
	id = strings.TrimSpace(id)
	if id == "" || id == MirrorAuto {
		return Mirrors(), nil
	}
	for _, m := range mirrors {
		if m.ID == id {
			return []Mirror{m}, nil
		}
	}
	ids := make([]string, 0, len(mirrors)+1)
	ids = append(ids, MirrorAuto)
	for _, m := range mirrors {
		ids = append(ids, m.ID)
	}
	return nil, fmt.Errorf("未知的加速源 %q，可选：%s", id, strings.Join(ids, " / "))
}

// ---- 下载 ----

const (
	// perSourceTimeout 单个来源的时长上限。源被墙时靠它快速切下一个，
	// 不能等满总超时再换。2 分钟对 64MB 的 City 库要求约 550KB/s，
	// 连上了却只有几十 KB/s 的源不如直接换掉。
	perSourceTimeout = 2 * time.Minute
	// totalTimeout 一次下载（含多源重试）的总时长上限。
	// 预算要能覆盖一整轮尝试：加速源个数 × perSourceTimeout 再加点余量，
	// 否则排在后面的源根本没有机会被试到。
	totalTimeout = 12 * time.Minute
)

// DownloadResult 是一次下载的结果。
type DownloadResult struct {
	Name    string `json:"name"`
	Mirror  string `json:"mirror"`  // 实际用上的加速源 ID
	URL     string `json:"url"`     // 实际请求的地址
	Version string `json:"version"` // 上游版本号，尽力而为，解析不到就是空
	Size    int64  `json:"size"`    // 落地字节数
}

// downloadClient 供整个下载流程共用。
//
// ResponseHeaderTimeout 是关键：源不可达时能在 20 秒内失败并切下一个，
// 而不是干等到总超时。ProxyFromEnvironment 让机器上配了代理的走代理。
var downloadClient = &http.Client{
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          4,
	},
}

// User-Agent 必须带：GitHub 对没有 UA 的请求会直接拒。
const downloadUA = "frpfirewall-geoip-updater"

// Download 从上游拉取指定数据库，校验后原子替换并热加载。
//
// mirrorID 传 MirrorAuto（或空）会按「加速源优先、直连兜底」的顺序依次尝试，
// 全部失败时把每个源的原因一并返回 —— 「都失败了」这种信息没法指导下一步。
func (r *Resolver) Download(ctx context.Context, name, mirrorID string) (*DownloadResult, error) {
	src, ok := sourceByName(name)
	if !ok {
		return nil, fmt.Errorf("不支持下载 %q，可选：%s", name, sourceNames())
	}

	chain, err := mirrorChain(mirrorID)
	if err != nil {
		return nil, err
	}

	// 两个下载会撞在同一个 <file>.tmp 上，所以同时只允许一个。
	// 用 TryLock 直接拒绝，让用户知道在下了，而不是排队等一个 64MB 的文件。
	if !r.downloadMu.TryLock() {
		return nil, errors.New("已有下载任务正在进行，请等它结束后再试")
	}
	defer r.downloadMu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, totalTimeout)
	defer cancel()

	failures := make([]string, 0, len(chain))
	for _, m := range chain {
		res, err := r.downloadFrom(ctx, src, m)
		if err == nil {
			return res, nil
		}
		failures = append(failures, m.Name+"："+err.Error())

		// 总超时到了就别再试剩下的，只会拿到一串同样的超时。
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("下载失败。%s", strings.Join(failures, "；"))
}

// downloadFrom 走指定的一个加速源下载一次。
func (r *Resolver) downloadFrom(ctx context.Context, src Source, m Mirror) (*DownloadResult, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, perSourceTimeout)
	defer cancel()

	return r.fetchAndInstall(attemptCtx, src.Name, MirrorURL(m.Prefix, src.URL), m.ID)
}

// fetchAndInstall 是真正干活的那一层：发请求 → 边下边写临时文件 → 校验 → 替换。
//
// 入口单独拆出来是为了好测：Download 里的上游地址是写死的，测试没法把
// 请求引到 httptest 上去，而这一层只认一个 URL。
func (r *Resolver) fetchAndInstall(ctx context.Context, name, url, mirrorID string) (*DownloadResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", downloadUA)

	resp, err := downloadClient.Do(req)
	if err != nil {
		return nil, friendlyNetErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d %s", resp.StatusCode, statusHint(resp.StatusCode))
	}
	// Content-Length 有就提前拒，省得白下 200MB 才开始报错。
	if resp.ContentLength > maxFileSize {
		return nil, fmt.Errorf("上游文件 %d 字节，超过上限 %d 字节", resp.ContentLength, maxFileSize)
	}

	n, err := r.install(name, resp.Body, maxFileSize)
	if err != nil {
		return nil, err
	}

	return &DownloadResult{
		Name:    name,
		Mirror:  mirrorID,
		URL:     url,
		Version: upstreamVersion(resp),
		Size:    n,
	}, nil
}

// releaseTagRe 匹配 GitHub 的 releases/download/<tag>/<file>。
var releaseTagRe = regexp.MustCompile(`/releases/download/([^/]+)/`)

// upstreamVersion 尽量从最终 URL 里解析出上游版本号。
//
// GitHub 的 releases/latest/download/<file> 会 302 到 releases/download/<tag>/<file>，
// 所以直连时能拿到 tag（P3TERX 那个仓库用日期当 tag）。走加速源时中间多一层跳转，
// 多半解析不到 —— 解析不到就返回空，不编造。
func upstreamVersion(resp *http.Response) string {
	if resp.Request == nil || resp.Request.URL == nil {
		return ""
	}
	if m := releaseTagRe.FindStringSubmatch(resp.Request.URL.Path); m != nil {
		return m[1]
	}
	return ""
}

// statusHint 把几个常见的状态码翻译成人话。
func statusHint(code int) string {
	switch code {
	case http.StatusNotFound:
		return "（上游没有这个文件，可能改名了）"
	case http.StatusForbidden:
		return "（被上游拒绝，加速源可能限流或已失效）"
	case http.StatusTooManyRequests:
		return "（上游限流，稍后再试或换个加速源）"
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return "（加速源不可用，换个源试试）"
	}
	return ""
}

// friendlyNetErr 把网络层错误翻译成能指导下一步的说法。
// 原始的 dial tcp: lookup xxx: no such host 对用户等于没说。
func friendlyNetErr(err error) error {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return fmt.Errorf("域名解析失败（%s），多半是 DNS 被污染，换一个加速源试试", dnsErr.Name)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("连接或读取超时，换一个加速源试试")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return errors.New("网络超时，换一个加速源试试")
	}
	return err
}
