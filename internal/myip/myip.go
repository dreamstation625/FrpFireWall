// Package myip 探测本机对外的公网 IPv4 地址。
//
// 只走"外部回显服务"这一条路：问第三方"你看到的我是谁"，而不是问本机
// 路由表"你打算用哪个源地址"。后者（UDP 拨一下 8.8.8.8:53 取 LocalAddr）
// 零成本、不外泄，但它回答的是"默认路由选中的那条"，多出口、策略路由、
// 机器在 NAT 后面时能给出一个完全不是公网出口的地址，而且看不出来它错了。
// 本功能唯一的价值就是"服务器真实对外地址"，宁可依赖外部服务换准确。
//
// 代价要说在明处：每次探测会向第三方暴露服务器 IP。所以结果带 60 秒缓存，
// 且只有显式调用接口时才探测，不随启动或定时跑。
package myip

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Source 是一个回显服务。Name 只用于展示"这个值是谁给的"。
type Source struct {
	Name string
	URL  string
}

// DefaultSources 按序尝试，第一个成功即返回。
//
// 国内源排在前面：这台机器大概率在国内，问境外服务要先绕一圈，
// 慢不说还经常连不上。后面的境外源是兜底，不是顺序无所谓 ——
// 真到了国内源全挂的时候，能拿到一个答案比挑好看的源重要。
func DefaultSources() []Source {
	return []Source{
		{Name: "myip.ipip.net", URL: "https://myip.ipip.net"},
		{Name: "api.cip.cc", URL: "https://api.cip.cc"},
		{Name: "myip.fireflysoft.net", URL: "https://myip.fireflysoft.net"},
		{Name: "api.ipify.org", URL: "https://api.ipify.org"},
		{Name: "ifconfig.me", URL: "https://ifconfig.me/ip"},
	}
}

const (
	// probeTimeout 单源总超时。五个源全挂最坏 25 秒，仍在可接受范围内，
	// 而且这是"点了检测才发生"的事，不在启动路径上。
	probeTimeout = 5 * time.Second
	// maxBody 回显内容最多读这么多。IP 在头部就出现了，4K 足够，
	// 也避免某个源返回一整页 HTML 时被拖着读。
	maxBody = 4096
	// cacheTTL 缓存时长，见包注释。
	cacheTTL = 60 * time.Second
	// userAgent 带个名字，方便对端知道是谁在问。
	userAgent = "frpfirewall"
)

// Result 是一次探测的结果。
//
// Err 非空表示没探到，此时 IP 为空。失败是常态（机器可能就没外网），
// 所以它不是 error 返回值而是结果里的一个字段 —— 调用方拿到后自己决定
// 是弹提示还是静默，不该因为"检测不到"把整个请求变成 500。
type Result struct {
	IP        string    `json:"ip"`
	Source    string    `json:"source"`
	CheckedAt time.Time `json:"checked_at"`
	Err       string    `json:"error,omitempty"`
}

// Ok 判断这次探测是否拿到了地址。
func (r *Result) Ok() bool { return r != nil && r.IP != "" }

// Resolver 带缓存的探测器，并发安全。
type Resolver struct {
	mu     sync.Mutex
	srcs   []Source
	client *http.Client
	ttl    time.Duration
	cached *Result
}

// Option 用于替换默认行为（测试里换成 httptest 服务）。
type Option func(*Resolver)

// WithSources 换掉回显服务清单。
func WithSources(srcs []Source) Option { return func(r *Resolver) { r.srcs = srcs } }

// WithClient 换掉 HTTP 客户端。
func WithClient(c *http.Client) Option { return func(r *Resolver) { r.client = c } }

// WithTTL 换掉缓存时长，传 0 或负值表示不缓存。
func WithTTL(d time.Duration) Option { return func(r *Resolver) { r.ttl = d } }

// New 创建探测器。
func New(opts ...Option) *Resolver {
	r := &Resolver{
		srcs: DefaultSources(),
		ttl:  cacheTTL,
		client: &http.Client{
			Timeout: probeTimeout,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout: 5 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   5 * time.Second,
				ResponseHeaderTimeout: 5 * time.Second,
			},
		},
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Lookup 返回缓存内的结果，过期或 force 时重新探测。
//
// 探测失败**不保留**上一次的成功值：一个已经连不上的服务器地址，
// 拿旧值继续提示"加入白名单"是在误导，不如老实说没探到。
func (r *Resolver) Lookup(ctx context.Context, force bool) *Result {
	r.mu.Lock()
	defer r.mu.Unlock()

	// ttl <= 0 表示"不缓存"（测试与"每次都要真实值"的场景用）
	if !force && r.cached != nil && r.ttl > 0 && time.Since(r.cached.CheckedAt) < r.ttl {
		return r.cached
	}
	r.cached = r.probe(ctx)
	return r.cached
}

func (r *Resolver) probe(ctx context.Context) *Result {
	var lastErr string
	for _, s := range r.srcs {
		body, err := r.fetch(ctx, s.URL)
		if err != nil {
			lastErr = fmt.Sprintf("%s: %v", s.Name, err)
			continue
		}
		addr, ok := ParseIPv4(body)
		if !ok {
			lastErr = fmt.Sprintf("%s 的响应里没有公网 IPv4", s.Name)
			continue
		}
		return &Result{IP: addr.String(), Source: s.Name, CheckedAt: time.Now()}
	}
	if lastErr == "" {
		lastErr = "没有配置回显服务"
	}
	return &Result{CheckedAt: time.Now(), Err: lastErr}
}

func (r *Resolver) fetch(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// 状态码不对就没必要读 body 了，但要把响应里的东西丢掉免得连着复用出问题
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ipv4Re 捞文本里第一个长得像 IPv4 的串。
//
// 不按行解析、不认各家格式：回显服务有纯文本的、有 JSON 的、有整页 HTML 的，
// 为每种写一个解析器是维护负担，而且任一改版就会静默失效。取第一个合法且
// 是公网地址的串，对这几类响应都成立 —— 它们都把 IP 放在最前面。
var ipv4Re = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)

// ParseIPv4 从回显内容里取出公网 IPv4。
//
// 私有 / 环回 / 组播 / 链路本地这类地址一律不算：外部服务看见的应当是公网
// 地址，返回了内网地址说明响应不对（或这台机器真的在 NAT 后面），
// 让它落到下一个源去，而不是拿一个"看着像 IP 但没用"的值交差。
func ParseIPv4(body string) (netip.Addr, bool) {
	for _, m := range ipv4Re.FindAllString(body, -1) {
		addr, err := netip.ParseAddr(m)
		if err != nil || !addr.Is4() {
			continue
		}
		if !usable(addr) {
			continue
		}
		return addr, true
	}
	return netip.Addr{}, false
}

func usable(a netip.Addr) bool {
	return !(a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified() ||
		a.IsInterfaceLocalMulticast())
}

// IsPublicIPv4 判断字符串是不是一个公网 IPv4（给界面上手工填的地址用）。
func IsPublicIPv4(s string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || !addr.Is4() {
		return false
	}
	return usable(addr)
}
