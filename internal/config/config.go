package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/dreamstation625/FrpFireWall/internal/version"
)

// Config 是运行期配置。
//
// 配置统一持久化在数据目录的 SQLite（settings 表）里，不依赖外部配置文件，
// 唯一必须从命令行给出的只有数据目录本身（否则找不到数据库）。
// 运行期可变的策略（滑窗阈值、封禁时长、黑白名单、GeoIP 国家等）另存在各自的表。
type Config struct {
	// DataDir 数据目录，存放 SQLite 与属地库文件。只读，不从配置接口修改。
	DataDir string `json:"data_dir"`

	// Backend 防火墙后端的初始偏好：auto | iptables | nftables。
	// 界面切换后端会写入 firewall_profiles 表，运行期以那张表为准。
	Backend string `json:"backend"`

	Server ServerConfig `json:"server"`
	Frps   FrpsConfig   `json:"frps"`
	Guard  GuardConfig  `json:"guard"`
	Log    LogConfig    `json:"log"`
	Update UpdateConfig `json:"update"`
}

type ServerConfig struct {
	// Listen 面板监听地址。
	//
	// 默认 0.0.0.0:7930。面板是装在那台被防火墙保护的机器上的，运维多半
	// 要换台机器打开它，只绑回环等于装完就用不了 —— 一键脚本装完打不开
	// 面板，排查半天发现是监听地址，这个代价比"默认少暴露一个端口"大。
	//
	// 关掉对外访问改成 127.0.0.1:7930（或某个内网地址），但要自己解决
	// 怎么访问它，比如 SSH 隧道 ssh -L 7930:127.0.0.1:7930 root@<服务器>。
	//
	// 对外可达时，安全只剩两道：一次性初始化令牌（防别人抢先设密码）
	// 与登录防爆破。密码走的是明文 HTTP，所以务必在面板里开启 TLS。
	Listen string    `json:"listen"`
	TLS    TLSConfig `json:"tls"`
	Auth   AuthConfig `json:"auth"`
}

type TLSConfig struct {
	// Enabled 为 true 时用 cert/key 起 HTTPS。
	// 面板对外网开放时建议开启，否则密码是明文传输。
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

type AuthConfig struct {
	Username string `json:"username"`
	// TokenTTLHours 是登录 token 的有效期。
	TokenTTLHours int `json:"token_ttl_hours"`
}

type FrpsConfig struct {
	// PluginListen 插件服务监听地址。只允许回环，frps 与本进程同机。
	PluginListen string `json:"plugin_listen"`
	// PluginPath 是 frps httpPlugins 里配置的 path。
	PluginPath string `json:"plugin_path"`
	// BindPort 是 frps 的 bindPort，用于下发连接速率限制规则。
	BindPort int `json:"bind_port"`
	// ProxyPorts 是代理对外暴露的端口，用于 NewUserConn 阶段判定的覆盖范围。
	ProxyPorts []int `json:"proxy_ports"`
	// TrustedProxies 是可信反代/CDN 回源网段（CIDR）。
	// 来自这些网段的 NewUserConn 不按 remote_addr 封禁，
	// 而是优先取 X-Forwarded-For 里的真实客户端 IP，避免封到 CDN 节点。
	TrustedProxies []string `json:"trusted_proxies"`
}

type GuardConfig struct {
	// Enabled 为 false 时本进程只做展示和插件判定，不往防火墙写任何规则。
	Enabled bool `json:"enabled"`
	// DryRun 观察模式：照常记录命中和封禁决策，但不真正下发规则。
	DryRun bool `json:"dry_run"`
}

type LogConfig struct {
	Level string `json:"level"`
	File  string `json:"file"`
}

// UpdateConfig 控制面板的版本更新检查。
type UpdateConfig struct {
	// Enabled 为 false 时完全不做在线检查。纯内网或不允许出网的服务器可关掉，
	// 面板仍会显示当前版本号并提供发布页链接。
	Enabled bool `json:"enabled"`
	// Repo 是用于检查发布的 GitHub 仓库，格式 owner/name。
	Repo string `json:"repo"`
}

// DefaultListen 是面板的默认监听地址。
//
// 抽成常量是因为它出现在两处：Default() 与 normalize() 的空值兜底。
// 两处写得不一致会出现「首次启动写 0.0.0.0，配置被清空后又变回
// 127.0.0.1」这种查起来很费劲的行为。
const DefaultListen = "0.0.0.0:7930"

// Default 返回一份可用的默认配置。
func Default() *Config {
	return &Config{
		DataDir: "./data",
		Backend: "auto",
		Server: ServerConfig{
			Listen: DefaultListen,
			TLS:    TLSConfig{Enabled: false},
			Auth: AuthConfig{
				Username:      "admin",
				TokenTTLHours: 12,
			},
		},
		Frps: FrpsConfig{
			PluginListen: "127.0.0.1:9100",
			PluginPath:   "/frps/handler",
			BindPort:     7000,
			ProxyPorts:   []int{80, 443},
		},
		Guard: GuardConfig{
			Enabled: true,
			DryRun:  false,
		},
		Log: LogConfig{
			Level: "info",
		},
		Update: UpdateConfig{
			Enabled: true,
			Repo:    version.DefaultRepo,
		},
	}
}

func (c *Config) normalize() error {
	if c.DataDir == "" {
		c.DataDir = "./data"
	}
	c.DataDir = filepath.Clean(c.DataDir)

	if c.Server.Listen == "" {
		c.Server.Listen = DefaultListen
	}
	if c.Server.Auth.Username == "" {
		c.Server.Auth.Username = "admin"
	}
	if c.Server.Auth.TokenTTLHours <= 0 {
		c.Server.Auth.TokenTTLHours = 12
	}
	if c.Frps.PluginListen == "" {
		c.Frps.PluginListen = "127.0.0.1:9100"
	}
	if c.Frps.PluginPath == "" {
		c.Frps.PluginPath = "/frps/handler"
	}
	// 插件服务必须绑回环：它没有独立鉴权，靠"只接受本机 frps 调用"来兜底。
	if !isLoopback(c.Frps.PluginListen) {
		return fmt.Errorf("frps 插件监听地址必须是回环地址（当前 %q），插件接口不能对外暴露", c.Frps.PluginListen)
	}
	if c.Frps.BindPort == 0 {
		c.Frps.BindPort = 7000
	}

	// 可信回源网段写错会静默失效（拿不到真实客户端 IP 就会封到 CDN 节点），
	// 所以这里直接拒绝非法 CIDR，而不是放过。
	cleaned := make([]string, 0, len(c.Frps.TrustedProxies))
	for _, s := range c.Frps.TrustedProxies {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, err := netip.ParsePrefix(s); err != nil {
			return fmt.Errorf("可信回源网段 %q 不是合法的 CIDR", s)
		}
		cleaned = append(cleaned, s)
	}
	c.Frps.TrustedProxies = cleaned

	switch c.Backend {
	case "", "auto", "iptables", "nftables":
	default:
		return fmt.Errorf("防火墙后端只能是 auto/iptables/nftables，当前 %q", c.Backend)
	}

	if c.Server.TLS.Enabled {
		if c.Server.TLS.CertFile == "" || c.Server.TLS.KeyFile == "" {
			return fmt.Errorf("启用 HTTPS 时必须同时填写证书与私钥路径")
		}
	}

	if c.Update.Repo == "" {
		c.Update.Repo = version.DefaultRepo
	}
	if err := validateRepoSlug(c.Update.Repo); err != nil {
		return err
	}
	return nil
}

// validateRepoSlug 校验 owner/name 形态的仓库标识。
//
// 这个值会被拼进 https://api.github.com/repos/{repo}/releases，
// 必须严格限制字符集，避免用户输入把请求引到别的路径上去。
func validateRepoSlug(s string) error {
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return fmt.Errorf("更新检查仓库 %q 应形如 owner/name", s)
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return fmt.Errorf("更新检查仓库 %q 的 owner 与 name 都不能为空", s)
		}
		for _, r := range p {
			switch {
			case r >= 'a' && r <= 'z',
				r >= 'A' && r <= 'Z',
				r >= '0' && r <= '9',
				r == '-', r == '_', r == '.':
			default:
				return fmt.Errorf("更新检查仓库 %q 含非法字符 %q", s, string(r))
			}
		}
	}
	return nil
}

// Validate 供配置写入前调用，保证入库的都是可用值。
func (c *Config) Validate() error { return c.normalize() }

func isLoopback(addr string) bool {
	host := addr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		host = addr[:i]
	}
	host = strings.Trim(host, "[]")
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

// randomSecret 生成 n 位的 URL 安全随机串。
func randomSecret(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	s := base64.RawURLEncoding.EncodeToString(buf)
	if len(s) > n {
		s = s[:n]
	}
	return s, nil
}

