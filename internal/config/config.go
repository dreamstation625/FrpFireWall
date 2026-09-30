package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
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
}

type ServerConfig struct {
	// Listen 面板监听地址。对外网开放时用 0.0.0.0:7930。
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

// Default 返回一份可用的默认配置。
func Default() *Config {
	return &Config{
		DataDir: "./data",
		Backend: "auto",
		Server: ServerConfig{
			Listen: "127.0.0.1:7930",
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
	}
}

func (c *Config) normalize() error {
	if c.DataDir == "" {
		c.DataDir = "./data"
	}
	c.DataDir = filepath.Clean(c.DataDir)

	if c.Server.Listen == "" {
		c.Server.Listen = "127.0.0.1:7930"
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

