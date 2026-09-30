package config

import (
	"crypto/subtle"
	"strconv"
	"strings"

	"github.com/dreamstation625/FrpFireWall/internal/model"
)

// KV 是配置持久化所需的最小接口，由 store.Store 实现。
type KV interface {
	GetSetting(key string) (string, error)
	SetSetting(key, value string) error
}

// 配置项在 settings 表里的键名。
// 加 cfg. 前缀，和 admin_password_hash 这类运行期凭据区分开。
const (
	KeyBackend        = "cfg.backend"
	KeyServerListen   = "cfg.server.listen"
	KeyTLSEnabled     = "cfg.server.tls.enabled"
	KeyTLSCertFile    = "cfg.server.tls.cert_file"
	KeyTLSKeyFile     = "cfg.server.tls.key_file"
	KeyAuthUsername   = "cfg.server.auth.username"
	KeyTokenTTLHours  = "cfg.server.auth.token_ttl_hours"
	KeyPluginListen   = "cfg.frps.plugin_listen"
	KeyPluginPath     = "cfg.frps.plugin_path"
	KeyBindPort       = "cfg.frps.bind_port"
	KeyProxyPorts     = "cfg.frps.proxy_ports"
	KeyTrustedProxies = "cfg.frps.trusted_proxies"
	KeyGuardEnabled   = "cfg.guard.enabled"
	KeyGuardDryRun    = "cfg.guard.dry_run"
	KeyLogLevel       = "cfg.log.level"
	KeyLogFile        = "cfg.log.file"

	// KeyJWTSecret 是面板 token 的签名密钥，自动生成，不对外暴露。
	KeyJWTSecret = "jwt_secret"
	// KeySetupToken 是首次设置密码用的一次性令牌，密码设置完成后立即删除。
	KeySetupToken = "setup_token"
)

// ToSettings 把配置摊平成键值对，用于写入数据库。
func (c *Config) ToSettings() map[string]string {
	return map[string]string{
		KeyBackend:        c.Backend,
		KeyServerListen:   c.Server.Listen,
		KeyTLSEnabled:     strconv.FormatBool(c.Server.TLS.Enabled),
		KeyTLSCertFile:    c.Server.TLS.CertFile,
		KeyTLSKeyFile:     c.Server.TLS.KeyFile,
		KeyAuthUsername:   c.Server.Auth.Username,
		KeyTokenTTLHours:  strconv.Itoa(c.Server.Auth.TokenTTLHours),
		KeyPluginListen:   c.Frps.PluginListen,
		KeyPluginPath:     c.Frps.PluginPath,
		KeyBindPort:       strconv.Itoa(c.Frps.BindPort),
		KeyProxyPorts:     intsToCSV(c.Frps.ProxyPorts),
		KeyTrustedProxies: strings.Join(c.Frps.TrustedProxies, ","),
		KeyGuardEnabled:   strconv.FormatBool(c.Guard.Enabled),
		KeyGuardDryRun:    strconv.FormatBool(c.Guard.DryRun),
		KeyLogLevel:       c.Log.Level,
		KeyLogFile:        c.Log.File,
	}
}

// FromSettings 从键值对还原配置。缺失或非法的项回落到默认值，
// 这样后续版本新增配置项时不需要写迁移脚本。
func FromSettings(m map[string]string) (*Config, error) {
	c := Default()

	if v := strings.TrimSpace(m[KeyBackend]); v != "" {
		c.Backend = v
	}
	if v := strings.TrimSpace(m[KeyServerListen]); v != "" {
		c.Server.Listen = v
	}
	c.Server.TLS.Enabled = parseBool(m[KeyTLSEnabled], c.Server.TLS.Enabled)
	c.Server.TLS.CertFile = m[KeyTLSCertFile]
	c.Server.TLS.KeyFile = m[KeyTLSKeyFile]
	if v := strings.TrimSpace(m[KeyAuthUsername]); v != "" {
		c.Server.Auth.Username = v
	}
	if v := parseInt(m[KeyTokenTTLHours], 0); v > 0 {
		c.Server.Auth.TokenTTLHours = v
	}
	if v := strings.TrimSpace(m[KeyPluginListen]); v != "" {
		c.Frps.PluginListen = v
	}
	if v := strings.TrimSpace(m[KeyPluginPath]); v != "" {
		c.Frps.PluginPath = v
	}
	if v := parseInt(m[KeyBindPort], 0); v > 0 {
		c.Frps.BindPort = v
	}
	if v := m[KeyProxyPorts]; strings.TrimSpace(v) != "" {
		c.Frps.ProxyPorts = csvToInts(v)
	}
	if v := m[KeyTrustedProxies]; strings.TrimSpace(v) != "" {
		c.Frps.TrustedProxies = strings.Split(v, ",")
	}
	c.Guard.Enabled = parseBool(m[KeyGuardEnabled], c.Guard.Enabled)
	c.Guard.DryRun = parseBool(m[KeyGuardDryRun], c.Guard.DryRun)
	if v := strings.TrimSpace(m[KeyLogLevel]); v != "" {
		c.Log.Level = v
	}
	c.Log.File = m[KeyLogFile]

	if err := c.normalize(); err != nil {
		return nil, err
	}
	return c, nil
}

// EnsureJWTSecret 保证存在一个稳定的 JWT 密钥。
// 密钥放在数据库里，重启不会把已登录的用户踢下线。
func EnsureJWTSecret(kv KV) (string, error) {
	if v, err := kv.GetSetting(KeyJWTSecret); err == nil && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v), nil
	}
	s, err := randomSecret(32)
	if err != nil {
		return "", err
	}
	if err := kv.SetSetting(KeyJWTSecret, s); err != nil {
		return "", err
	}
	return s, nil
}

// EnsureSetupToken 在尚未设置面板密码时返回初始化令牌。
// 已设置密码则返回空串，表示无需初始化。
func EnsureSetupToken(kv KV) (string, error) {
	if h, err := kv.GetSetting(model.SettingPasswordHash); err == nil && h != "" {
		return "", nil
	}
	if t, err := kv.GetSetting(KeySetupToken); err == nil && strings.TrimSpace(t) != "" {
		return strings.TrimSpace(t), nil
	}
	t, err := randomSecret(16)
	if err != nil {
		return "", err
	}
	if err := kv.SetSetting(KeySetupToken, t); err != nil {
		return "", err
	}
	return t, nil
}

// SetupTokenMatches 校验初始化令牌。密码一旦设置，令牌即失效。
func SetupTokenMatches(kv KV, token string) bool {
	if h, err := kv.GetSetting(model.SettingPasswordHash); err == nil && h != "" {
		return false
	}
	want, err := kv.GetSetting(KeySetupToken)
	if err != nil || strings.TrimSpace(want) == "" {
		return false
	}
	return subtleEqual(strings.TrimSpace(want), strings.TrimSpace(token))
}

// ClearSetupToken 在密码设置完成后清除令牌。
func ClearSetupToken(kv KV) error {
	return kv.SetSetting(KeySetupToken, "")
}

// subtleEqual 定长比较，避免用耗时差把令牌逐位试出来。
func subtleEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func parseBool(v string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	}
	return def
}

func parseInt(v string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return n
}

func intsToCSV(in []int) string {
	parts := make([]string, 0, len(in))
	for _, n := range in {
		parts = append(parts, strconv.Itoa(n))
	}
	return strings.Join(parts, ",")
}

func csvToInts(s string) []int {
	out := make([]int, 0, 8)
	for _, p := range strings.Split(s, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil && n > 0 && n < 65536 {
			out = append(out, n)
		}
	}
	return out
}
