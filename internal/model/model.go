package model

import (
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// ACL 名单类型
const (
	KindWhite = "white"
	KindBlack = "black"
)

// 封禁来源
const (
	SourceAuto   = "auto"   // 频次超阈值自动封禁
	SourceManual = "manual" // 人工封禁
	SourceGeoIP  = "geoip"  // 命中国家/地区封禁
	SourceSystem = "system" // 系统内置保护项
)

// 封禁状态
const (
	BanActive   = "active"
	BanExpired  = "expired"
	BanReleased = "released"
)

// 事件类别
//
// 关于 login_attempt / login_blocked 的划分：
// frps 在**鉴权之前**调用插件的 Login 回调，插件拿不到"密码/token 是否正确"。
// 所以这里区分的是"这次回调是否被本程序拦截"，而不是 frps 的鉴权结果。
// 频次统计因此是"登录尝试频次"，对暴力破解场景效果一致。
const (
	EvtLoginAttempt = "login_attempt" // Login 回调，已放行
	EvtLoginBlocked = "login_blocked" // Login 回调，被本程序拦截
	EvtUserConn     = "user_conn"     // NewUserConn 回调
	EvtBan          = "ban"
	EvtUnban        = "unban"
	EvtRuleChange   = "rule_change"
	EvtConfig       = "config"
	EvtGeoIP        = "geoip"
	EvtAuth         = "auth"
)

// ACLEntry 黑白名单条目。黑白名单共用一张表，用 Kind 区分。
type ACLEntry struct {
	ID         uint       `gorm:"primaryKey" json:"id"`
	Kind       string     `gorm:"uniqueIndex:uk_kind_target;size:8;not null" json:"kind"`
	Target     string     `gorm:"uniqueIndex:uk_kind_target;size:64;not null" json:"target"`
	TargetType string     `gorm:"size:8;not null" json:"target_type"` // ipv4 | ipv6 | cidr4 | cidr6
	Remark     string     `gorm:"size:255" json:"remark"`
	Source     string     `gorm:"size:16;not null;default:manual" json:"source"`
	Country    string     `gorm:"size:64" json:"country"`
	Province   string     `gorm:"size:64" json:"province"`
	ExpiresAt  *time.Time `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// BanRecord 封禁记录。自动封禁、手动封禁、GeoIP 封禁统一进这张表，用 Source 区分。
type BanRecord struct {
	ID          uint       `gorm:"primaryKey" json:"id"`
	Target      string     `gorm:"index;size:64;not null" json:"target"`
	TargetType  string     `gorm:"size:8;not null" json:"target_type"`
	Reason      string     `gorm:"size:255" json:"reason"`
	Source      string     `gorm:"index;size:16;not null" json:"source"`
	TriggerUser string     `gorm:"size:64" json:"trigger_user"`
	HitCount    int        `gorm:"default:1" json:"hit_count"`
	Country     string     `gorm:"size:64" json:"country"`
	Province    string     `gorm:"size:64" json:"province"`
	Status      string     `gorm:"index;size:16;not null" json:"status"`
	BannedAt    time.Time  `json:"banned_at"`
	ExpiresAt   *time.Time `gorm:"index" json:"expires_at"`
	ReleasedAt  *time.Time `json:"released_at"`
	ReleasedBy  string     `gorm:"size:64" json:"released_by"`
}

// Permanent 表示永久封禁（ExpiresAt 为空）。
func (b *BanRecord) Permanent() bool { return b.ExpiresAt == nil }

// TargetAddr 从 Target 里取出纯 IP 字符串。
// 滑动窗口计数始终按单个来源 IP 统计，不跟随封禁粒度，
// 所以需要这个转换来对齐两边的 key。
func (b *BanRecord) TargetAddr() string {
	if p, err := netip.ParsePrefix(b.Target); err == nil {
		return p.Addr().String()
	}
	if a, err := netip.ParseAddr(b.Target); err == nil {
		return a.String()
	}
	return b.Target
}

// Remaining 返回剩余封禁时长；永久封禁返回 -1，已到期返回 0。
func (b *BanRecord) Remaining(now time.Time) time.Duration {
	if b.ExpiresAt == nil {
		return -1
	}
	d := b.ExpiresAt.Sub(now)
	if d < 0 {
		return 0
	}
	return d
}

// Policy 是运行期策略，单行记录（ID 恒为 1），前端可随时修改并即时生效。
type Policy struct {
	ID uint `gorm:"primaryKey" json:"id"`

	// 滑动窗口：WindowSeconds 秒内失败达到 Threshold 次即触发封禁。
	WindowSeconds int `gorm:"not null;default:60" json:"window_seconds"`
	Threshold     int `gorm:"not null;default:10" json:"threshold"`

	// BanDurations 阶梯封禁时长（秒），逗号分隔，按顺序递增使用。
	// 0 表示永久。例："600,3600,86400,0" = 10分钟 → 1小时 → 1天 → 永久。
	BanDurations string `gorm:"not null" json:"ban_durations"`
	// EscalateWindowHours 阶梯升级的统计窗口：这么久之内再次触发才升级。
	EscalateWindowHours int `gorm:"not null;default:24" json:"escalate_window_hours"`

	// BanGranularity 封禁粒度：ip | cidr24
	BanGranularity string `gorm:"size:8;not null;default:ip" json:"ban_granularity"`

	// FailMode 插件异常时的策略：open（放行，默认）| close（拒绝）
	FailMode string `gorm:"size:8;not null;default:open" json:"fail_mode"`

	AutoBanEnabled bool `gorm:"not null;default:true" json:"auto_ban_enabled"`
	// ObserveOnly 观察模式：照常记录并统计，但不真正封禁，用于上线初期试阈值。
	ObserveOnly bool `gorm:"not null;default:false" json:"observe_only"`

	GeoIPBlockEnabled   bool   `gorm:"not null;default:false" json:"geoip_block_enabled"`
	GeoIPBlockCountries string `gorm:"size:2048;not null;default:''" json:"geoip_block_countries"`
	// GeoIPMode blacklist = 拒绝列表内国家；whitelist = 只允许列表内国家
	GeoIPMode string `gorm:"size:16;not null;default:blacklist" json:"geoip_mode"`

	RateLimitEnabled   bool `gorm:"not null;default:false" json:"rate_limit_enabled"`
	RateLimitPerSec    int  `gorm:"not null;default:20" json:"rate_limit_per_sec"`
	RateLimitBurst     int  `gorm:"not null;default:40" json:"rate_limit_burst"`

	UpdatedAt time.Time `json:"updated_at"`
}

// CountryList 把逗号分隔的国家码拆成切片（已大写、去空）。
func (p *Policy) CountryList() []string {
	out := make([]string, 0, 8)
	for _, s := range strings.Split(p.GeoIPBlockCountries, ",") {
		s = strings.ToUpper(strings.TrimSpace(s))
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// DurationSteps 解析阶梯时长。
func (p *Policy) DurationSteps() []int64 {
	out := make([]int64, 0, 4)
	for _, s := range strings.Split(p.BanDurations, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		v, err := strconv.ParseInt(s, 10, 64)
		if err == nil && v >= 0 {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		out = []int64{600}
	}
	return out
}

// Event 事件审计。登录失败、封禁、解封、规则变更全量留痕。
type Event struct {
	ID       uint      `gorm:"primaryKey" json:"id"`
	Ts       time.Time `gorm:"index:idx_event_ts;not null" json:"ts"`
	Category string    `gorm:"index;size:32;not null" json:"category"`
	IP       string    `gorm:"index;size:64" json:"ip"`
	Country  string    `gorm:"size:64" json:"country"`
	Province string    `gorm:"size:64" json:"province"`
	User     string    `gorm:"size:64" json:"user"`
	Op       string    `gorm:"size:32" json:"op"`
	Detail   string    `gorm:"size:1024" json:"detail"`
	Actor    string    `gorm:"size:64" json:"actor"`
}

// RuleChange 防火墙规则变更审计。
type RuleChange struct {
	ID      uint      `gorm:"primaryKey" json:"id"`
	Ts      time.Time `gorm:"index;not null" json:"ts"`
	Backend string    `gorm:"size:16;not null" json:"backend"`
	Action  string    `gorm:"size:48;not null" json:"action"`
	Payload string    `gorm:"type:text" json:"payload"`
	Result  string    `gorm:"size:16;not null" json:"result"`
	Error   string    `gorm:"size:512" json:"error"`
}

// FirewallProfile 防火墙后端偏好与探测结果，单行记录。
type FirewallProfile struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	Preferred  string    `gorm:"size:16;not null;default:auto" json:"preferred"`
	Detected   string    `gorm:"size:16" json:"detected"`
	DetectedAt time.Time `json:"detected_at"`
	Detail     string    `gorm:"type:text" json:"detail"`
}

// Setting 是键值配置表，同时承载面板配置（cfg.*）、面板凭据与密钥。
type Setting struct {
	Key       string    `gorm:"primaryKey;size:64" json:"key"`
	Value     string    `gorm:"type:text" json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

// 已知的 setting key。
const (
	SettingPasswordHash = "admin_password_hash"
	SettingUsername     = "admin_username"
)

// TargetTypeOf 判断一个 IP/CIDR 字符串的类型。
func TargetTypeOf(s string) string {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return "invalid"
		}
		if p.Addr().Is4() {
			return "cidr4"
		}
		return "cidr6"
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "invalid"
	}
	if a.Is4() {
		return "ipv4"
	}
	return "ipv6"
}

// PackageCountries 把国家码切片序列化成存储格式。
func PackageCountries(codes []string) string {
	seen := make(map[string]struct{}, len(codes))
	out := make([]string, 0, len(codes))
	for _, c := range codes {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return strings.Join(out, ",")
}
