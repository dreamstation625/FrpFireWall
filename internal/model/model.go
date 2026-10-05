package model

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/portrange"
)

// ACL 名单类型
const (
	KindWhite = "white"
	KindBlack = "black"
)

// 封禁范围：一个地址被封住之后，到底挡掉它多少访问。
//
// 这个维度是必要的，因为内核层的黑名单规则默认不带端口限定 —— 封一个 IP
// 等于让整台机器对它静默，SSH、面板、其它服务一起挡。多数时候这正是想要的；
// 但当这个 IP 同时还有别的用途（合作方出口、监控节点、运维自己的跳板），
// 就需要一个"只挡住它连 frp、其它照常"的中间档。
const (
	// ScopeAll 全端口：该地址到本机任意端口的入站全部丢弃。
	ScopeAll = "all"
	// ScopeFrp 仅 frp 端口：只丢弃 frp 服务端口（bindPort + proxyPorts）上的入站。
	//
	// 端口来自全局的受保护端口集合（见 DESIGN §4.6），条目自己不写端口。
	ScopeFrp = "frp"
	// ScopeCustom 自定义端口：只丢弃该条目 Ports 里列出的那些目的端口。
	//
	// 和 ScopeFrp 是两个方向：ScopeFrp 回答"别碰 frp 之外的东西"（端口由全局
	// 配置算出来），ScopeCustom 回答"只动这几个端口"（端口随条目走）。
	// 后者才是"既要限制这个地址访问某个服务、又不想把它的 frp 一起掐了"的落点 ——
	// 拿 ScopeFrp 做不到这件事，它的端口集合是全局的，改它等于改所有条目。
	//
	// 注意插件层（frps 的 Login / NewUserConn 回调）拿不到被访问的端口，所以
	// 自定义端口只作用于内核规则，不影响"这个地址能不能登录 frp" —— 见 D19。
	ScopeCustom = "custom"
)

// ValidScope 判断范围取值是否合法。
func ValidScope(s string) bool {
	return s == ScopeAll || s == ScopeFrp || s == ScopeCustom
}

// ScopeNeedsPorts 判断该范围是否必须带端口列表。
//
// 单独一个判断函数而不是在调用处写 `scope == ScopeCustom`：范围与"要不要端口"
// 的关系是同一个概念的两面，散在各处迟早出现"某个入口放过了没端口的 custom"。
func ScopeNeedsPorts(scope string) bool { return scope == ScopeCustom }

// ParseCustomPorts 解析自定义端口列表，返回规范化后的集合。
//
// 空列表**不是**错误被吞掉而是明确报错：范围选了自定义却一个端口都没填，
// 落到内核上就是"一条规则都生成不出来"，表现成界面上封着、实际什么都没封。
func ParseCustomPorts(ports string) (portrange.Set, error) {
	ps, err := portrange.Parse(ports)
	if err != nil {
		return nil, err
	}
	if len(ps) == 0 {
		return nil, fmt.Errorf("自定义端口不能为空：写单个端口（8080）或区间（9000-9100），多个用逗号分隔")
	}
	return ps, nil
}

// 封禁来源
const (
	SourceAuto   = "auto"   // 频次超阈值自动封禁
	SourceManual = "manual" // 人工封禁
	SourceGeoIP  = "geoip"  // 命中国家/地区封禁
	SourceSystem = "system" // 系统内置保护项
	// SourceRule 细分规则的「命中即拦截」。
	//
	// 与 SourceAuto 分开：那一个说的是"次数攒够了"，这一个说的是"条件对上了"，
	// 界面上要分别显示，排障时也要一眼看出是"他来得太频繁"还是"他就是那个
	// 地区的人"。
	SourceRule = "rule"
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
	ID         uint   `gorm:"primaryKey" json:"id"`
	Kind       string `gorm:"uniqueIndex:uk_kind_target;size:8;not null" json:"kind"`
	Target     string `gorm:"uniqueIndex:uk_kind_target;size:64;not null" json:"target"`
	TargetType string `gorm:"size:8;not null" json:"target_type"` // ipv4 | ipv6 | cidr4 | cidr6
	// Scope 封禁范围（all | frp | custom）。只对黑名单有意义，白名单恒为 all。
	// 默认 all 是有意为之：升级上来的存量条目保持原来的"全端口"行为，
	// 不能因为加了这个字段就悄悄把别人原本封死的东西变松。
	Scope string `gorm:"size:8;not null;default:all" json:"scope"`
	// Ports 是 ScopeCustom 下要封的目的端口，区间写法，如 "8080,9000-9100"。
	//
	// 只在 scope=custom 时有值：换成别的范围时接口层会把它清空。留一个不参与
	// 生效的值在库里，等于制造"配置里写着、实际不生效"的陷阱 —— 这种错在界面上
	// 完全看不出来，只有去数内核规则条数才会发现。
	Ports  string `gorm:"size:512;not null;default:''" json:"ports"`
	Remark string `gorm:"size:255" json:"remark"`
	// Enabled 条目是否启用。停用的条目不参与判定、不产生内核规则，但保留在
	// 名单里（列表可见、可再启用）。
	//
	// 必须带 default:true：AutoMigrate 给存量行补这一列时，SQLite 的 NOT NULL
	// 列没有默认值加不上去，而存量行必须是"启用"（升级不能悄悄放行原本封死的
	// 地址）。代价是 GORM 的零值坑反过来咬——插入 Enabled=false 的结构体时该列
	// 会被省略、落库成 true（RateRule.Enabled 不加 default 就是这个原因）。
	// 这里接受这个代价，因为约定**所有创建路径都写 Enabled=true**：界面新建、
	// 导入、批量添加都没有"建出来就是停用"的入口，停用只能事后切换。
	Enabled   bool       `gorm:"not null;default:true" json:"enabled"`
	Source    string     `gorm:"size:16;not null;default:manual" json:"source"`
	Country   string     `gorm:"size:64" json:"country"`
	Province  string     `gorm:"size:64" json:"province"`
	ExpiresAt *time.Time `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// BanRecord 封禁记录。自动封禁、手动封禁、GeoIP 封禁统一进这张表，用 Source 区分。
type BanRecord struct {
	ID         uint   `gorm:"primaryKey" json:"id"`
	Target     string `gorm:"index;size:64;not null" json:"target"`
	TargetType string `gorm:"size:8;not null" json:"target_type"`
	// Scope 封禁范围（all | frp | custom），与 ACLEntry 同义。默认 all。
	Scope string `gorm:"size:8;not null;default:all" json:"scope"`
	// Ports 是 ScopeCustom 下要封的目的端口，与 ACLEntry 同义。默认空。
	Ports  string `gorm:"size:512;not null;default:''" json:"ports"`
	Reason string `gorm:"size:255" json:"reason"`
	Source string `gorm:"index;size:16;not null" json:"source"`
	// SourceRef 是触发这条封禁的来源引用，形如 "acl:12" / "rule:5"。
	// 按频次自动封禁、人工封禁、系统保护项都为空。
	//
	// 为什么需要它：来源条目被删除或停用时，由它封掉的地址应当一起解封 ——
	// 否则"删掉了一条名单，被它封的地址还是进不来"，而界面上已经看不到那条
	// 名单了，用户只能去封禁列表里一个个手点。反过来，手动解封一个地址时也要
	// 能顺着它找到"是哪条条目把它挡在外面的"：找不到的话，解禁当场生效、
	// 下次连接又被同一条条目挡回去，用户看到的是"解禁没起作用"。
	//
	// 用文本引用而不是两个可空外键列：来源目前只有"名单条目"和"细分规则"两种，
	// 每加一种来源就要加一列的话，查询和迁移都会跟着长；而查它只需要一次等值
	// 比较。解析与拼装集中在 BanSourceRef / ParseBanSourceRef。
	SourceRef   string     `gorm:"index;size:32;not null;default:''" json:"source_ref"`
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

// 封禁来源引用的类型前缀。
const (
	// BanRefACL 来源是黑白名单条目（地区条目命中即封禁走的就是这条路）。
	BanRefACL = "acl"
	// BanRefRule 来源是一条细分规则（命中即拦截）。
	BanRefRule = "rule"
)

// BanSourceRef 拼一条来源引用。
//
// id 是**名单条目**的自增主键。细分规则那条路不走这里 —— 它的引用是内容签名
// （见 RateRule.BanRef），所以用 BanRefRule 前缀自行拼接，形态上是同一个
// "类型:标识"协议，标识的取值规则由类型决定。
func BanSourceRef(kind string, id uint) string {
	if kind == "" || id == 0 {
		return ""
	}
	return kind + ":" + strconv.FormatUint(uint64(id), 10)
}

// ParseBanSourceRef 拆解来源引用，返回来源类型与 ID。
// 空串、格式不对、ID 非正数一律返回 ok=false —— 调用方据此跳过联动处理，
// 而不是拿一个零值 ID 去删东西。
//
// 只认十进制 ID，也就是**只适用于名单条目那类引用**。规则引用里的标识是
// 十六进制内容签名，解析不出来，这里会返回 ok=false —— 想判断来源类型请用
// BanSourceRefKind，别拿这个函数的成败去推。
func ParseBanSourceRef(ref string) (kind string, id uint, ok bool) {
	kind = BanSourceRefKind(ref)
	if kind == "" {
		return "", 0, false
	}
	n, err := strconv.ParseUint(ref[strings.LastIndex(ref, ":")+1:], 10, 64)
	if err != nil || n == 0 {
		return "", 0, false
	}
	return kind, uint(n), true
}

// BanSourceRefKind 取出引用里的来源类型（"acl" / "rule"），取不到返回空串。
//
// 单独一个函数、不并进 ParseBanSourceRef：两者的**标识形态不同** —— 名单条目
// 是自增主键（十进制），细分规则是内容签名（十六进制哈希，见 RateRule.BanRef）。
// 让 ParseBanSourceRef 也接受任意字符串的话，"acl:zzz" 这种明显坏掉的引用会被
// 静默收下，调用方再去 GetACL(0) 查出一个不存在的条目。
//
// 所以分工是：先问 Kind 决定走哪条分支，需要 ID 的那一支再调 ParseBanSourceRef。
// 这样"判断来源类型"就不会被"ID 能不能解析"绑架 —— 这个坑真踩过：规则引用
// "rule:466972c4" 解析不出十进制 ID，于是调用方在第一步就返回了，那句
// "该地址由细分规则拦截、解禁后还会被拦"的提示从来没出现过。
//
// 按**最后一个**冒号切：类型名里不会有冒号，但标识将来若要带自己的分隔符
// （比如 "rule:2:abc"），切最后一个才不会把类型切出一截来。
func BanSourceRefKind(ref string) string {
	ref = strings.TrimSpace(ref)
	i := strings.LastIndex(ref, ":")
	if i <= 0 {
		return ""
	}
	return ref[:i]
}

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

	RateLimitEnabled bool `gorm:"not null;default:false" json:"rate_limit_enabled"`
	RateLimitPerSec  int  `gorm:"not null;default:20" json:"rate_limit_per_sec"`
	RateLimitBurst   int  `gorm:"not null;default:40" json:"rate_limit_burst"`

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
	ID        uint      `gorm:"primaryKey" json:"id"`
	Ts        time.Time `gorm:"index:idx_event_ts;not null" json:"ts"`
	Category  string    `gorm:"index;size:32;not null" json:"category"`
	IP        string    `gorm:"index;size:64" json:"ip"`
	Country   string    `gorm:"size:64" json:"country"`
	Province  string    `gorm:"size:64" json:"province"`
	User      string    `gorm:"size:64" json:"user"`
	ProxyName string    `gorm:"size:128;index" json:"proxy_name"`
	Op        string    `gorm:"size:32" json:"op"`
	Detail    string    `gorm:"size:1024" json:"detail"`
	Actor     string    `gorm:"size:64" json:"actor"`
}

// CounterSample 一次采样里某条受管规则的丢包计数快照。
//
// 存它是为了两件事：画趋势图，以及算"最近一批新增多少"。计数本身来自内核、
// 规则重建就归零，所以表里存的是**一个个读数**而不是累加出来的总量 ——
// 总量由读的时候做差得出（差值为负说明这中间重建过规则，见 guard 的采样说明）。
//
// 一次采样写进来的所有行共用同一个 Ts，靠它把"同一批"区分开：查上一批就是
// 找小于当前 Ts 的最大 Ts，不需要额外的批次号字段。
type CounterSample struct {
	ID      uint      `gorm:"primaryKey" json:"id"`
	Ts      time.Time `gorm:"index:idx_cs_ts;not null" json:"ts"`
	Backend string    `gorm:"size:16;not null" json:"backend"`
	// Kind / Key / Family 与 firewall.RuleCounter 的三个字段一一对应，
	// 是这条计数在两次采样之间对得上的唯一凭据。
	Kind   string `gorm:"size:16;not null" json:"kind"`
	Key    string `gorm:"size:160;index:idx_cs_key;not null" json:"key"`
	Family string `gorm:"size:8" json:"family"`
	// Label 冗余存一份：它来自当次采样时的端口分组名，分组被改名或删掉之后，
	// 历史采样点仍要能说清自己是谁。
	Label   string `gorm:"size:128" json:"label"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
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
