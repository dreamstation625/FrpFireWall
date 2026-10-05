package guard

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/config"
	"github.com/dreamstation625/FrpFireWall/internal/firewall"
	"github.com/dreamstation625/FrpFireWall/internal/geoip"
	"github.com/dreamstation625/FrpFireWall/internal/model"
	"github.com/dreamstation625/FrpFireWall/internal/portrange"
	"github.com/dreamstation625/FrpFireWall/internal/store"
)

// banState 是一条活跃封禁的内存表示。内存里的这份是唯一权威，
// 防火墙规则只是它的投影，任何时候都能从内存重新生成。
type banState struct {
	Prefix netip.Prefix
	Target string
	// Scope 封禁范围（all | frp | custom）。自动封禁固定 all，手动封禁可指定。
	Scope string
	// Ports 只在 Scope == custom 时有值（见 blockTarget 的同名字段）。
	Ports  portrange.Set
	Reason string
	Source string
	// SourceRef 是触发这条封禁的来源引用（"acl:12" / "rule:5"），空表示
	// 频次自动封禁、人工封禁或全局地域名单。解禁时要顺着它决定"要不要
	// 连背后的名单条目一起清掉"（见 Manager.ReleaseBansByRef）。
	SourceRef string
	User      string
	RecordID  uint
	HitCount  int
	BannedAt  time.Time
	// Expires 为零值表示永久封禁。
	Expires  time.Time
	Country  string
	Province string
}

// Permanent 判断是否永久封禁。
func (b *banState) Permanent() bool { return b.Expires.IsZero() }

// Remaining 返回剩余时长；永久返回 -1，已过期返回 0。
func (b *banState) Remaining(now time.Time) time.Duration {
	if b.Expires.IsZero() {
		return -1
	}
	if d := b.Expires.Sub(now); d > 0 {
		return d
	}
	return 0
}

// BanView 是给前端的封禁视图。
type BanView struct {
	Target string `json:"target"`
	// Scope 封禁范围（all | frp | custom）。
	Scope string `json:"scope"`
	// Ports 是 scope=custom 时的端口文本，其余范围为空的。前端直接展示，
	// 不做结构转换 —— 与 RateRule.Ports 的口径一致。
	Ports  string `json:"ports"`
	Reason string `json:"reason"`
	Source string `json:"source"`
	// SourceRef 指向触发这条封禁的具体来源（"acl:12" / "rule:3a7f"），
	// 频次自动封禁与全局地域名单为空。前端用它判断"手动解封时要不要连带
	// 清掉背后那条名单条目"—— 只看 source 是不够的：同为名单来源的封禁里，
	// 也必须知道是哪一条才能说得清后果。
	SourceRef    string     `json:"source_ref"`
	User         string     `json:"user"`
	RecordID     uint       `json:"record_id"`
	HitCount     int        `json:"hit_count"`
	BannedAt     time.Time  `json:"banned_at"`
	ExpiresAt    *time.Time `json:"expires_at"`
	RemainingSec int64      `json:"remaining_sec"` // -1 表示永久
	Permanent    bool       `json:"permanent"`
	Country      string     `json:"country"`
	Province     string     `json:"province"`
}

// Stats 是引擎运行状态，供概览页展示。
type Stats struct {
	Enabled        bool   `json:"enabled"`
	DryRun         bool   `json:"dry_run"`
	Backend        string `json:"backend"`
	BackendOK      bool   `json:"backend_ok"`
	ActiveBans     int    `json:"active_bans"`
	WhiteCount     int    `json:"white_count"`
	BlackCount     int    `json:"black_count"`
	TrustedCount   int    `json:"trusted_count"`
	WindowsTracked int    `json:"windows_tracked"`
	// AppRuleCount / KernelRuleCount 是当前生效的细分规则条数，按落点分。
	AppRuleCount    int `json:"app_rule_count"`
	KernelRuleCount int `json:"kernel_rule_count"`
	// RuleProblems 是编译不过、被跳过的规则原因。界面必须显示出来 ——
	// 一条规则在列表里显示"已启用"、实际一条都没生效，是最难发现的那类问题。
	RuleProblems  []string  `json:"rule_problems,omitempty"`
	LastSyncAt    time.Time `json:"last_sync_at"`
	LastSyncErr   string    `json:"last_sync_err"`
	LastSyncRules int       `json:"last_sync_rules"`
}

// Verdict 是一次判定结论。
type Verdict struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason"`
	// Detail 是给 frps 的拒绝原因，会出现在 frpc 的错误里，便于排障。
	Detail string `json:"detail"`
}

// Manager 是封禁引擎。它同时承担：
//   - frps 插件回调的判定入口（JudgeLogin / JudgeUserConn）
//   - 封禁状态机（阶梯时长、到期解封）
//   - 期望状态与内核规则的对齐（Reconcile）
//
// blockTarget 是内存里的黑名单条目：地址 + 封禁范围（+ 自定义端口）。
//
// 范围只影响内核规则怎么写（全端口丢 / 只在某些端口上丢），不影响"是否命中"的判定 ——
// 插件层本来就只作用于 frp 连接，而且拿不到被访问的端口，几种范围对它没有区别。
// 所以自定义端口与「仅 frp 端口」在判定路径上完全一样，区别只在内核规则的端口集合。
type blockTarget struct {
	Prefix    netip.Prefix
	ExpiresAt *time.Time
	Scope     string
	// Ports 只在 Scope == custom 时有值。其余范围下端口要么是全局的（frp），
	// 要么根本不带（all），存在条目上只会制造两个真相。
	Ports portrange.Set
}

// geoEntry 是一条「地区条目」在运行时的形态（黑名单或白名单里的国家/省/市）。
//
// 它与 blockTarget 并列而不是混进去：blockTarget 是 netip.Prefix，要参与内核
// 规则的编译；地区条目恰恰相反 —— 它**一条内核规则都不产生**，只在插件判定时
// 拿属地库的查询结果做比较。混在一起会让"名单 → 内核规则"那条路径到处判类型。
//
// 落地的办法是命中之后把这个具体 IP 封掉（triggerBan），与全局地域封禁同一套
// 手法 —— 内核认不出属地，那就让应用层认出来、再把结果落进内核。
type geoEntry struct {
	id   uint
	kind string // model.TargetGeoCountry / Province / City
	// list 是已归一化的地区文本，可含多个值（逗号分隔，任一命中即算命中）。
	list string
	// expiresAt 是条目自己的到期时刻，nil 表示永久。
	//
	// 它决定命中之后封多久。不带它的话，地区条目命中的封禁时长只能回落到全局
	// 阶梯，而全局阶梯还会按**该地址自己的封禁历史**升级 —— 结果是同一个条目
	// 的命中会封出 10 分钟 / 1 小时两种时长，而界面上那条「有效期」压根不参与，
	// 用户看到的就是"设了 1 小时不管用，同一批地址时长还各不相同"。
	expiresAt *time.Time
}

type Manager struct {
	cfg   *config.Config
	store *store.Store
	geo   *geoip.Resolver
	drv   firewall.Driver
	log   *slog.Logger

	applyMu       sync.Mutex
	banMu         sync.Mutex
	refreshMu     sync.Mutex
	whiteExpiry   map[netip.Prefix]time.Time
	nextACLExpiry time.Time
	mu            sync.RWMutex
	policy        *model.Policy
	protect       *protector
	white         []netip.Prefix
	black         []blockTarget
	// geoWhite / geoBlack 是名单里的地区条目，与上面的 IP 名单并列。
	// 判定时两者都看：命中任一即算命中白/黑名单。
	geoWhite []geoEntry
	geoBlack []geoEntry
	bans     map[string]*banState
	windows  map[string]*hitWindow

	// appRules 是按优先级排好的细分规则（应用层那部分）。
	// kernelRules 是细分规则里落在内核的那部分，交给驱动编译成限速规则。
	//
	// 两者都是从 rate_rules 表编译出来的，一次 Refresh 整体替换 ——
	// 判定路径上只读，不加锁也不会有半新半旧的状态。
	appRules    []appRule
	kernelRules []kernelRule
	// ruleProblems 记录编译不过、被跳过的规则，界面要把它显示出来。
	ruleProblems []string

	// frpsProxyPorts 是运行期生效的 frp 代理端口。
	//
	// 单独存一份而不是每次读 m.cfg：m.cfg 是进程启动时的那一份，而代理端口可以
	// 热改（frp 接入页直接编辑受保护端口），改完要立刻重新对齐内核规则。
	// 只有这一项走热更路径 —— bind_port、监听地址这类要重启的配置仍以 m.cfg 为准，
	// 免得出现"一半是新的、一半是旧的"这种没人能解释的状态。
	frpsProxyPorts portrange.Set

	// eventRetention 是运行期生效的事件保留天数，0 表示永久保留。
	//
	// 与 frpsProxyPorts 同一个道理：m.cfg 是启动时的快照，而保留期可以在系统设置
	// 里热改，改完要立刻按新值清一次，不能被 m.cfg 里那份旧值拦住。
	eventRetention int

	lastSyncAt    time.Time
	lastSyncErr   string
	lastSyncRules int

	eventCh chan *model.Event
	applyCh chan struct{}
}

// New 创建引擎。drv 可以为 nil —— 此时只做判定与展示，不往防火墙写规则。
func New(cfg *config.Config, st *store.Store, geo *geoip.Resolver, drv firewall.Driver, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{
		cfg:     cfg,
		store:   st,
		geo:     geo,
		drv:     drv,
		log:     log,
		bans:    make(map[string]*banState),
		windows: make(map[string]*hitWindow),
		eventCh: make(chan *model.Event, 2048),
		applyCh: make(chan struct{}, 1),
		// 启动时的生效值。之后由 SetFrpsProxyPorts 热改。
		frpsProxyPorts: cfg.Frps.ProxyPorts.Normalize(),
		// 同上，之后由 SetEventRetention 热改。
		eventRetention: cfg.Event.RetentionDays,
	}
}

// Start 加载状态并启动后台协程。
func (m *Manager) Start(ctx context.Context) error {
	if err := m.Refresh(); err != nil {
		return err
	}
	if err := m.rebuildBans(); err != nil {
		return err
	}

	if m.guardEnabled() {
		if err := m.Reconcile(); err != nil {
			m.log.Error("初始规则同步失败", "err", err)
		}
		// 先采一次：不采的话第一条趋势要等一个采样间隔后才出现，而"刚启动就想知道
		// 拦了多少"是最常见的诉求。放在 Reconcile 之后 —— 规则都还没下发时
		// 读到的是空表，采出来的是一批全是 0 的噪声。
		m.sampleCounters()
	}

	go m.eventLoop(ctx)
	go m.tickLoop(ctx)
	return nil
}

func (m *Manager) guardEnabled() bool { return m.cfg.Guard.Enabled }

func (m *Manager) dryRun() bool { return m.cfg.Guard.DryRun }

// Refresh 从数据库重新加载策略与名单。前端改完配置后调用。
func (m *Manager) Refresh() error {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()
	policy, err := m.store.GetPolicy()
	if err != nil {
		return fmt.Errorf("读取策略失败: %w", err)
	}

	whiteRows, err := m.store.AllACL(model.KindWhite)
	if err != nil {
		return fmt.Errorf("读取白名单失败: %w", err)
	}
	blackRows, err := m.store.AllACL(model.KindBlack)
	if err != nil {
		return fmt.Errorf("读取黑名单失败: %w", err)
	}

	ruleRows, err := m.store.RateRules()
	if err != nil {
		return fmt.Errorf("读取频控细分规则失败: %w", err)
	}
	appRules, kernelRules, skipped := compileRules(ruleRows)
	for _, s := range skipped {
		m.log.Error("频控细分规则无法生效，已跳过", "reason", s)
	}

	prot, protErr := newProtector(m.cfg.Frps.TrustedProxies...)
	if protErr != nil {
		m.log.Warn("可信回源段配置有问题", "err", protErr)
	}

	now := time.Now()
	white := toPrefixes(whiteRows, now)
	black := toBlockTargets(blackRows, now)
	// 同一批行再过一遍地区口径：一条行只会落进其中一边（类型互斥），
	// 所以两份切片加起来正好覆盖整张名单。
	geoWhite := toGeoEntries(whiteRows, now)
	geoBlack := toGeoEntries(blackRows, now)

	m.mu.Lock()
	m.policy = policy
	m.protect = prot
	m.white = white
	m.whiteExpiry = make(map[netip.Prefix]time.Time)
	m.nextACLExpiry = time.Time{}
	for _, r := range append(whiteRows, blackRows...) {
		if !r.Enabled || r.ExpiresAt == nil || !r.ExpiresAt.After(now) {
			continue
		}
		if m.nextACLExpiry.IsZero() || r.ExpiresAt.Before(m.nextACLExpiry) {
			m.nextACLExpiry = *r.ExpiresAt
		}
	}
	seenWhite := make(map[netip.Prefix]bool)
	for _, r := range whiteRows {
		if !r.Enabled || model.IsGeoTargetType(r.TargetType) || (r.ExpiresAt != nil && !r.ExpiresAt.After(now)) {
			continue
		}
		p, err := parsePrefixOrAddr(r.Target)
		if err != nil {
			continue
		}
		if r.ExpiresAt == nil {
			m.whiteExpiry[p] = time.Time{}
		} else if !seenWhite[p] || (!m.whiteExpiry[p].IsZero() && r.ExpiresAt.After(m.whiteExpiry[p])) {
			m.whiteExpiry[p] = *r.ExpiresAt
		}
		seenWhite[p] = true
	}
	m.black = black
	m.geoWhite = geoWhite
	m.geoBlack = geoBlack
	m.appRules = appRules
	m.kernelRules = kernelRules
	m.ruleProblems = skipped
	m.mu.Unlock()

	if protErr != nil {
		return protErr
	}
	return nil
}

// toPrefixes 把名单行转成前缀，跳过停用、已过期和解析失败的条目。
func toPrefixes(rows []model.ACLEntry, now time.Time) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(rows))
	for _, r := range rows {
		// 地区条目的是 ISO 码/地名，不是地址，走 toGeoEntries。
		// 显式判类型而不是等 parsePrefixOrAddr 失败：依赖"恰好解析不出来"
		// 太脆，将来 TargetType 再多一种形态就会悄悄漏进来。
		if model.IsGeoTargetType(r.TargetType) {
			continue
		}
		// 停用的条目与"不在名单里"等价。判在过期之前：它连"生效中"都算不上，
		// 更轮不到讨论过没过期。
		if !r.Enabled {
			continue
		}
		if r.ExpiresAt != nil && !r.ExpiresAt.After(now) {
			continue
		}
		p, err := parsePrefixOrAddr(r.Target)
		if err != nil {
			continue
		}
		out = append(out, p)
	}
	return out
}

// toGeoEntries 挑出名单里的地区条目（国家 / 省份 / 城市）。
//
// 与 toPrefixes 是**互补**的两拨：地区条目的 Target 不是 IP，压根进不了
// toPrefixes（解析会失败被跳过），所以这里单独收一遍。两条路径都跳过停用与
// 已过期的条目，规则一致。
func toGeoEntries(rows []model.ACLEntry, now time.Time) []geoEntry {
	out := make([]geoEntry, 0, 4)
	for _, r := range rows {
		if !model.IsGeoTargetType(r.TargetType) {
			continue
		}
		if !r.Enabled {
			continue
		}
		if r.ExpiresAt != nil && !r.ExpiresAt.After(now) {
			continue
		}
		list := strings.TrimSpace(r.Target)
		// 空值不该出现（接口层会拦），但库里可能有手工写坏的行。
		// 放进去只会让每次判定白比一遍空串。
		if list == "" {
			continue
		}
		out = append(out, geoEntry{
			id:        r.ID,
			kind:      r.TargetType,
			list:      list,
			expiresAt: r.ExpiresAt,
		})
	}
	return out
}

// toBlockTargets 把黑名单行转成带范围的条目，跳过停用、已过期和解析失败的。
//
// 范围缺失或非法一律按 all 处理。空值是真会出现的：AutoMigrate 加列前写入的
// 老行、以及手工改过数据库的行。兜底方向必须是"更严"的那一侧 —— 把本该全端口
// 封禁的条目降级成只在某些端口上封，等于不知不觉放松了封禁。
func toBlockTargets(rows []model.ACLEntry, now time.Time) []blockTarget {
	out := make([]blockTarget, 0, len(rows))
	for _, r := range rows {
		// 地区条目一条内核规则都不产生 —— 内核认不出属地（见 geoEntry 的注释）。
		// 它命中的落地方式是"把这个具体 IP 封掉"，由判定链做，不在这里。
		if model.IsGeoTargetType(r.TargetType) {
			continue
		}
		if !r.Enabled {
			continue
		}
		if r.ExpiresAt != nil && !r.ExpiresAt.After(now) {
			continue
		}
		p, err := parsePrefixOrAddr(r.Target)
		if err != nil {
			continue
		}
		scope := r.Scope
		if !model.ValidScope(scope) {
			scope = model.ScopeAll
		}
		ports, ok := parseScopePorts(scope, r.Ports)
		if !ok {
			scope, ports = model.ScopeAll, nil
		}
		out = append(out, blockTarget{Prefix: p, Scope: scope, Ports: ports, ExpiresAt: r.ExpiresAt})
	}
	return out
}

// parseScopePorts 解析条目的端口条件。
//
// ok 为 false 表示"这个范围本该有端口、但拿不到可用的" —— 调用方负责把它退化成
// 全端口。兜底方向取更严的一侧是刻意的：一条写着"只封 8080"的条目如果因为端口
// 字段被手工清空而变成"不封"，那是实打实的安全缺口，而且在界面上完全看不出来
// （列表里它还显示着）。反向的代价是可能多封了几个端口，看得见、也解释得清。
func parseScopePorts(scope, ports string) (portrange.Set, bool) {
	if !model.ScopeNeedsPorts(scope) {
		return nil, true
	}
	ps, err := portrange.Parse(ports)
	if err != nil || len(ps) == 0 {
		return nil, false
	}
	return ps, true
}

// rebuildBans 从数据库恢复活跃封禁。程序重启后靠它自愈。
//
// 注意"自愈"包含两层，且它们分别由不同的机制完成：
//   - **内核**：这里只把未到期的放进内存，随后的 Reconcile 全量重建受管链
//     （iptables 先 -F 再写、nftables 先删受管 handle 再写），于是"程序没运行
//     期间就已经到期"的那些封禁，即便还留在内核里也会被这轮重建清掉。
//   - **库**：由 expireBans 的 ReleaseExpired 兜底 —— 那一步扫的是库，
//     不依赖这里是否把过期的行放进内存。
func (m *Manager) rebuildBans() error {
	rows, err := m.store.ActiveBans()
	if err != nil {
		return fmt.Errorf("读取活跃封禁失败: %w", err)
	}
	now := time.Now()
	bans := make(map[string]*banState, len(rows))

	for _, r := range rows {
		p, err := parsePrefixOrAddr(r.Target)
		if err != nil {
			continue
		}
		// 已到期的不恢复：既不占内存，也不该被"恢复"进内核规则。
		// 库里的 status 不由这里负责（见函数头的两层说明）。
		if r.ExpiresAt != nil && !r.ExpiresAt.After(now) {
			continue
		}
		scope := r.Scope
		if !model.ValidScope(scope) {
			scope = model.ScopeAll
		}
		ports, ok := parseScopePorts(scope, r.Ports)
		if !ok {
			scope, ports = model.ScopeAll, nil
		}
		st := &banState{
			Prefix:    p,
			Target:    r.Target,
			Scope:     scope,
			Ports:     ports,
			Reason:    r.Reason,
			Source:    r.Source,
			SourceRef: r.SourceRef,
			User:      r.TriggerUser,
			RecordID:  r.ID,
			HitCount:  r.HitCount,
			BannedAt:  r.BannedAt,
			Country:   r.Country,
			Province:  r.Province,
		}
		if r.ExpiresAt != nil {
			st.Expires = *r.ExpiresAt
		}
		bans[st.Target] = st
	}

	m.mu.Lock()
	m.bans = bans
	m.mu.Unlock()
	return nil
}

// Reconcile 把内核规则对齐到当前期望状态。
func (m *Manager) Reconcile() error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	m.mu.RLock()
	drv := m.drv
	m.mu.RUnlock()
	if drv == nil || !m.guardEnabled() {
		return nil
	}

	desired := m.desired()

	var err error
	if m.dryRun() {
		// 观察模式：只打印将要下发的规则，不落盘。
		var preview string
		preview, err = drv.Preview(desired)
		if err == nil {
			m.log.Info("观察模式：跳过规则下发", "preview_bytes", len(preview))
		}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = firewall.SyncContext(ctx, drv, desired)
	}

	m.mu.Lock()
	m.lastSyncAt = time.Now()
	m.lastSyncRules = desiredRuleCount(desired)
	if err != nil {
		m.lastSyncErr = err.Error()
	} else {
		m.lastSyncErr = ""
	}
	m.mu.Unlock()

	if err != nil {
		_ = m.store.AddRuleChange(&model.RuleChange{
			Backend: drv.Name(),
			Action:  "sync",
			Payload: fmt.Sprintf(`{"rules":%d}`, desiredRuleCount(desired)),
			Result:  "failed",
			Error:   truncate(err.Error(), 500),
		})
		return err
	}
	return nil
}

// desiredRuleCount 数出期望状态里被封的条目数（按地址计，不按内核规则条数）。
//
// 只数全端口那一份会漏掉端口限定的条目：界面上会显示"本次同步 3 条"，
// 而实际封着十来个地址，排查时第一反应是"怎么少了"，方向直接跑偏。
func desiredRuleCount(des firewall.Desired) int {
	n := len(des.Blacklist)
	for _, g := range des.PortBlacklists {
		n += len(g.Prefixes)
	}
	return n
}

// 端口限定分组的标签，只用在告警与规则摘要里。
// frp 那一组是固定名字；自定义分组的标签带上端口文本，否则几条告警长得一样，
// 用户无法判断该去哪一条条目上改。
const frpGroupLabel = "仅 frp 端口"

func customGroupLabel(ports string) string { return "自定义端口 " + ports }

// desired 计算内核侧的期望状态。
//
// 关键点：白名单是在这里"做减法"实现的，而不是往内核写一条豁免规则。
// 这样白名单的语义精确地等于"不会被本程序封禁"，不会变成"放行全端口"。
func (m *Manager) desired() firewall.Desired {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	// 受保护端口在同一把锁里算一次：它既可能被 frp 范围的条目用到，
	// 又要参与限速规则，两次分别算的话中间可能被热更新改掉，结果自相矛盾。
	protect := m.protectPortsLocked()

	// 同一个地址可能同时来自手动黑名单与自动封禁，两处范围还可能不同。
	// 先把所有条目归集成"地址 + 范围 + 端口"，再按下面的规则分桶。
	type scopedEntry struct {
		prefix netip.Prefix
		scope  string
		ports  portrange.Set
	}
	entries := make([]scopedEntry, 0, len(m.black)+len(m.bans))
	exceptions := append([]netip.Prefix(nil), systemProtected...)
	for _, w := range m.white {
		if exp := m.whiteExpiry[w]; exp.IsZero() || exp.After(now) {
			exceptions = append(exceptions, w)
		}
	}

	collect := func(p netip.Prefix, scope string, ports portrange.Set) {

		if !model.ValidScope(scope) {
			scope = model.ScopeAll
		}
		switch scope {
		case model.ScopeFrp:
			// 端口来自全局的受保护端口，不跟着条目走。
			ports = protect
		case model.ScopeCustom:
			// 自定义范围没有端口就表达不出任何规则。退化成全端口而不是丢掉：
			// 兜底方向必须是"更严"的那一侧 —— 把一条本该封住的条目静默放掉，
			// 是没有办法从界面上看出来的错误。接口层会拦住空端口，能走到这里
			// 基本只可能是库里被手工改坏了。
			if ports = ports.Normalize(); len(ports) == 0 {
				scope, ports = model.ScopeAll, nil
			}
		}
		// frp 端口集合为空时同理退化（bind_port 被清成 0 且代理端口为空）。
		if scope != model.ScopeAll && len(ports.Normalize()) == 0 {
			scope, ports = model.ScopeAll, nil
		}
		for _, piece := range subtractPrefixes(p, exceptions) {
			entries = append(entries, scopedEntry{prefix: piece, scope: scope, ports: ports})
		}
	}

	for _, b := range m.black {
		if b.ExpiresAt == nil || b.ExpiresAt.After(now) {
			collect(b.Prefix, b.Scope, b.Ports)
		}
	}
	for _, b := range m.bans {
		if m.policy != nil && m.policy.ObserveOnly && b.Source != model.SourceManual {
			continue
		}
		if b.Expires.IsZero() || b.Expires.After(now) {
			collect(b.Prefix, b.Scope, b.Ports)
		}
	}

	// 全端口优先：它已经覆盖了所有端口，同一地址再进任何端口限定组都是冗余，
	// 而且会变成"这个地址为什么出现在两处"这种需要解释的问题。
	// 冲突时严格范围胜出 —— 与以前「全端口 vs 仅 frp 端口」的取舍一致。
	fullPort := make(map[netip.Prefix]bool, len(entries))
	for _, e := range entries {
		if e.scope == model.ScopeAll {
			fullPort[e.prefix] = true
		}
	}

	// 端口限定按端口集合分组：Key 由端口集合派生，因此同一个集合天然合为一组，
	// 不同集合必须分开 —— 合成一组会让 A 组的地址在 B 组的端口上也被封，
	// 而两组规则长得一模一样，光看规则本身发现不了。
	groupOf := make(map[string]*firewall.PortBlacklist, 4)
	usedByFrp := make(map[string]bool, 4)
	members := make(map[string]map[netip.Prefix]bool, 4)
	for _, e := range entries {
		if e.scope == model.ScopeAll || fullPort[e.prefix] {
			continue
		}
		key := e.ports.String()
		if _, ok := groupOf[key]; !ok {
			groupOf[key] = &firewall.PortBlacklist{Key: key, Ports: e.ports}
			members[key] = make(map[netip.Prefix]bool, 4)
		}
		if e.scope == model.ScopeFrp {
			usedByFrp[key] = true
		}
		members[key][e.prefix] = true
	}

	keys := make([]string, 0, len(groupOf))
	for k := range groupOf {
		keys = append(keys, k)
	}
	// 排序只为输出稳定：内核规则本身与顺序无关（都是 DROP），但两份内容相同的
	// 期望状态应当生成完全一样的文本，否则每次比对都会看到"变化"。
	sort.Strings(keys)

	portGroups := make([]firewall.PortBlacklist, 0, len(keys))
	for _, k := range keys {
		g := groupOf[k]
		// 标签只影响告警与规则摘要里的可读性，不参与判定。
		// 一组里同时有 frp 条目和自定义条目时（自定义那份端口恰好等于受保护端口，
		// 于是两者合成一组）优先显示"仅 frp 端口"——按端口集合分组本来就是有意的，
		// 两种来源在这里本来就是同一件事。
		g.Label = customGroupLabel(k)
		if usedByFrp[k] {
			g.Label = frpGroupLabel
		}
		for p := range members[k] {
			g.Prefixes = append(g.Prefixes, p.String())
		}
		sort.Strings(g.Prefixes)
		portGroups = append(portGroups, *g)
	}

	blackAll := make([]string, 0, len(fullPort))
	for p := range fullPort {
		blackAll = append(blackAll, p.String())
	}
	sort.Strings(blackAll)

	white := make([]string, 0, len(m.white))
	for _, p := range m.white {
		if exp := m.whiteExpiry[p]; !exp.IsZero() && !exp.After(now) {
			continue
		}
		white = append(white, p.String())
	}

	return firewall.Desired{
		Blacklist:      blackAll,
		PortBlacklists: portGroups,
		Whitelist:      white,
		RateLimits:     m.rateLimitsLocked(),
	}
}

// protectPortsLocked 返回受保护端口：frp 相关端口，全局限速与「仅 frp 端口」
// 的黑名单都作用于此。不做全线保护，避免误伤其它服务。
//
// 用 Merge 而不是逐个 append：bindPort 常常就落在代理端口区间里面
// （例如 bindPort 7000、allowPorts 20000-30000 之外的 7000-7100），
// 合并后同一段端口只会生成一条规则。
func (m *Manager) protectPortsLocked() portrange.Set {
	bind := portrange.Set{}
	if m.cfg.Frps.BindPort > 0 {
		bind = portrange.Ports(m.cfg.Frps.BindPort)
	}
	return bind.Merge(m.frpsProxyPorts)
}

// FrpsPorts 返回当前生效的 frp 端口，供面板展示"受保护端口"这一栏。
//
// 返回的是运行期生效值，不是 m.cfg 里那份启动快照 —— 代理端口可以热改，
// 面板必须显示真正正在生效的东西，否则改完还要怀疑自己是不是记错了。
func (m *Manager) FrpsPorts() (bindPort int, proxyPorts, protect portrange.Set) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Frps.BindPort, m.frpsProxyPorts, m.protectPortsLocked()
}

// SetFrpsProxyPorts 热更新 frp 代理端口，并立即重新对齐内核规则。
//
// 只改内存里这一份，不碰数据库：落库由接口层负责。分成两步是因为"改配置"和
// "让配置生效"是两件事 —— 落库失败的话不该已经动过内核规则。
func (m *Manager) SetFrpsProxyPorts(ports portrange.Set) {
	m.mu.Lock()
	m.frpsProxyPorts = ports.Normalize()
	m.mu.Unlock()
	m.scheduleApply()
}

// Preview 生成将要下发的规则文本。
func (m *Manager) Preview() (string, error) {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	m.mu.RLock()
	drv := m.drv
	m.mu.RUnlock()
	if drv == nil {
		return "", fmt.Errorf("当前没有可用的防火墙后端")
	}
	return drv.Preview(m.desired())
}

// scheduleApply 触发一次异步重新对齐。多次连续调用会被合并。
func (m *Manager) scheduleApply() {
	select {
	case m.applyCh <- struct{}{}:
	default:
		// 已经有待处理的信号，无需重复
	}
}

// Stats 返回运行状态。
func (m *Manager) Stats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 内核规则数把全局兜底也算进去：界面上要回答的是"现在有几条限速规则
	// 在内核里"，而不是"细分规则有几条"。
	kernelRules := len(m.kernelRules)
	if m.policy != nil && m.policy.RateLimitEnabled && m.policy.RateLimitPerSec > 0 {
		kernelRules++
	}

	s := Stats{
		Enabled:         m.guardEnabled(),
		DryRun:          m.dryRun(),
		ActiveBans:      len(m.bans),
		WhiteCount:      len(m.white),
		BlackCount:      len(m.black),
		WindowsTracked:  len(m.windows),
		AppRuleCount:    len(m.appRules),
		KernelRuleCount: kernelRules,
		RuleProblems:    append([]string(nil), m.ruleProblems...),
		LastSyncAt:      m.lastSyncAt,
		LastSyncErr:     m.lastSyncErr,
		LastSyncRules:   m.lastSyncRules,
	}
	if m.protect != nil {
		s.TrustedCount = m.protect.TrustedCount()
	}
	if m.drv != nil {
		s.Backend = m.drv.Name()
		s.BackendOK = m.drv.Capability().Supported
	}
	return s
}

// Policy 返回当前策略副本。
func (m *Manager) Policy() *model.Policy {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.policy == nil {
		return nil
	}
	cp := *m.policy
	return &cp
}

// Bans 返回当前活跃封禁列表。
func (m *Manager) Bans() []BanView {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	out := make([]BanView, 0, len(m.bans))
	for _, b := range m.bans {
		scope := b.Scope
		if !model.ValidScope(scope) {
			scope = model.ScopeAll
		}
		v := BanView{
			Target:    b.Target,
			Scope:     scope,
			Ports:     b.Ports.String(),
			Reason:    b.Reason,
			Source:    b.Source,
			SourceRef: b.SourceRef,
			User:      b.User,
			RecordID:  b.RecordID,
			HitCount:  b.HitCount,
			BannedAt:  b.BannedAt,
			Permanent: b.Permanent(),
			Country:   b.Country,
			Province:  b.Province,
		}
		if !b.Permanent() {
			e := b.Expires
			v.ExpiresAt = &e
		}
		v.RemainingSec = int64(b.Remaining(now) / time.Second)
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BannedAt.After(out[j].BannedAt) })
	return out
}

// Lookup 查询某个 IP 的当前状态（是否被封、命中原因），供前端排障。
func (m *Manager) Lookup(target string) map[string]any {
	result := map[string]any{"target": target}

	addr, err := netip.ParseAddr(strings.TrimSpace(target))
	if err != nil {
		result["valid"] = false
		result["error"] = "不是合法的 IP 地址"
		return result
	}
	addr = addr.Unmap()
	result["valid"] = true
	result["system_protected"] = IsSystemProtected(addr)

	m.mu.RLock()
	policy := m.policy
	isWhite := m.matchAnyLocked(m.white, addr)
	isBlack := m.matchAnyBlockLocked(m.black, addr)
	blockScope := m.blockScopeLocked(m.black, addr)
	trusted := m.protect != nil && m.protect.IsTrustedProxy(addr)
	b, banned := m.findBanLocked(addr, policy, time.Now())
	appRules := m.appRules
	m.mu.RUnlock()

	result["whitelisted"] = isWhite
	result["blacklisted"] = isBlack
	if blockScope != "" {
		result["block_scope"] = blockScope
	}
	result["trusted_proxy"] = trusted
	result["banned"] = banned

	// 窗口命中数要和判定走同一套选择逻辑，否则排障时会看到
	// "查询说有 12 次命中、判定却说没到阈值"这种自相矛盾的结论。
	geoNow := m.lookupGeo(addr)
	now := time.Now()
	tag, win, who := "", time.Duration(0), "全局策略"
	// 代理名在这里永远是空：查询请求只给了一个 IP，没有"连的是哪个隧道"这层
	// 上下文。后果是**带代理条件的规则在查询结果里显示为不命中** —— 这与真实
	// 判定一致（登录阶段同样没有代理名），不是查询漏了规则。
	if r := pickAppRule(appRules, addr, geoNow, ""); r != nil {
		who = "规则「" + r.name + "」"
		if r.threshold > 0 {
			tag, win = r.tag(), r.window
		}
	} else if policy != nil {
		win = time.Duration(policy.WindowSeconds) * time.Second
	}
	hits := 0
	if win > 0 {
		hits = m.windowCount(tag, addr.String(), now, win)
	}
	result["window_rule"] = who
	result["window_hits"] = hits

	if banned {
		result["ban"] = BanView{
			Target:       b.Target,
			Scope:        b.Scope,
			Reason:       b.Reason,
			Source:       b.Source,
			HitCount:     b.HitCount,
			BannedAt:     b.BannedAt,
			Permanent:    b.Permanent(),
			RemainingSec: int64(b.Remaining(now) / time.Second),
		}
	}
	result["geoip"] = geoNow
	return result
}

// SetDriver 在切换防火墙后端时替换驱动。
// 调用方要保证新驱动已经 EnsureBase 完毕，否则会出现规则悬空。
func (m *Manager) SetDriver(drv firewall.Driver) {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	m.mu.Lock()
	m.drv = drv
	m.mu.Unlock()
}

// DriverName 返回当前后端名，无驱动时返回空串。
func (m *Manager) DriverName() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.drv == nil {
		return ""
	}
	return m.drv.Name()
}

// ---- 后台循环 ----

func (m *Manager) eventLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-m.eventCh:
			if err := m.store.AddEvent(e); err != nil {
				m.log.Warn("写入事件失败", "err", err)
			}
		}
	}
}

func (m *Manager) tickLoop(ctx context.Context) {
	sec := time.NewTicker(time.Second)
	defer sec.Stop()
	clean := time.NewTicker(5 * time.Minute)
	defer clean.Stop()
	// 丢包计数采样。与 clean 分开：清理是"防止表无限长"的兜底，采样是
	// 定时取数，两者节奏不一样，绑在一起改一个就会动到另一个。
	sample := time.NewTicker(counterSampleInterval)
	defer sample.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.applyCh:
			// 合并短时间内的连续信号，避免一次批量封禁触发几十次规则重建。
			timer := time.NewTimer(150 * time.Millisecond)
		drain:
			for {
				select {
				case <-m.applyCh:
				case <-timer.C:
					break drain
				case <-ctx.Done():
					timer.Stop()
					return
				}
			}
			timer.Stop()

			if err := m.Reconcile(); err != nil {
				m.log.Error("规则同步失败", "err", err)
			}
		case <-sec.C:
			m.expireBans()
			m.mu.RLock()
			exp := m.nextACLExpiry
			m.mu.RUnlock()
			if !exp.IsZero() && !exp.After(time.Now()) {
				if err := m.Refresh(); err == nil {
					m.scheduleApply()
				} else {
					m.log.Error("刷新到期名单失败", "err", err)
				}
			}
		case <-sample.C:
			m.sampleCounters()
		case <-clean.C:
			m.pruneWindows()
			m.purgeEvents()
			m.purgeCounterSamples()
		}
	}
}

// expireBans 处理到期封禁，自动解封并把状态落库。
func (m *Manager) expireBans() {
	m.banMu.Lock()
	defer m.banMu.Unlock()
	now := time.Now()
	retired, err := m.store.ReleaseExpired(now)
	if err != nil {
		m.log.Warn("更新过期封禁状态失败", "err", err)
		return
	}

	m.mu.Lock()
	var expired []*banState
	for k, b := range m.bans {
		if !b.Expires.IsZero() && !b.Expires.After(now) {
			expired = append(expired, b)
			delete(m.bans, k)
			m.resetWindowsForLocked(b.Prefix.String())
		}
	}
	m.mu.Unlock()

	// 落库这一步**不能**放到下面的早退之后。
	//
	// ReleaseExpired 扫的是库、不是内存，两者并不等价：程序没运行的那段时间里
	// 到期的封禁不会进内存（rebuildBans 会把它们跳过），所以完全可能出现
	// "内存里一条到期项都没有、库里却堆着若干已过期行"。早退挡在它前面的话，
	// 这些行会永远卡在 status=active —— 封禁记录页一直显示"封禁中"，
	// 内核里其实早已没有对应规则，变成"界面说封着、实际没封"。
	// 它本身是全局 + 幂等的，多跑一次的代价只是一次带索引的查询。

	if len(expired) == 0 && len(retired) == 0 {
		return
	}

	seen := make(map[uint]bool, len(expired))
	for _, b := range expired {
		seen[b.RecordID] = true
		m.log.Info("封禁到期自动解封", "target", b.Target, "reason", b.Reason)
		m.pushEvent(&model.Event{
			Category: model.EvtUnban,
			IP:       b.Target,
			Detail:   "封禁到期，自动解封：" + b.Reason,
			Actor:    "system",
		})
	}
	// 库里那批中不在内存里的（重启时被跳过的），也要留一条痕：否则它们在
	// 事件日志里彻底消失 —— 封禁记录显示已过期，却查不到是什么时候解的。
	for _, b := range retired {
		if seen[b.ID] {
			continue
		}
		m.log.Info("清理程序未运行期间到期的封禁", "target", b.Target, "reason", b.Reason)
		m.pushEvent(&model.Event{
			Category: model.EvtUnban,
			IP:       b.Target,
			Detail:   "封禁到期，自动解封（程序未运行期间到期）：" + b.Reason,
			Actor:    "system",
		})
	}
	m.scheduleApply()
}

// pruneWindows 淘汰长时间无活动的计数窗口与令牌桶，防止内存随历史 IP 无限增长。
func (m *Manager) pruneWindows() {
	m.mu.Lock()
	defer m.mu.Unlock()
	retention := 30 * time.Minute
	if m.policy != nil {
		retention = max(retention, time.Duration(m.policy.WindowSeconds)*time.Second)
	}
	for _, r := range m.appRules {
		retention = max(retention, r.window)
	}
	cutoff := time.Now().Add(-retention)
	for k, w := range m.windows {
		if w.last.Before(cutoff) {
			delete(m.windows, k)
		}
	}
	for i := range m.appRules {
		m.appRules[i].bucket.prune(cutoff)
	}
}

// purgeEvents 按当前生效的保留期清理过期事件。
//
// 保留期为 0 表示永久保留，此时什么都不做 —— 不为了删 0 条去扫一遍表。
func (m *Manager) purgeEvents() {
	days := m.EventRetention()
	if days <= 0 {
		return
	}
	before := time.Now().AddDate(0, 0, -days)
	if n, err := m.store.PurgeEvents(before); err == nil && n > 0 {
		m.log.Info("清理历史事件", "removed", n, "retention_days", days)
	}
}

// SetEventRetention 热改事件保留天数（0 表示永久保留），并立刻清一次。
//
// 立刻清而不是等下一个 5 分钟清理周期：用户刚把 30 改成 7，界面上那些更老的
// 记录若还挂着，他没法判断是没生效还是没到清理时间。清完刷新就能看到结果。
//
// 这是个写操作，且由接口请求同步触发 —— 清理走的是 ts 上的索引，量级可控
// （事件表本身就是按这个保留期在裁剪的，不会积累到需要很久才能删完）。
func (m *Manager) SetEventRetention(days int) {
	if days < 0 {
		days = 0
	}
	m.mu.Lock()
	m.eventRetention = days
	m.mu.Unlock()
	m.purgeEvents()
}

// EventRetention 返回运行期生效的事件保留天数（0 表示永久保留）。
func (m *Manager) EventRetention() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.eventRetention
}

// pushEvent 异步入队一条事件。队列满时直接丢弃，绝不阻塞判定路径。
func (m *Manager) pushEvent(e *model.Event) {
	if e.Ts.IsZero() {
		e.Ts = time.Now()
	}
	select {
	case m.eventCh <- e:
	default:
		// 队列满时丢弃，判定路径不等待日志写入。
	}
}

// findBanLocked 查该地址是否处于封禁中。
//
// 两级查询：
//  1. 先按规范化的 key 精确命中（常见路径，O(1)）
//  2. 再扫一遍是否有覆盖该地址的网段封禁（cidr24 粒度时需要）
//
// 调用方需持有读锁。
func (m *Manager) findBanLocked(addr netip.Addr, policy *model.Policy, now time.Time) (*banState, bool) {
	active := func(b *banState) bool {
		return (b.Expires.IsZero() || b.Expires.After(now)) && !(policy != nil && policy.ObserveOnly && b.Source != model.SourceManual)
	}
	key := m.banKeyLocked(addr, policy)
	if b, ok := m.bans[key]; ok && active(b) {
		return b, true
	}
	for _, b := range m.bans {
		if b.Prefix.Contains(addr) && active(b) {
			return b, true
		}
	}
	return nil, false
}

// banKeyLocked 按当前策略算出封禁记录的 key。
// 必须与 banPrefix 的结果一致，否则封禁查不到（这是踩过的坑）。
func (m *Manager) banKeyLocked(addr netip.Addr, policy *model.Policy) string {
	return m.banPrefix(addr, policy).String()
}

// windowKey 是滑动窗口计数的 key：规则标签 + 来源 IP。
//
// 必须带规则标签：细分规则的窗口与阈值可以和全局完全不同，共用一个窗口会让
// 「某地区限速」和全局策略互相把对方的计数顶上去 —— 表现成"阈值莫名其妙
// 提前触发"，而且看哪一条配置都挑不出毛病。
//
// IP 部分始终用单个 IP，不跟封禁粒度走：频次统计要精确到来源。
// ruleTag 为空表示全局策略。
func windowKey(ruleTag, ip string) string {
	return ruleTag + "|" + ip
}

// countWindow 记一次命中并返回窗口内的总数。
func (m *Manager) countWindow(ruleTag, ip string, now time.Time, win time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	k := windowKey(ruleTag, ip)
	w := m.windows[k]
	if w == nil {
		w = &hitWindow{}
		m.windows[k] = w
	}
	return w.add(now, win)
}

// windowCount 读窗口内的命中数，不记录新命中。
func (m *Manager) windowCount(ruleTag, ip string, now time.Time, win time.Duration) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	w := m.windows[windowKey(ruleTag, ip)]
	if w == nil {
		return 0
	}
	return w.count(now, win)
}

// resetWindowsFor 把某个地址在所有规则下的窗口计数归零。
//
// 必须扫全部规则，不能只清全局那一个：细分规则各有各的窗口，漏掉哪个，
// 那个规则的阈值就形同虚设 —— 解封之后第一次访问就重新达标。
//
// 调用方需持有写锁。
func (m *Manager) resetWindowsForLocked(ip string) {
	p, err := parsePrefixOrAddr(ip)
	if err != nil {
		return
	}
	for k, w := range m.windows {
		a, err := netip.ParseAddr(k[strings.LastIndex(k, "|")+1:])
		if err == nil && p.Contains(a) {
			w.reset()
		}
	}
	for i := range m.appRules {
		m.appRules[i].bucket.resetPrefix(p)
	}
}

// Whitelisted 判断地址是否被白名单覆盖（含被某个 CIDR 条目罩住的情况）。
//
// 刻意复用判定路径用的那份内存名单，而不是现查一次库：界面上"已放行 / 未放行"
// 与"实际会不会拦"必须是同一个结论，各写一遍迟早会对不上（过期、停用、
// 地区条目这些边角最容易分叉）。
//
// 注意它只看 IP/CIDR 条目：地区白名单（国家 / 省份 / 城市）要拿属地去比，
// 而"服务器出口 IP 是否被放行"这个问题下，属地匹配的语义太松（等于整个国家
// 放行），不该拿它得出"已放行"的结论。
func (m *Manager) Whitelisted(addr netip.Addr) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.matchAnyLocked(m.white, addr)
}

// matchAnyLocked 判断地址是否命中某个前缀集合。调用方需持有锁。
func (m *Manager) matchAnyLocked(list []netip.Prefix, addr netip.Addr) bool {
	for _, p := range list {
		if exp := m.whiteExpiry[p]; !exp.IsZero() && !exp.After(time.Now()) {
			continue
		}
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// matchAnyBlockLocked 判断地址是否命中黑名单。调用方需持有锁。
//
// 这里刻意不看范围：插件层只作用于 frp 的登录与建连回调，所以"只封 frp 端口"
// 与"全端口封禁"在它面前是同一件事。
func (m *Manager) matchAnyBlockLocked(list []blockTarget, addr netip.Addr) bool {
	for _, b := range list {
		if b.ExpiresAt != nil && !b.ExpiresAt.After(time.Now()) {
			continue
		}
		if b.Prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// matchGeoLocked 判断属地是否命中地区名单，返回命中的那一条（未命中返回 nil）。
// 调用方需持有锁。
//
// 传进去的是属地的三个**原始**字段，归一化由 model.MatchGeo 统一做 ——
// 名单侧保存时已经归一化过，查询侧不过同一遍归一化就永远对不上，
// 而且不报错（省份上踩过的坑，见 province.go）。
//
// 返回的是切片内元素的指针。名单是 Refresh 时整体换掉的（不是原地改），
// 所以拿到指针之后在锁外继续用是安全的，与 matchAppRule 同一个理由。
func (m *Manager) matchGeoLocked(list []geoEntry, geo *geoip.Info) *geoEntry {
	if geo == nil {
		return nil
	}
	for i := range list {
		if list[i].expiresAt != nil && !list[i].expiresAt.After(time.Now()) {
			continue
		}
		if model.MatchGeo(list[i].kind, list[i].list, geo.Country, geo.Province, geo.City) {
			return &list[i]
		}
	}
	return nil
}

// blockScopeLocked 返回地址命中的黑名单范围，未命中返回空串。调用方需持有锁。
//
// 命中多条时取覆盖最宽的那类：all > frp > custom。排障时要回答的是"这个地址
// 实际被挡得有多死"，而不是"它命中了哪几条"。
//
// frp 排在 custom 前面是因为覆盖面：frp 那一组是 bindPort 加整段代理端口，
// 通常比用户为单条条目随手填的几个端口宽；而 all 永远是最宽的那个，见到就返回。
// 三种范围之间没有真正的包含关系（这是排序而不是包含判断），所以这里只是一个
// 约定 —— 唯一的要求是稳定，别让同一种冲突有时报 frp、有时报 custom。
func (m *Manager) blockScopeLocked(list []blockTarget, addr netip.Addr) string {
	scope := ""
	for _, b := range list {
		if !b.Prefix.Contains(addr) || (b.ExpiresAt != nil && !b.ExpiresAt.After(time.Now())) {
			continue
		}
		switch b.Scope {
		case model.ScopeAll:
			return model.ScopeAll
		case model.ScopeFrp:
			scope = model.ScopeFrp
		case model.ScopeCustom:
			if scope == "" {
				scope = model.ScopeCustom
			}
		}
	}
	return scope
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
