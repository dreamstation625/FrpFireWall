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
	// Scope 封禁范围（all | frp）。自动封禁固定 all，手动封禁可指定。
	Scope    string
	Reason   string
	Source   string
	User     string
	RecordID uint
	HitCount int
	BannedAt time.Time
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
	// Scope 封禁范围（all | frp）。
	Scope        string     `json:"scope"`
	Reason       string     `json:"reason"`
	Source       string     `json:"source"`
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
	Enabled        bool      `json:"enabled"`
	DryRun         bool      `json:"dry_run"`
	Backend        string    `json:"backend"`
	BackendOK      bool      `json:"backend_ok"`
	ActiveBans     int       `json:"active_bans"`
	WhiteCount     int       `json:"white_count"`
	BlackCount     int       `json:"black_count"`
	TrustedCount   int       `json:"trusted_count"`
	WindowsTracked int       `json:"windows_tracked"`
	LastSyncAt     time.Time `json:"last_sync_at"`
	LastSyncErr    string    `json:"last_sync_err"`
	LastSyncRules  int       `json:"last_sync_rules"`
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
// blockTarget 是内存里的黑名单条目：地址 + 封禁范围。
//
// 范围只影响内核规则怎么写（全端口丢 / 只丢 frp 端口），不影响"是否命中"的判定 ——
// 插件层本来就只作用于 frp 连接，两种范围对它没有区别。
type blockTarget struct {
	Prefix netip.Prefix
	Scope  string
}

type Manager struct {
	cfg   *config.Config
	store *store.Store
	geo   *geoip.Resolver
	drv   firewall.Driver
	log   *slog.Logger

	mu      sync.RWMutex
	policy  *model.Policy
	protect *protector
	white   []netip.Prefix
	black   []blockTarget
	bans    map[string]*banState
	windows map[string]*hitWindow

	lastSyncAt    time.Time
	lastSyncErr   string
	lastSyncRules int

	eventCh chan *model.Event
	applyCh chan struct{}

	droppedEvents int64
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

	if m.guardEnabled() && m.drv != nil {
		if err := m.drv.EnsureBase(); err != nil {
			// 基础链建不起来不是致命错误：判定与展示仍可用，
			// 但要明确告诉用户"网络层封禁当前不可用"。
			m.log.Error("创建受管防火墙链失败，网络层封禁将不可用", "err", err)
			m.mu.Lock()
			m.lastSyncErr = err.Error()
			m.mu.Unlock()
		} else if err := m.Reconcile(); err != nil {
			m.log.Error("初始规则同步失败", "err", err)
		}
	}

	go m.eventLoop(ctx)
	go m.tickLoop(ctx)
	return nil
}

func (m *Manager) guardEnabled() bool { return m.cfg.Guard.Enabled }

func (m *Manager) dryRun() bool { return m.cfg.Guard.DryRun }

// Refresh 从数据库重新加载策略与名单。前端改完配置后调用。
func (m *Manager) Refresh() error {
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

	prot, protErr := newProtector(m.cfg.Frps.TrustedProxies...)
	if protErr != nil {
		m.log.Warn("可信回源段配置有问题", "err", protErr)
	}

	now := time.Now()
	white := toPrefixes(whiteRows, now)
	black := toBlockTargets(blackRows, now)

	m.mu.Lock()
	m.policy = policy
	m.protect = prot
	m.white = white
	m.black = black
	m.mu.Unlock()

	if protErr != nil {
		return protErr
	}
	return nil
}

// toPrefixes 把名单行转成前缀，跳过已过期和解析失败的条目。
func toPrefixes(rows []model.ACLEntry, now time.Time) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(rows))
	for _, r := range rows {
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

// toBlockTargets 把黑名单行转成带范围的条目，跳过已过期和解析失败的。
//
// 范围缺失或非法一律按 all 处理。空值是真会出现的：AutoMigrate 加列前写入的
// 老行、以及手工改过数据库的行。兜底方向必须是"更严"的那一侧 —— 把本该全端口
// 封禁的条目降级成只封 frp 端口，等于不知不觉放松了封禁。
func toBlockTargets(rows []model.ACLEntry, now time.Time) []blockTarget {
	out := make([]blockTarget, 0, len(rows))
	for _, r := range rows {
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
		out = append(out, blockTarget{Prefix: p, Scope: scope})
	}
	return out
}

// rebuildBans 从数据库恢复活跃封禁。程序重启后靠它自愈。
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
		// 已到期的不恢复，交给 expireBans 走正常过期流程。
		if r.ExpiresAt != nil && !r.ExpiresAt.After(now) {
			continue
		}
		scope := r.Scope
		if !model.ValidScope(scope) {
			scope = model.ScopeAll
		}
		st := &banState{
			Prefix:   p,
			Target:   r.Target,
			Scope:    scope,
			Reason:   r.Reason,
			Source:   r.Source,
			User:     r.TriggerUser,
			RecordID: r.ID,
			HitCount: r.HitCount,
			BannedAt: r.BannedAt,
			Country:  r.Country,
			Province: r.Province,
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
	if m.drv == nil || !m.guardEnabled() {
		return nil
	}

	desired := m.desired()

	var err error
	if m.dryRun() {
		// 观察模式：只打印将要下发的规则，不落盘。
		var preview string
		preview, err = m.drv.Preview(desired)
		if err == nil {
			m.log.Info("观察模式：跳过规则下发", "preview_bytes", len(preview))
		}
	} else {
		err = m.drv.Sync(desired)
	}

	m.mu.Lock()
	m.lastSyncAt = time.Now()
	m.lastSyncRules = len(desired.Blacklist)
	if err != nil {
		m.lastSyncErr = err.Error()
	} else {
		m.lastSyncErr = ""
	}
	m.mu.Unlock()

	if err != nil {
		_ = m.store.AddRuleChange(&model.RuleChange{
			Backend: m.drv.Name(),
			Action:  "sync",
			Payload: fmt.Sprintf(`{"rules":%d}`, len(desired.Blacklist)),
			Result:  "failed",
			Error:   truncate(err.Error(), 500),
		})
		return err
	}
	return nil
}

// desired 计算内核侧的期望状态。
//
// 关键点：白名单是在这里"做减法"实现的，而不是往内核写一条豁免规则。
// 这样白名单的语义精确地等于"不会被本程序封禁"，不会变成"放行全端口"。
func (m *Manager) desired() firewall.Desired {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()

	// 同一个地址可能同时来自手动黑名单与自动封禁，两处范围还可能不同。
	// 这里用 map 归并而不是简单拼接：全端口已经覆盖了 frp 端口，同一地址再写
	// 一条 frp 规则纯属冗余，还会变成"为什么这里有两行"这种需要解释的问题。
	// 冲突时严格范围胜出。
	scopeOf := make(map[netip.Prefix]string, len(m.black)+len(m.bans))

	add := func(p netip.Prefix, scope string) {
		if IsSystemProtected(p.Addr()) {
			return
		}
		if m.matchAnyLocked(m.white, p.Addr()) {
			return
		}
		if !model.ValidScope(scope) {
			scope = model.ScopeAll
		}
		if prev, ok := scopeOf[p]; ok && prev == model.ScopeAll {
			return // 已是全端口，别再降级成 frp
		}
		scopeOf[p] = scope
	}

	for _, b := range m.black {
		add(b.Prefix, b.Scope)
	}
	for _, b := range m.bans {
		if b.Expires.IsZero() || b.Expires.After(now) {
			add(b.Prefix, b.Scope)
		}
	}

	blackAll := make([]string, 0, len(scopeOf))
	blackFrp := make([]string, 0, 8)
	for p, scope := range scopeOf {
		if scope == model.ScopeFrp {
			blackFrp = append(blackFrp, p.String())
		} else {
			blackAll = append(blackAll, p.String())
		}
	}
	sort.Strings(blackAll)
	sort.Strings(blackFrp)

	white := make([]string, 0, len(m.white))
	for _, p := range m.white {
		white = append(white, p.String())
	}

	des := firewall.Desired{
		Blacklist:    blackAll,
		BlacklistFrp: blackFrp,
		Whitelist:    white,
		ProtectPorts: m.protectPortsLocked(),
	}
	if m.policy != nil && m.policy.RateLimitEnabled {
		des.RateLimit = &firewall.RateLimitSpec{
			Enabled: true,
			PerSec:  m.policy.RateLimitPerSec,
			Burst:   m.policy.RateLimitBurst,
		}
	}
	return des
}

// protectPortsLocked 返回速率限制与保护规则作用的端口集合。
// 只保护 frp 相关端口，不做全线保护，避免误伤其它服务。
//
// 用 Merge 而不是逐个 append：bindPort 常常就落在代理端口区间里面
// （例如 bindPort 7000、allowPorts 20000-30000 之外的 7000-7100），
// 合并后同一段端口只会生成一条规则。
func (m *Manager) protectPortsLocked() portrange.Set {
	bind := portrange.Set{}
	if m.cfg.Frps.BindPort > 0 {
		bind = portrange.Ports(m.cfg.Frps.BindPort)
	}
	return bind.Merge(m.cfg.Frps.ProxyPorts)
}

// Preview 生成将要下发的规则文本。
func (m *Manager) Preview() (string, error) {
	if m.drv == nil {
		return "", fmt.Errorf("当前没有可用的防火墙后端")
	}
	return m.drv.Preview(m.desired())
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

	s := Stats{
		Enabled:        m.guardEnabled(),
		DryRun:         m.dryRun(),
		ActiveBans:     len(m.bans),
		WhiteCount:     len(m.white),
		BlackCount:     len(m.black),
		WindowsTracked: len(m.windows),
		LastSyncAt:     m.lastSyncAt,
		LastSyncErr:    m.lastSyncErr,
		LastSyncRules:  m.lastSyncRules,
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
			Reason:    b.Reason,
			Source:    b.Source,
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
	var windowCount int
	if w := m.windows[addr.String()]; w != nil && policy != nil {
		windowCount = w.count(time.Now(), time.Duration(policy.WindowSeconds)*time.Second)
	}
	m.mu.RUnlock()

	result["whitelisted"] = isWhite
	result["blacklisted"] = isBlack
	if blockScope != "" {
		result["block_scope"] = blockScope
	}
	result["trusted_proxy"] = trusted
	result["window_hits"] = windowCount
	result["banned"] = banned
	if banned {
		result["ban"] = BanView{
			Target:       b.Target,
			Scope:        b.Scope,
			Reason:       b.Reason,
			Source:       b.Source,
			HitCount:     b.HitCount,
			BannedAt:     b.BannedAt,
			Permanent:    b.Permanent(),
			RemainingSec: int64(b.Remaining(time.Now()) / time.Second),
		}
	}
	if m.geo != nil {
		result["geoip"] = m.geo.Lookup(addr)
	}
	return result
}

// SetDriver 在切换防火墙后端时替换驱动。
// 调用方要保证新驱动已经 EnsureBase 完毕，否则会出现规则悬空。
func (m *Manager) SetDriver(drv firewall.Driver) {
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
		case <-clean.C:
			m.pruneWindows()
			m.purgeEvents()
		}
	}
}

// expireBans 处理到期封禁，自动解封并把状态落库。
func (m *Manager) expireBans() {
	now := time.Now()

	m.mu.Lock()
	var expired []*banState
	for k, b := range m.bans {
		if !b.Expires.IsZero() && !b.Expires.After(now) {
			expired = append(expired, b)
			delete(m.bans, k)
			// 窗口计数用的是纯 IP 作为 key，这里要对应上
			if w := m.windows[windowKey(b.Prefix)]; w != nil {
				w.reset()
			}
		}
	}
	m.mu.Unlock()

	if len(expired) == 0 {
		return
	}

	// 落库状态由 store 批量处理，这里只负责内存与事件。
	if _, err := m.store.ReleaseExpired(now); err != nil {
		m.log.Warn("更新过期封禁状态失败", "err", err)
	}

	for _, b := range expired {
		m.log.Info("封禁到期自动解封", "target", b.Target, "reason", b.Reason)
		m.pushEvent(&model.Event{
			Category: model.EvtUnban,
			IP:       b.Target,
			Detail:   "封禁到期，自动解封：" + b.Reason,
			Actor:    "system",
		})
	}
	m.scheduleApply()
}

// pruneWindows 淘汰长时间无活动的计数窗口，防止内存随历史 IP 无限增长。
func (m *Manager) pruneWindows() {
	cutoff := time.Now().Add(-30 * time.Minute)

	m.mu.Lock()
	defer m.mu.Unlock()
	for k, w := range m.windows {
		if w.last.Before(cutoff) {
			delete(m.windows, k)
		}
	}
}

// purgeEvents 清理超过保留期的事件。
func (m *Manager) purgeEvents() {
	before := time.Now().AddDate(0, 0, -30)
	if n, err := m.store.PurgeEvents(before); err == nil && n > 0 {
		m.log.Info("清理历史事件", "removed", n)
	}
}

// pushEvent 异步入队一条事件。队列满时直接丢弃，绝不阻塞判定路径。
func (m *Manager) pushEvent(e *model.Event) {
	if e.Ts.IsZero() {
		e.Ts = time.Now()
	}
	select {
	case m.eventCh <- e:
	default:
		m.droppedEvents++
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
	key := m.banKeyLocked(addr, policy)
	if b, ok := m.bans[key]; ok {
		if b.Expires.IsZero() || b.Expires.After(now) {
			return b, true
		}
		return nil, false
	}
	for _, b := range m.bans {
		if !b.Prefix.Contains(addr) {
			continue
		}
		if b.Expires.IsZero() || b.Expires.After(now) {
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

// windowKey 是滑动窗口计数的 key。始终用纯 IP，
// 因为频次统计要精确到单个来源，不能跟着封禁粒度走。
func windowKey(p netip.Prefix) string {
	return p.Addr().String()
}

// matchAnyLocked 判断地址是否命中某个前缀集合。调用方需持有锁。
func (m *Manager) matchAnyLocked(list []netip.Prefix, addr netip.Addr) bool {
	for _, p := range list {
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
		if b.Prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// blockScopeLocked 返回地址命中的黑名单范围，未命中返回空串。调用方需持有锁。
//
// 命中多条时取最严格的那条（all 优先）。排障时要回答的是"这个地址实际被挡得
// 有多死"，而不是"它命中了哪几条"；把范围最宽的那条报出来才不误导。
func (m *Manager) blockScopeLocked(list []blockTarget, addr netip.Addr) string {
	scope := ""
	for _, b := range list {
		if !b.Prefix.Contains(addr) {
			continue
		}
		if b.Scope != model.ScopeFrp {
			return model.ScopeAll
		}
		scope = model.ScopeFrp
	}
	return scope
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
