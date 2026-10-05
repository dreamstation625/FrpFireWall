package guard

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/geoip"
	"github.com/dreamstation625/FrpFireWall/internal/model"
	"github.com/dreamstation625/FrpFireWall/internal/portrange"
)

// Apply 触发一次异步重新对齐。改完名单或策略后调用。
func (m *Manager) Apply() { m.scheduleApply() }

// triggerBan 是引擎内部触发的封禁（频次超限 / GeoIP 命中 / 命中细分规则）。
//
// steps 是本次使用的阶梯封禁时长，由调用方给：细分规则自带自己的阶梯，
// 全局策略用 Policy 里的那份。见 nextDuration 的说明。
//
// sourceRef 指向触发这条封禁的**具体来源**（名单条目 / 细分规则），形如 "acl:12"；
// 频次自动封禁、全局地域名单留空。它的用途是联动解禁：来源被删除或停用时，
// 由它封掉的地址要一起解封 —— 否则"删掉了那条名单，被它封的地址还是进不来"，
// 而界面上已经看不到那条名单了，用户只能去封禁列表里一个个手点。
func (m *Manager) triggerBan(
	addr netip.Addr, source, reason, user, proxy string,
	geo *geoip.Info, steps []int64, sourceRef string,
) {
	m.banMu.Lock()
	defer m.banMu.Unlock()
	addr = addr.Unmap()

	m.mu.RLock()
	policy := m.policy
	m.mu.RUnlock()

	prefix := m.banPrefix(addr, policy)
	target := prefix.String()

	m.mu.RLock()
	_, exists := m.bans[target]
	m.mu.RUnlock()
	if exists {
		return // 已在封禁中，不重复建记录
	}

	country, province := "", ""
	if geo != nil {
		country, province = geo.Country, geo.Province
	}

	// 观察模式：只留下决策痕迹，不真正封禁。上线初期用它验证阈值是否合适。
	observe := m.dryRun() || (policy != nil && policy.ObserveOnly)
	if observe {
		m.log.Info("观察模式：记录封禁决策但不下发", "target", target, "reason", reason)
		m.pushEvent(&model.Event{
			Category:  model.EvtObserved,
			IP:        target,
			User:      user,
			ProxyName: proxy,
			Country:   country,
			Province:  province,
			Detail:    "【观察模式】" + reason,
			Actor:     "system",
		})
		return
	}

	if policy != nil && !policy.AutoBanEnabled {
		return
	}
	dur, step := m.nextDuration(target, policy, steps)

	now := time.Now()
	rec := &model.BanRecord{
		Target:     target,
		TargetType: model.TargetTypeOf(target),
		// 自动封禁固定全端口。它不是人在盯着做的决定，误伤代价更大（把正常用户
		// 的 SSH 一起挡了），但"只封 frp 端口"会让暴力破解者仍能扫其它端口 ——
		// 权衡后宁可封得死一点，需要放宽的场景由人工改条目范围来兜。
		Scope:       model.ScopeAll,
		Reason:      reason,
		Source:      source,
		SourceRef:   sourceRef,
		TriggerUser: user,
		HitCount:    step,
		Country:     country,
		Province:    province,
		Status:      model.BanActive,
		BannedAt:    now,
	}
	if dur > 0 {
		e := now.Add(dur)
		rec.ExpiresAt = &e
	}

	if err := m.store.CreateBan(rec); err != nil {
		m.log.Error("写入封禁记录失败，封禁未生效", "err", err, "target", target)
		return
	}

	st := &banState{
		Prefix:    prefix,
		Target:    target,
		Scope:     model.ScopeAll,
		Reason:    reason,
		Source:    source,
		SourceRef: sourceRef,
		User:      user,
		RecordID:  rec.ID,
		HitCount:  step,
		BannedAt:  now,
		Country:   country,
		Province:  province,
	}
	if rec.ExpiresAt != nil {
		st.Expires = *rec.ExpiresAt
	}

	m.mu.Lock()
	m.bans[target] = st
	m.mu.Unlock()

	detail := fmt.Sprintf("触发封禁（%s）：%s", sourceLabel(source), reason)
	if st.Permanent() {
		detail += "；时长：永久（第 " + fmt.Sprint(step) + " 级）"
	} else {
		detail += fmt.Sprintf("；时长：%s（第 %d 级）", humanDuration(dur), step)
	}

	m.log.Warn("执行封禁", "target", target, "source", source, "reason", reason)

	m.pushEvent(&model.Event{
		Category:  model.EvtBan,
		IP:        target,
		User:      user,
		ProxyName: proxy,
		Country:   country,
		Province:  province,
		Detail:    detail,
		Actor:     "system",
	})

	m.scheduleApply()
}

// BanManual 人工封禁。dur <= 0 表示永久；scope 为空按全端口处理。
//
// ports 只在 scope=custom 时用得上，其余范围忽略（接口层已经挡住了这种情况，
// 这里再判一次是因为 guard 也可能被别的调用方直接调）。
func (m *Manager) BanManual(target, reason, by string, dur time.Duration, scope string, ports portrange.Set) (*model.BanRecord, error) {
	m.banMu.Lock()
	defer m.banMu.Unlock()
	p, err := parsePrefixOrAddr(strings.TrimSpace(target))
	if err != nil {
		return nil, fmt.Errorf("地址格式不正确: %w", err)
	}
	if IsSystemProtected(p.Addr()) {
		return nil, fmt.Errorf("该地址属于系统保护范围（回环 / 内网 / 链路本地），不允许封禁")
	}
	if scope == "" {
		scope = model.ScopeAll
	}
	if !model.ValidScope(scope) {
		return nil, fmt.Errorf("封禁范围只能是 %s / %s / %s",
			model.ScopeAll, model.ScopeFrp, model.ScopeCustom)
	}
	// 自定义范围没端口就等于"封了等于没封"：内核规则一条都生成不出来，
	// 而界面上它会正常显示成一条生效中的封禁。所以这里直接拒绝，不放行。
	if model.ScopeNeedsPorts(scope) {
		if ports = ports.Normalize(); len(ports) == 0 {
			return nil, fmt.Errorf("「自定义端口」范围需要至少一个端口，例如 8080 或 9000-9100")
		}
	} else {
		ports = nil
	}
	if reason == "" {
		reason = "人工封禁"
	}
	if by == "" {
		by = "admin"
	}

	t := p.String()

	m.mu.RLock()
	_, exists := m.bans[t]
	white := m.matchAnyLocked(m.white, p.Addr())
	m.mu.RUnlock()

	if exists {
		return nil, fmt.Errorf("%s 已在封禁中", t)
	}
	if white {
		return nil, fmt.Errorf("%s 在白名单中，请先从白名单移除再封禁", t)
	}

	geo := m.lookupGeo(p.Addr())
	now := time.Now()

	rec := &model.BanRecord{
		Target:     t,
		TargetType: model.TargetTypeOf(t),
		Scope:      scope,
		Ports:      ports.String(),
		Reason:     reason,
		Source:     model.SourceManual,
		HitCount:   1,
		Country:    geo.Country,
		Province:   geo.Province,
		Status:     model.BanActive,
		BannedAt:   now,
	}
	if dur > 0 {
		e := now.Add(dur)
		rec.ExpiresAt = &e
	}
	if err := m.store.CreateBan(rec); err != nil {
		return nil, fmt.Errorf("写入封禁记录失败: %w", err)
	}

	st := &banState{
		Prefix:   p,
		Target:   t,
		Scope:    scope,
		Ports:    ports,
		Reason:   reason,
		Source:   model.SourceManual,
		RecordID: rec.ID,
		HitCount: 1,
		BannedAt: now,
		Country:  geo.Country,
		Province: geo.Province,
	}
	if rec.ExpiresAt != nil {
		st.Expires = *rec.ExpiresAt
	}

	m.mu.Lock()
	m.bans[t] = st
	m.mu.Unlock()

	detail := "人工封禁：" + reason
	if st.Permanent() {
		detail += "；时长：永久"
	} else {
		detail += "；时长：" + humanDuration(dur)
	}
	// 封禁范围必须进审计：事后追查"这个地址当时到底被封了什么"时，
	// 只写"人工封禁"是答不出来的，而范围恰恰是最容易记错的一项。
	detail += "；范围：" + scopeLabelFor(scope, ports)
	m.pushEvent(&model.Event{
		Category: model.EvtBan,
		IP:       t,
		Country:  geo.Country,
		Province: geo.Province,
		Detail:   detail,
		Actor:    by,
	})

	m.scheduleApply()
	return rec, nil
}

// Unban 按地址解封。
func (m *Manager) Unban(target, by string) error {
	m.banMu.Lock()
	defer m.banMu.Unlock()
	p, err := parsePrefixOrAddr(strings.TrimSpace(target))
	if err != nil {
		return fmt.Errorf("地址格式不正确: %w", err)
	}
	t := p.String()

	m.mu.RLock()
	st, ok := m.bans[t]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%s 当前不在封禁列表中", t)
	}
	if st.RecordID > 0 {
		if err := m.store.ReleaseBan(st.RecordID, by, model.BanReleased); err != nil {
			return fmt.Errorf("更新封禁记录失败: %w", err)
		}
	}
	m.mu.Lock()
	delete(m.bans, t)
	m.resetWindowsForLocked(t)
	m.mu.Unlock()

	m.pushEvent(&model.Event{
		Category: model.EvtUnban,
		IP:       t,
		Detail:   "人工解封",
		Actor:    by,
	})
	m.scheduleApply()

	if !ok {
		return fmt.Errorf("%s 当前不在封禁列表中", t)
	}
	return nil
}

// UnbanByRecordID 按封禁记录 ID 解封。前端列表用的是记录 ID。
func (m *Manager) UnbanByRecordID(id uint, by string) error {
	m.banMu.Lock()
	defer m.banMu.Unlock()
	rec, err := m.store.GetBan(id)
	if err != nil {
		return fmt.Errorf("封禁记录不存在: %w", err)
	}
	if rec.Status != model.BanActive {
		return fmt.Errorf("该记录状态为 %s，无需解封", rec.Status)
	}

	if err := m.store.ReleaseBan(rec.ID, by, model.BanReleased); err != nil {
		return fmt.Errorf("更新记录状态失败: %w", err)
	}
	m.mu.Lock()
	_, ok := m.bans[rec.Target]
	delete(m.bans, rec.Target)
	m.resetWindowsForLocked(rec.Target)
	m.mu.Unlock()

	m.pushEvent(&model.Event{
		Category: model.EvtUnban,
		IP:       rec.Target,
		Detail:   "人工解封",
		Actor:    by,
	})
	m.scheduleApply()

	if !ok {
		m.log.Info("解封的记录在内存中已不存在，仅更新了数据库状态", "target", rec.Target)
	}
	return nil
}

// ReleaseBansByRef 解除由某条来源（名单条目 / 细分规则）触发的活跃封禁。
//
// 用在"来源被删除或停用"的场景：删掉一条名单之后，被它封掉的地址还挂在封禁
// 列表里，而界面上已经看不到那条名单了 —— 用户既不知道该点哪几条，
// 也想不通"我明明删了，为什么它还进不来"。规则被停用/删除同理。
//
// 数据库按来源解除全部活跃行，包含旧版本遗留的重复记录；成功后同步更新内存。
//
// 没有匹配的封禁不算错误 —— 那条来源可能一个地址都没封过，这是正常情况。
func (m *Manager) ReleaseBansByRef(ref, by, why string) (int, error) {
	m.banMu.Lock()
	defer m.banMu.Unlock()
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return 0, nil
	}

	m.mu.Lock()
	hits := make([]*banState, 0, 4)
	for _, b := range m.bans {
		if b.SourceRef != ref {
			continue
		}
		hits = append(hits, b)
	}
	m.mu.Unlock()

	count, err := m.store.ReleaseBansByRef(ref, by)
	if err != nil {
		return 0, fmt.Errorf("更新封禁记录状态失败: %w", err)
	}

	m.mu.Lock()
	for _, b := range hits {
		delete(m.bans, b.Target)
		m.resetWindowsForLocked(b.Prefix.String())
	}
	m.mu.Unlock()
	for _, b := range hits {
		m.pushEvent(&model.Event{
			Category: model.EvtUnban,
			IP:       b.Target,
			Detail:   "来源已移除，自动解封：" + why,
			Actor:    by,
		})
	}
	m.scheduleApply()

	m.log.Info("来源移除，联动解封", "ref", ref, "count", len(hits), "reason", why)
	return int(count), nil
}

// nextDuration 按阶梯策略算出本次封禁时长与阶梯序号。
//
// 阶梯**表**由调用方给：细分规则自带自己的阶梯，全局策略用 Policy 里的那份。
// 传空则回退到全局，再空则回退到 10 分钟（策略表被改坏时的兜底，不能让封禁
// 因为"没读到配置"变成 0 秒即立刻解封）。
//
// 阶梯**序号**仍然只看该地址最近一次封禁是第几级，与"这次是哪条规则触发的"
// 无关。理由：升级说的是"这个人屡教不改"，换一条规则命中不改变这个事实。
// 反过来，如果按规则分别记序号，攻击者只要在两条规则之间来回触发，
// 等级就会被永远压在第一级 —— 那正好是升级机制想防的事。
func (m *Manager) nextDuration(target string, policy *model.Policy, steps []int64) (time.Duration, int) {
	if len(steps) == 0 && policy != nil {
		steps = policy.DurationSteps()
	}
	if len(steps) == 0 {
		steps = []int64{600}
	}

	windowHours := 0
	if policy != nil {
		windowHours = policy.EscalateWindowHours
	}

	step := 0
	if last, err := m.store.LastBanOfTarget(target); err == nil && last != nil {
		window := model.SafeHours(windowHours)
		if window > 0 && time.Since(last.BannedAt) < window {
			step = last.HitCount
		}
	}
	if step >= len(steps) {
		step = len(steps) - 1
	}
	if step < 0 {
		step = 0
	}

	sec := steps[step]
	if sec <= 0 {
		return 0, step + 1 // 0 表示永久
	}
	return model.SafeSeconds(sec), step + 1
}

// banStepsForEntry 把"名单条目的到期时刻"翻译成 triggerBan 要的阶梯表。
//
// 为什么要单独给地区条目算时长，而不是沿用全局阶梯：那个「有效期」就是用户对
// "这条拦截持续多久"的声明，无视它会出现两个说不通的现象 ——
//
//   - 设成 1 小时的条目，命中后却封 10 分钟（全局阶梯的第一级）；
//   - 同一个条目的多次命中时长还不一样，因为 nextDuration 会按**该地址自己的
//     封禁历史**往上升级（默认阶梯 600,3600,86400,0、升级窗口 24 小时）。
//     一批地址同时被测，有的封 10 分钟有的封 1 小时，看起来毫无规律。
//
// 升级阶梯是给频次自动封禁设计的（"这个人屡教不改"）；一条人工写下的地区条目
// 本来就带着明确的存续期，不该再受该地址历史的影响。
//
// 传单元素阶梯等价于"固定时长、不升级"：nextDuration 会把序号夹到 0，
// 剩下的元素取不到。这与它"返回第几级"的语义不冲突。
//
// 与地址黑名单条目也正好对齐 —— 那种条目是常驻内核规则，条目在就封着、
// 条目删掉或过期就自动放行；地区条目没有内核对象可依赖，所以在这里把
// "封到条目到期为止"显式写出来，两者的存续期语义才一致。
func banStepsForEntry(expiresAt *time.Time, now time.Time) []int64 {
	if expiresAt == nil {
		// 永久条目 ⇒ 封永久（阶梯里的 0 就是永久），与"永久地址条目"一致。
		return []int64{0}
	}
	sec := int64(expiresAt.Sub(now) / time.Second)
	if sec < 1 {
		// 理论上到不了这里：过期条目在 toGeoEntries 就被筛掉了。
		// 万一撞上（快照刚加载完、条目在这一瞬间到期），封 1 秒 ——
		// 立刻到期等价于"不封"，比回落全局阶梯封 10 分钟忠实得多。
		sec = 1
	}
	return []int64{sec}
}

// banPrefix 根据策略决定封禁粒度：单 IP 还是 /24 网段。
func (m *Manager) banPrefix(addr netip.Addr, policy *model.Policy) netip.Prefix {
	if policy != nil && policy.BanGranularity == "cidr24" && addr.Is4() {
		return netip.PrefixFrom(addr, 24).Masked()
	}
	return netip.PrefixFrom(addr, addr.BitLen())
}

// scopeLabelFor 把封禁范围渲染成给人看的文字，带自定义端口。
func scopeLabelFor(scope string, ports portrange.Set) string {
	switch scope {
	case model.ScopeFrp:
		return "仅 frp 端口"
	case model.ScopeCustom:
		return "自定义端口 " + ports.String()
	default:
		return "全部端口"
	}
}

func sourceLabel(s string) string {
	switch s {
	case model.SourceAuto:
		return "频次超限"
	case model.SourceManual:
		return "人工"
	case model.SourceGeoIP:
		return "地域"
	case model.SourceSystem:
		return "系统"
	default:
		return s
	}
}
