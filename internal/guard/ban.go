package guard

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/geoip"
	"github.com/dreamstation625/FrpFireWall/internal/model"
)

// Apply 触发一次异步重新对齐。改完名单或策略后调用。
func (m *Manager) Apply() { m.scheduleApply() }

// triggerBan 是引擎内部触发的封禁（频次超限 / GeoIP 命中）。
func (m *Manager) triggerBan(addr netip.Addr, source, reason, user string, geo *geoip.Info) {
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
			Category: model.EvtBan,
			IP:       target,
			User:     user,
			Country:  country,
			Province: province,
			Detail:   "【观察模式】" + reason,
			Actor:    "system",
		})
		return
	}

	dur, step := m.nextDuration(target, policy)

	now := time.Now()
	rec := &model.BanRecord{
		Target:      target,
		TargetType:  model.TargetTypeOf(target),
		Reason:      reason,
		Source:      source,
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
		Prefix:   prefix,
		Target:   target,
		Reason:   reason,
		Source:   source,
		User:     user,
		RecordID: rec.ID,
		HitCount: step,
		BannedAt: now,
		Country:  country,
		Province: province,
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
		Category: model.EvtBan,
		IP:       target,
		User:     user,
		Country:  country,
		Province: province,
		Detail:   detail,
		Actor:    "system",
	})

	m.scheduleApply()
}

// BanManual 人工封禁。dur <= 0 表示永久。
func (m *Manager) BanManual(target, reason, by string, dur time.Duration) (*model.BanRecord, error) {
	p, err := parsePrefixOrAddr(strings.TrimSpace(target))
	if err != nil {
		return nil, fmt.Errorf("地址格式不正确: %w", err)
	}
	if IsSystemProtected(p.Addr()) {
		return nil, fmt.Errorf("该地址属于系统保护范围（回环 / 内网 / 链路本地），不允许封禁")
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
	p, err := parsePrefixOrAddr(strings.TrimSpace(target))
	if err != nil {
		return fmt.Errorf("地址格式不正确: %w", err)
	}
	t := p.String()

	m.mu.Lock()
	st, ok := m.bans[t]
	delete(m.bans, t)
	if st != nil {
		if w := m.windows[windowKey(st.Prefix)]; w != nil {
			w.reset()
		}
	}
	m.mu.Unlock()

	if ok && st.RecordID > 0 {
		if err := m.store.ReleaseBan(st.RecordID, by, model.BanReleased); err != nil {
			m.log.Warn("更新封禁记录状态失败", "err", err, "id", st.RecordID)
		}
	}

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
	rec, err := m.store.GetBan(id)
	if err != nil {
		return fmt.Errorf("封禁记录不存在: %w", err)
	}
	if rec.Status != model.BanActive {
		return fmt.Errorf("该记录状态为 %s，无需解封", rec.Status)
	}

	m.mu.Lock()
	_, ok := m.bans[rec.Target]
	delete(m.bans, rec.Target)
	if w := m.windows[rec.TargetAddr()]; w != nil {
		w.reset()
	}
	m.mu.Unlock()

	if err := m.store.ReleaseBan(rec.ID, by, model.BanReleased); err != nil {
		return fmt.Errorf("更新记录状态失败: %w", err)
	}

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

// nextDuration 按阶梯策略算出本次封禁时长与阶梯序号。
//
// 阶梯判定依据：查该 target 最近一条封禁记录，若还在升级窗口内则往上跳一级，
// 否则从第一级重新开始。这样"偶尔踩线"和"持续攻击"会被区别对待。
func (m *Manager) nextDuration(target string, policy *model.Policy) (time.Duration, int) {
	if policy == nil {
		return 10 * time.Minute, 1
	}

	steps := policy.DurationSteps()
	step := 0

	if last, err := m.store.LastBanOfTarget(target); err == nil && last != nil {
		window := time.Duration(policy.EscalateWindowHours) * time.Hour
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
	return time.Duration(sec) * time.Second, step + 1
}

// banPrefix 根据策略决定封禁粒度：单 IP 还是 /24 网段。
func (m *Manager) banPrefix(addr netip.Addr, policy *model.Policy) netip.Prefix {
	if policy != nil && policy.BanGranularity == "cidr24" && addr.Is4() {
		return netip.PrefixFrom(addr, 24).Masked()
	}
	return netip.PrefixFrom(addr, addr.BitLen())
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
