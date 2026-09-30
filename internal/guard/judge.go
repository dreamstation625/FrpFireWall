package guard

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/geoip"
	"github.com/dreamstation625/FrpFireWall/internal/model"
)

// JudgeLogin 处理 frps 的 Login 插件回调。
//
// 重要限制：frps 在鉴权**之前**调用插件，插件拿不到"token 是否正确"。
// 所以本引擎统计的是**登录尝试频次**，不是"登录失败次数"。
// 对暴力破解场景结论一致（攻击者每次尝试都会触发一次回调），
// 正常客户端断线重连的频次远低于默认阈值，不会误伤。
func (m *Manager) JudgeLogin(addr netip.Addr, user, _ string) Verdict {
	return m.judge(addr, user, model.EvtLoginAttempt, "login", "")
}

// JudgeUserConn 处理 frps 的 NewUserConn 插件回调。
//
// CDN 回源场景下 remoteAddr 往往是 CDN 节点 IP，
// 对这类来源只记录、不做封禁（封一个节点等于掐死一大片正常用户）。
func (m *Manager) JudgeUserConn(clientAddr netip.Addr, remoteAddr, user, proxy string) Verdict {
	addr := clientAddr
	if ra, err := netip.ParseAddrPort(remoteAddr); err == nil {
		addr = ra.Addr()
	} else if ra2, err := netip.ParseAddr(remoteAddr); err == nil {
		addr = ra2
	}
	return m.judge(addr, user, model.EvtUserConn, "user-conn", proxy)
}

func (m *Manager) judge(addr netip.Addr, user, category, op, extra string) Verdict {
	if !addr.IsValid() {
		return Verdict{Allow: true, Reason: "invalid-address"}
	}
	addr = addr.Unmap()
	ip := addr.String()

	// 0. 系统保护地址：回环、内网、链路本地。封了没有安全收益，只会把自己锁死。
	if IsSystemProtected(addr) {
		return Verdict{Allow: true, Reason: "system-protected"}
	}

	now := time.Now()

	m.mu.RLock()
	policy := m.policy
	isWhite := m.matchAnyLocked(m.white, addr)
	isBlack := m.matchAnyLocked(m.black, addr)
	trusted := m.protect != nil && m.protect.IsTrustedProxy(addr)
	ban, banned := m.findBanLocked(addr, policy, now)
	m.mu.RUnlock()

	geoInfo := m.lookupGeo(addr)
	evt := func(detail string) {
		m.pushEvent(&model.Event{
			Category: category,
			IP:       ip,
			User:     user,
			Op:       op,
			Detail:   detail,
			Country:  geoInfo.Country,
			Province: geoInfo.Province,
		})
	}

	// 1. 白名单：直接放行，永不封禁。
	if isWhite {
		evt("命中白名单，放行")
		return Verdict{Allow: true, Reason: "whitelist"}
	}

	// 2. 手动黑名单：拒绝。
	if isBlack {
		evt("命中手动黑名单，拒绝")
		m.pushEvent(&model.Event{
			Category: model.EvtLoginBlocked, IP: ip, User: user, Op: op,
			Country: geoInfo.Country, Province: geoInfo.Province,
			Detail: "命中手动黑名单",
		})
		return Verdict{Allow: false, Reason: "blacklist", Detail: "IP 已在黑名单中"}
	}

	// 3. 活跃封禁：拒绝，并把剩余时间回给 frpc，方便运维排查。
	if banned {
		remaining := ban.Remaining(now)
		m.pushEvent(&model.Event{
			Category: model.EvtLoginBlocked, IP: ip, User: user, Op: op,
			Country: geoInfo.Country, Province: geoInfo.Province,
			Detail: "IP 处于封禁中：" + ban.Reason,
		})
		return Verdict{
			Allow:  false,
			Reason: "banned",
			Detail: banDetail(ban, remaining),
		}
	}

	// 4. 可信回源（CDN / 反代）：只记录，不参与封禁决策。
	if trusted {
		evt("来自可信回源网段，跳过封禁决策")
		return Verdict{Allow: true, Reason: "trusted-proxy"}
	}

	if policy == nil {
		return Verdict{Allow: true, Reason: "no-policy"}
	}

	// 5. GeoIP 国家/地区判定（应用层实时解析，不落内核集合）
	if policy.GeoIPBlockEnabled && geoInfo.Found && geoInfo.Country != "" {
		if m.countryBlocked(policy, geoInfo.Country) {
			reason := fmt.Sprintf("来源国家/地区 %s 命中封禁名单", geoInfo.CountryName)
			if policy.GeoIPMode == "whitelist" {
				reason = fmt.Sprintf("来源国家/地区 %s 不在放行名单内", geoInfo.CountryName)
			}
			m.triggerBan(addr, model.SourceGeoIP, reason, user, geoInfo)
			m.pushEvent(&model.Event{
				Category: model.EvtLoginBlocked, IP: ip, User: user, Op: op,
				Country: geoInfo.Country, Province: geoInfo.Province,
				Detail: reason,
			})
			return Verdict{Allow: false, Reason: "geoip-blocked", Detail: reason}
		}
	}

	// 6. 滑动窗口频次统计
	win := time.Duration(policy.WindowSeconds) * time.Second
	if win <= 0 {
		win = time.Minute
	}

	m.mu.Lock()
	w := m.windows[ip]
	if w == nil {
		w = &hitWindow{}
		m.windows[ip] = w
	}
	hits := w.add(now, win)
	m.mu.Unlock()

	if policy.Threshold > 0 && hits >= policy.Threshold {
		detail := fmt.Sprintf("%d 秒内登录尝试 %d 次，超过阈值 %d 次",
			policy.WindowSeconds, hits, policy.Threshold)

		if !policy.AutoBanEnabled {
			m.pushEvent(&model.Event{
				Category: model.EvtLoginBlocked, IP: ip, User: user, Op: op,
				Country: geoInfo.Country, Province: geoInfo.Province,
				Detail: detail + "（自动封禁已关闭，仅记录）",
			})
			return Verdict{Allow: true, Reason: "threshold-hit-no-autoban"}
		}

		m.triggerBan(addr, model.SourceAuto, detail, user, geoInfo)
		m.pushEvent(&model.Event{
			Category: model.EvtLoginBlocked, IP: ip, User: user, Op: op,
			Country: geoInfo.Country, Province: geoInfo.Province,
			Detail: detail,
		})
		return Verdict{Allow: false, Reason: "rate-exceeded", Detail: detail}
	}

	evt("放行" + extraSuffix(extra))
	return Verdict{Allow: true, Reason: "ok"}
}

func extraSuffix(extra string) string {
	if extra == "" {
		return ""
	}
	return "（" + extra + "）"
}

func banDetail(ban *banState, remaining time.Duration) string {
	if ban.Permanent() {
		return fmt.Sprintf("IP 已被永久封禁：%s", ban.Reason)
	}
	if remaining > 0 {
		return fmt.Sprintf("IP 已被封禁，剩余 %s：%s", humanDuration(remaining), ban.Reason)
	}
	return "IP 已被封禁：" + ban.Reason
}

func humanDuration(d time.Duration) string {
	if d <= 0 {
		return "0 秒"
	}
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%.1f 天", d.Hours()/24)
	case d >= time.Hour:
		return fmt.Sprintf("%.1f 小时", d.Hours())
	case d >= time.Minute:
		return fmt.Sprintf("%d 分钟", int(d.Minutes()))
	default:
		return fmt.Sprintf("%d 秒", int(d.Seconds()))
	}
}

func (m *Manager) lookupGeo(addr netip.Addr) *geoip.Info {
	if m.geo == nil {
		return &geoip.Info{IP: addr.String()}
	}
	return m.geo.Lookup(addr)
}

// countryBlocked 判断来源国家是否应被拦截。
// blacklist 模式：在列表内则拦；whitelist 模式：不在列表内则拦。
func (m *Manager) countryBlocked(policy *model.Policy, country string) bool {
	list := policy.CountryList()
	if len(list) == 0 {
		// 白名单模式下列表为空意味着"谁都不放行"，这是危险配置，这里按不放行处理
		return policy.GeoIPMode == "whitelist"
	}
	hit := false
	for _, c := range list {
		if c == country {
			hit = true
			break
		}
	}
	if policy.GeoIPMode == "whitelist" {
		return !hit
	}
	return hit
}
