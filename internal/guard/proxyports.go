package guard

import (
	"fmt"
	"sort"
)

// NewProxy 在监听成功前调用，只能学习明确的固定 TCP 端口。
// 不推断随机端口、共享 HTTP/HTTPS 端口或负载均衡组端口，也不把快照落库。
// 重启后重新学习，避免把旧会话的端口误用于新连接。
const maxProxyPortMappings = 4096

type proxyPortKey struct {
	user, runID, name string
}

// ProxyPortView 展示已申报的端口；收到同会话的新连接后才标记为已使用。
// 这不是在线代理列表：失败的注册没有成功/失败回调，可能只留下申报记录。
type ProxyPortView struct {
	User      string `json:"user"`
	ProxyName string `json:"proxy_name"`
	ProxyType string `json:"proxy_type"`
	Port      int    `json:"port"`
	Observed  bool   `json:"observed"`
	Problem   string `json:"problem,omitempty"`
}

// RegisterProxyPort 只记录元数据，不参与频次统计、不新增封禁。
// 按用户、会话和代理名隔离，失败的同名抢注不能覆盖原会话的端口。
func (m *Manager) RegisterProxyPort(user, runID, name, kind string, port int, group string) error {
	if runID == "" || name == "" || len(user) > 256 || len(runID) > 256 || len(name) > 256 {
		return fmt.Errorf("代理端口映射缺少有效会话或代理名")
	}
	v := ProxyPortView{User: user, ProxyName: name, ProxyType: kind}
	switch {
	case kind != "tcp":
		v.Problem = "仅支持固定端口的 TCP 代理"
	case group != "":
		v.Problem = "负载均衡组的实际监听端口无法由注册回调确认"
	case port < 1 || port > 65535:
		v.Problem = "未申报有效固定端口（随机端口不支持）"
	default:
		v.Port = port
	}
	key := proxyPortKey{user, runID, name}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proxyPortMappings == nil {
		m.proxyPortMappings = make(map[proxyPortKey]ProxyPortView)
	}
	if old, ok := m.proxyPortMappings[key]; ok {
		// NewProxy 是注册前的请求，重复注册可能失败，不能直接覆盖正在使用的值。
		// 无法确认是哪次注册生效时，退回未知端口，避免错误扩大匹配范围。
		if old.Port != v.Port || old.ProxyType != v.ProxyType || old.Problem != v.Problem {
			old.Port = 0
			old.Problem = "同一会话的代理申报发生冲突，请重新连接后学习端口"
		}
		m.proxyPortMappings[key] = old
		return nil
	}
	if len(m.proxyPortMappings) >= maxProxyPortMappings {
		return fmt.Errorf("代理端口映射已达到 %d 条上限，新代理端口保持未知", maxProxyPortMappings)
	}
	m.proxyPortMappings[key] = v
	return nil
}

func (m *Manager) RemoveProxyPort(user, runID, name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.proxyPortMappings, proxyPortKey{user, runID, name})
}

// ResolveProxyPort 只给同一会话、同类型的连接提供端口；未知时返回 0。
func (m *Manager) ResolveProxyPort(user, runID, name, kind string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := proxyPortKey{user, runID, name}
	v, ok := m.proxyPortMappings[key]
	if !ok || v.ProxyType != kind || v.Port == 0 {
		return 0
	}
	if !v.Observed {
		v.Observed = true
		m.proxyPortMappings[key] = v
	}
	return v.Port
}

func (m *Manager) ProxyPortMappings() []ProxyPortView {
	m.mu.RLock()
	out := make([]ProxyPortView, 0, len(m.proxyPortMappings))
	for _, v := range m.proxyPortMappings {
		out = append(out, v)
	}
	m.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].ProxyName != out[j].ProxyName {
			return out[i].ProxyName < out[j].ProxyName
		}
		if out[i].User != out[j].User {
			return out[i].User < out[j].User
		}
		return out[i].Port < out[j].Port
	})
	return out
}
