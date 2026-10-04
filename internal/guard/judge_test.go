package guard

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/dreamstation625/FrpFireWall/internal/geoip"
	"github.com/dreamstation625/FrpFireWall/internal/model"
)

// 取一条刚产生的事件。
//
// 判定链的事件是投递进 channel 的（另有一个 goroutine 落库），测试里没起那个
// goroutine 也没关系 —— channel 有缓冲，事件就在里面，直接读即可。这样比"sleep
// 等落库再查库"快得多，也不用担心时序导致的偶发失败。
func takeEvent(t *testing.T, m *Manager) *model.Event {
	t.Helper()
	select {
	case e := <-m.eventCh:
		return e
	default:
		t.Fatal("判定没有产生任何事件")
		return nil
	}
}

// 代理名要落在**独立的列**上，而不是拼进详情里。
//
// 这是"事件日志里能按代理名找"的前提：拼在 detail 里的话，搜索只能靠子串碰运气
// （代理名 web-1 会连 web-10、web-100 一起捞出来），也没法排序和按列筛选。
// 反过来，detail 里再写一遍就是同一件事说两遍，界面上还得占宽度。
func TestJudgeCarriesProxyNameInItsOwnColumn(t *testing.T) {
	m := newTestManager(t)

	v := m.JudgeUserConn(netip.MustParseAddr("203.0.113.5"), "203.0.113.5:1234", "u", "web-ssh")
	if !v.Allow {
		t.Fatalf("无策略命中的来源应当放行，得到 %+v", v)
	}

	e := takeEvent(t, m)
	if e.Category != model.EvtUserConn {
		t.Fatalf("事件类别应为 %q，实际 %q", model.EvtUserConn, e.Category)
	}
	if e.ProxyName != "web-ssh" {
		t.Fatalf("proxy_name = %q，应当是回调带过来的 web-ssh —— 没落到独立列上的话界面根本没有这一列可看", e.ProxyName)
	}
	if strings.Contains(e.Detail, "web-ssh") {
		t.Errorf("详情里不该再拼代理名：%q", e.Detail)
	}
}

// Login 回调不带代理名（隧道还没建立），事件里这一列应当留空而不是编一个。
func TestJudgeLoginLeavesProxyNameEmpty(t *testing.T) {
	m := newTestManager(t)

	if v := m.JudgeLogin(netip.MustParseAddr("203.0.113.6"), "u", ""); !v.Allow {
		t.Fatalf("无策略命中的来源应当放行，得到 %+v", v)
	}
	e := takeEvent(t, m)
	if e.Category != model.EvtLoginAttempt {
		t.Fatalf("事件类别应为 %q，实际 %q", model.EvtLoginAttempt, e.Category)
	}
	if e.ProxyName != "" {
		t.Errorf("Login 回调没有代理名，proxy_name 应当为空，实际 %q", e.ProxyName)
	}
}

// 封禁事件也要带代理名：它是"哪个隧道把人招来的"唯一线索。
// 封禁是判定链触发的，代理名必须一路传进 triggerBan，中间少传一层就丢了。
func TestBanEventCarriesProxyName(t *testing.T) {
	m := newTestManager(t)

	m.triggerBan(netip.MustParseAddr("203.0.113.9"), model.SourceAuto,
		"登录尝试超阈值", "u", "web-ssh", &geoip.Info{Country: "CN"}, nil, "")

	e := takeEvent(t, m)
	if e.Category != model.EvtBan {
		t.Fatalf("事件类别应为 %q，实际 %q", model.EvtBan, e.Category)
	}
	if e.ProxyName != "web-ssh" {
		t.Errorf("封禁事件 proxy_name = %q，期望 web-ssh", e.ProxyName)
	}
}
