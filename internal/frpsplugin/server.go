// Package frpsplugin 实现 frps 原生服务端插件协议。
//
// 协议要点（JSON over HTTP）：
//
//	POST /handler?version=0.1.0&op=Login
//	X-Frp-Reqid: <trace id>
//	{ "version": "0.1.0", "op": "Login", "content": { ... } }
//
// 响应三选一：
//
//	拒绝：            {"reject": true, "reject_reason": "..."}
//	允许且不改内容：  {"reject": false, "unchange": true}
//	允许并替换内容：  {"unchange": false, "content": { ... }}
//
// 最重要的两条工程约束：
//
//  1. frps 调用插件是**同步阻塞**的。插件超时 = 登录超时。
//     所以这里给判定加了硬超时，超时或 panic 一律 fail-open 放行。
//     理由：防火墙插件挂掉不应该导致整个 frp 服务不可用。
//
//  2. ops 只挂 Login 和 NewUserConn，**绝不能挂 Ping**。
//     心跳是每客户端 30s 一次，挂上来会让插件 QPS 乘以客户端数，
//     在小内存机器上直接把 frps 拖垮。
package frpsplugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/guard"
)

// verdictTimeout 是单次判定的硬上限。
// frps 登录本来就不该被这个插件拖慢，超过这个时间说明内部出了问题，直接放行。
const verdictTimeout = 100 * time.Millisecond

// maxBody 限制请求体大小，防止异常请求打爆内存。
const maxBody = 1 << 20

// 支持的操作。绝不包含 Ping。
const (
	opLogin       = "Login"
	opNewUserConn = "NewUserConn"
	opPing        = "Ping"
)

type Server struct {
	mgr  *guard.Manager
	log  *slog.Logger
	addr string
	path string
	srv  *http.Server

	// failOpen 为 true 时，内部异常放行；为 false 时拒绝（fail-close）。
	failOpen func() bool
}

// New 创建插件服务。listen 必须是回环地址。
func New(listen, path string, mgr *guard.Manager, log *slog.Logger, failOpen func() bool) *Server {
	if log == nil {
		log = slog.Default()
	}
	if failOpen == nil {
		failOpen = func() bool { return true }
	}
	if path == "" {
		path = "/frps/handler"
	}
	return &Server{mgr: mgr, log: log, addr: listen, path: path, failOpen: failOpen}
}

// ---- 协议结构 ----

type pluginRequest struct {
	Version string          `json:"version"`
	Op      string          `json:"op"`
	Content json.RawMessage `json:"content"`
}

type pluginResponse struct {
	Reject       bool   `json:"reject"`
	RejectReason string `json:"reject_reason,omitempty"`
	Unchange     bool   `json:"unchange,omitempty"`
}

type userInfo struct {
	User  string            `json:"user"`
	Metas map[string]string `json:"metas"`
	RunID string            `json:"run_id"`
}

type loginContent struct {
	Version       string            `json:"version"`
	Hostname      string            `json:"hostname"`
	OS            string            `json:"os"`
	Arch          string            `json:"arch"`
	User          string            `json:"user"`
	Timestamp     int64             `json:"timestamp"`
	PrivilegeKey  string            `json:"privilege_key"`
	RunID         string            `json:"run_id"`
	PoolCount     int               `json:"pool_count"`
	Metas         map[string]string `json:"metas"`
	ClientAddress string            `json:"client_address"`
}

type newUserConnContent struct {
	User       userInfo `json:"user"`
	ProxyName  string   `json:"proxy_name"`
	ProxyType  string   `json:"proxy_type"`
	RemoteAddr string   `json:"remote_addr"`
}

// ---- 生命周期 ----

// Start 启动插件服务（非阻塞）。
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc(s.path, s.handle)
	mux.HandleFunc("/healthz", s.handleHealth)

	s.srv = &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("插件服务监听 %s 失败: %w", s.addr, err)
	}
	go func() {
		if err := s.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.log.Error("插件服务退出", "err", err)
		}
	}()
	s.log.Info("frps 插件服务已启动", "addr", s.addr, "path", s.path)
	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "service": "frpfirewall-plugin"})
}

// ---- 请求处理 ----

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	// 插件接口没有任何鉴权，靠"只接受本机回环来源"兜底。
	if !isLoopback(r.RemoteAddr) {
		s.log.Warn("插件接口收到非本机请求，已拒绝", "remote", r.RemoteAddr)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	op := r.URL.Query().Get("op")

	resp := s.dispatchSafely(op, r)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// dispatchSafely 把判定放进带超时与 panic 恢复的边界里。
func (s *Server) dispatchSafely(op string, r *http.Request) pluginResponse {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		return s.onInternalError("读取请求体失败: " + err.Error())
	}

	var req pluginRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return s.onInternalError("解析请求失败: " + err.Error())
	}
	if req.Op != "" {
		op = req.Op
	}

	resultCh := make(chan pluginResponse, 1)
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("判定过程 panic", "panic", fmt.Sprint(rec), "op", op)
				resultCh <- s.failResponse("判定过程异常")
			}
		}()
		resultCh <- s.dispatch(op, req)
	}()

	select {
	case resp := <-resultCh:
		return resp
	case <-time.After(verdictTimeout):
		s.log.Warn("判定超时，按 fail 策略处理", "op", op, "timeout", verdictTimeout)
		return s.failResponse("判定超时")
	}
}

func (s *Server) dispatch(op string, req pluginRequest) pluginResponse {
	switch op {
	case opLogin:
		var c loginContent
		if err := json.Unmarshal(req.Content, &c); err != nil {
			return s.onInternalError("解析 Login 内容失败: " + err.Error())
		}
		addr := parseAddr(c.ClientAddress)
		v := s.mgr.JudgeLogin(addr, c.User, c.Hostname)
		return toResponse(v)

	case opNewUserConn:
		var c newUserConnContent
		if err := json.Unmarshal(req.Content, &c); err != nil {
			return s.onInternalError("解析 NewUserConn 内容失败: " + err.Error())
		}
		v := s.mgr.JudgeUserConn(netip.Addr{}, c.RemoteAddr, c.User.User, c.ProxyName)
		return toResponse(v)

	case opPing:
		// 理论上不会走到这里（配置里不挂 Ping）。
		// 万一被挂上了，也立刻放行，绝不参与任何统计——
		// 心跳是高频调用，一旦参与计数会瞬间把正常客户端全封掉。
		return pluginResponse{Reject: false, Unchange: true}

	default:
		// 不认识的操作一律放行，保证兼容未来新增的 op。
		return pluginResponse{Reject: false, Unchange: true}
	}
}

func (s *Server) failResponse(reason string) pluginResponse {
	if s.failOpen() {
		// fail-open：插件自身出问题不应该导致 frp 服务不可用
		s.log.Warn("按 fail-open 策略放行", "reason", reason)
		return pluginResponse{Reject: false, Unchange: true}
	}
	s.log.Warn("按 fail-close 策略拒绝", "reason", reason)
	return pluginResponse{Reject: true, RejectReason: "frpfirewall 插件异常（fail-close 模式）：" + reason}
}

func (s *Server) onInternalError(reason string) pluginResponse {
	s.log.Error("插件内部错误", "reason", reason)
	return s.failResponse(reason)
}

func toResponse(v guard.Verdict) pluginResponse {
	if v.Allow {
		return pluginResponse{Reject: false, Unchange: true}
	}
	reason := v.Detail
	if reason == "" {
		reason = v.Reason
	}
	if reason == "" {
		reason = "被 frpfirewall 拦截"
	}
	return pluginResponse{Reject: true, RejectReason: reason}
}

// ---- 辅助 ----

func isLoopback(remoteAddr string) bool {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// parseAddr 从 "1.2.3.4:5678" 解析出 IP。frps 给的 client_address 带端口。
func parseAddr(s string) netip.Addr {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a
	}
	return netip.Addr{}
}

// Snippet 生成需要追加到 frps.toml 的配置片段。
func Snippet(pluginAddr, pluginPath string) string {
	var b strings.Builder
	b.WriteString("# ===== FrpFireWall 接入配置 =====\n")
	b.WriteString("# 追加到 frps.toml 后执行 systemctl restart frps\n\n")
	b.WriteString("[[httpPlugins]]\n")
	b.WriteString("name = \"frpfirewall\"\n")
	fmt.Fprintf(&b, "addr = %q\n", pluginAddr)
	fmt.Fprintf(&b, "path = %q\n", pluginPath)
	b.WriteString("ops = [\"Login\", \"NewUserConn\"]\n")
	b.WriteString("tlsVerify = false\n")
	b.WriteString("\n# 不要把 \"Ping\" 加进 ops：心跳每客户端 30s 一次，挂上来会让插件调用量\n")
	b.WriteString("# 乘以客户端数量，小内存机器上足以把 frps 拖垮。\n")
	return b.String()
}
