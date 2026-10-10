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
//  2. NewProxy / CloseProxy 只维护端口上下文，不参与频次统计；**绝不能挂 Ping**。
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
	opNewProxy    = "NewProxy"
	opCloseProxy  = "CloseProxy"
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

type newProxyContent struct {
	User       userInfo `json:"user"`
	ProxyName  string   `json:"proxy_name"`
	ProxyType  string   `json:"proxy_type"`
	RemotePort int      `json:"remote_port"`
	Group      string   `json:"group"`
}

type closeProxyContent struct {
	User      userInfo `json:"user"`
	ProxyName string   `json:"proxy_name"`
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
	if !isLoopback(r.RemoteAddr) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
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
		port := s.mgr.ResolveProxyPort(c.User.User, c.User.RunID, c.ProxyName, c.ProxyType)
		v := s.mgr.JudgeUserConn(netip.Addr{}, c.RemoteAddr, c.User.User, c.ProxyName, port)
		return toResponse(v)

	case opNewProxy:
		var c newProxyContent
		if err := json.Unmarshal(req.Content, &c); err != nil {
			return s.onInternalError("解析 NewProxy 内容失败: " + err.Error())
		}
		if err := s.mgr.RegisterProxyPort(c.User.User, c.User.RunID, c.ProxyName, c.ProxyType, c.RemotePort, c.Group); err != nil {
			s.log.Warn("未能记录代理端口，端口条件保持未知", "proxy", c.ProxyName, "err", err)
		}
		return pluginResponse{Reject: false, Unchange: true}

	case opCloseProxy:
		var c closeProxyContent
		if err := json.Unmarshal(req.Content, &c); err != nil {
			return s.onInternalError("解析 CloseProxy 内容失败: " + err.Error())
		}
		s.mgr.RemoveProxyPort(c.User.User, c.User.RunID, c.ProxyName)
		return pluginResponse{Reject: false, Unchange: true}

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

// pluginName 是写进 frps 配置的插件名。
const pluginName = "frpfirewall"

// ops 是订阅的回调。**绝不能加 "Ping"**：心跳是每客户端 30s 一次，
// 挂上来会让插件 QPS 乘以客户端数，在小内存机器上直接把 frps 拖垮。
var ops = []string{"Login", "NewProxy", "CloseProxy", "NewUserConn"}

// Ops 返回订阅的 op 列表副本。
//
// API 层下发前端的 ops 走这里，而不是各写一份 —— 两边写岔的话，界面告诉用户
// 订阅了某几个 op，实际没订阅，这种错在界面上完全看不出来。
func Ops() []string {
	return append([]string(nil), ops...)
}

func quotedOps() string {
	out := make([]string, len(ops))
	for i, op := range ops {
		out[i] = fmt.Sprintf("%q", op)
	}
	return strings.Join(out, ", ")
}

// Snippet 生成需要追加到 frps.toml 的配置片段。
func Snippet(pluginAddr, pluginPath string) string {
	var b strings.Builder
	b.WriteString("# ===== FrpFireWall 接入配置 =====\n")
	b.WriteString("# 追加到 frps.toml 后执行 systemctl restart frps\n\n")
	b.WriteString("[[httpPlugins]]\n")
	fmt.Fprintf(&b, "name = %q\n", pluginName)
	fmt.Fprintf(&b, "addr = %q\n", pluginAddr)
	fmt.Fprintf(&b, "path = %q\n", pluginPath)
	fmt.Fprintf(&b, "ops = [%s]\n", quotedOps())
	b.WriteString("tlsVerify = false\n")
	b.WriteString("\n# 不要把 \"Ping\" 加进 ops：心跳每客户端 30s 一次，挂上来会让插件调用量\n")
	b.WriteString("# 乘以客户端数量，小内存机器上足以把 frps 拖垮。\n")
	return b.String()
}

// SnippetJSON 生成同一份接入配置的 JSON 形态，供 frps.json 使用。
//
// frp 从 v0.52.0 起同时支持 TOML / YAML / JSON（INI 已废弃），但 JSON 形态与
// TOML 片段有两处**不能照搬**的差别，界面上必须讲清楚：
//
//  1. JSON 没有「往文件末尾追加一段」的语法。httpPlugins 是顶层对象的数组字段，
//     所以要合并进现有配置（已经有 httpPlugins 数组就往里加一个元素），
//     而不是像 TOML 那样直接追加。因此这里给的是一个完整对象。
//  2. 标准 JSON 不支持注释，"不要把 Ping 加进 ops" 这类说明带不过来，
//     只能由调用方在界面上另行提示。
//
// 字段名用 frp 的 json tag（驼峰：httpPlugins / tlsVerify），**大小写不能改**：
// frp 默认开严格校验，写成 tls_verify 会被 "json: unknown field" 直接拒掉。
//
// 生成形态已用 frps v0.71.0 实测：
//
//	frps verify -c ./frps.json  →  syntax is ok
func SnippetJSON(pluginAddr, pluginPath string) string {
	// addr / path 来自配置，插值前按 JSON 规则转义，避免生成一份语法都不合法的
	// 配置让用户去 debug。string 的 Marshal 不会失败，忽略错误。
	jq := func(s string) string {
		b, _ := json.Marshal(s)
		return string(b)
	}

	var b strings.Builder
	b.WriteString("{\n")
	b.WriteString("  \"httpPlugins\": [\n")
	b.WriteString("    {\n")
	fmt.Fprintf(&b, "      \"name\": %s,\n", jq(pluginName))
	fmt.Fprintf(&b, "      \"addr\": %s,\n", jq(pluginAddr))
	fmt.Fprintf(&b, "      \"path\": %s,\n", jq(pluginPath))
	fmt.Fprintf(&b, "      \"ops\": [%s],\n", quotedOps())
	b.WriteString("      \"tlsVerify\": false\n")
	b.WriteString("    }\n")
	b.WriteString("  ]\n")
	b.WriteString("}\n")
	return b.String()
}

// HardeningTOML 是 frps.toml 侧建议的加固项，按需追加。
//
// 都是可选项目，所以整段可以原样贴过去、也可以只挑其中几行。
func HardeningTOML() string {
	return "# 以下为可选加固项，按需追加到 frps.toml\n" +
		"# 只接受启用 TLS 的客户端，减少协议层攻击面\n" +
		"transport.tls.force = true\n\n" +
		"# 让心跳与工作连接也参与插件校验（注意：会增加插件调用量）\n" +
		"# auth.additionalScopes = [\"HeartBeats\", \"NewWorkConns\"]\n\n" +
		"# 限制单个客户端的代理数量\n" +
		"maxPortsPerClient = 10\n"
}

// HardeningJSON 是同一组加固项的 JSON 形态。
//
// 比 TOML 版本**少一项**，这不是遗漏：TOML 里 auth.additionalScopes 是注释掉的
// 「可选」，而 JSON 没有注释语法 —— 写进文件就等于生效，它会让插件调用量随客户端
// 数量一起上涨。是否打开得由用户自己决定，不能由我们默认塞进去，所以这一条只在
// 界面上用文字说明。
//
// 字段名与嵌套层级经 frps v0.71.0 `frps verify -c` 实测。
func HardeningJSON() string {
	return "{\n" +
		"  \"transport\": {\n" +
		"    \"tls\": {\n" +
		"      \"force\": true\n" +
		"    }\n" +
		"  },\n" +
		"  \"maxPortsPerClient\": 10\n" +
		"}\n"
}
