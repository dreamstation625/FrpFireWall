package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/dreamstation625/FrpFireWall/internal/config"
	"github.com/dreamstation625/FrpFireWall/internal/geoip"
	"github.com/dreamstation625/FrpFireWall/internal/guard"
	"github.com/dreamstation625/FrpFireWall/internal/model"
	"github.com/dreamstation625/FrpFireWall/internal/store"
)

// 进程内的整条 HTTP 链路：真 store + 真 guard + 真路由。
//
// 为什么不用单元测试糊过去：这里要覆盖的是「路由挂上了没有」「装配有没有把零件接错」
// 「请求体里的 rules 有没有真的走到存储和判定引擎」——这几件事都在装配层，
// 拿纯函数单测是测不到的。路由尤其值得盯：gin 对冲突路径**直接 panic**，
// 一挂就是整个面板起不来，而且只有真正启动过一次才会发现。
type harness struct {
	t     *testing.T
	ts    *httptest.Server
	srv   *Server
	token string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	gin.SetMode(gin.TestMode)

	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.Default()

	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("打开测试库失败：%v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	geo := geoip.New(t.TempDir())
	// drv 传 nil：判定与接口都不依赖驱动，Apply() 只是往一个带缓冲的 channel
	// 里塞信号（非阻塞），没有消费者也不会卡住。
	g := guard.New(cfg, st, geo, nil, discard)

	srv := New(cfg, st, geo, g, nil, nil, "test-secret", "admin", "x", nil, discard)

	// 直接签发 token，跳过 bcrypt 登录：本文件测的是策略与规则，
	// 鉴权在冒烟脚本里另有一套（那边走真实登录）。
	token, _, err := srv.issueToken("admin")
	if err != nil {
		t.Fatalf("签发 token 失败：%v", err)
	}

	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(ts.Close)

	return &harness{t: t, ts: ts, srv: srv, token: token}
}

type resp struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data"`
	Error string          `json:"error"`
}

// call 发一个带鉴权的请求，返回状态码与解出来的响应体。
func (h *harness) call(method, path string, body any) (int, resp) {
	h.t.Helper()

	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, h.ts.URL+path, rdr)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()

	raw, _ := io.ReadAll(res.Body)
	var out resp
	_ = json.Unmarshal(raw, &out)
	if out.Error == "" && !out.OK {
		// 路由层的响应（比如 404）没有 ok 字段，直接留原文便于排查
		out.Error = strings.TrimSpace(string(raw))
	}
	return res.StatusCode, out
}

func (h *harness) data(r resp) map[string]any {
	h.t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Data, &m); err != nil {
		h.t.Fatalf("data 不是对象：%s", string(r.Data))
	}
	return m
}

// raw 取原始响应体。
//
// 专给出文件类接口用（导出名单、导出规则）：它们返回的是 text/plain 而不是
// 那个 {ok,data} 信封，走 call 会被当成解析失败。导出内容的格式本身就是被测对象
// ——前缀怎么写的、多值用什么分隔符 —— 所以必须看原文，不能先解析成结构。
func (h *harness) raw(method, path string, body any) (int, string) {
	h.t.Helper()

	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, h.ts.URL+path, rdr)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()

	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(out)
}

// policyBody 取当前策略作为请求体模板。
//
// id / updated_at 要删掉：它们由服务端决定，带上只会让人以为客户端能改。
// 返回的模板**不含 rules 字段** —— 那正好用来测「缺席 = 不动规则」。
func (h *harness) policyBody() map[string]any {
	h.t.Helper()
	code, r := h.call(http.MethodGet, "/api/v1/policy", nil)
	if code != http.StatusOK {
		h.t.Fatalf("读策略失败：%d %s", code, r.Error)
	}
	body := h.data(r)
	delete(body, "id")
	delete(body, "updated_at")
	return body
}

func withRules(base map[string]any, rules []map[string]any) map[string]any {
	out := make(map[string]any, len(base)+1)
	for k, v := range base {
		out[k] = v
	}
	out["rules"] = rules
	return out
}

func (h *harness) rules() []any {
	h.t.Helper()
	_, r := h.call(http.MethodGet, "/api/v1/policy/rules", nil)
	list, ok := h.data(r)["rules"].([]any)
	if !ok {
		h.t.Fatalf("rules 不是数组：%s", string(r.Data))
	}
	return list
}

// 路由必须能注册成功且各自可达。
//
// gin 对 "/policy" 与 "/policy/rules" 这类前缀重叠的路径有自己的插入逻辑，
// 注册冲突会直接 panic —— 整个面板起不来，且只有真正启动过一次才会暴露。
func TestPolicyRoutesRegisterAndRespond(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{
		"/api/v1/policy",
		"/api/v1/policy/rules",
		"/api/v1/geoip/provinces",
		"/api/v1/system/info",
	} {
		code, r := h.call(http.MethodGet, path, nil)
		if code != http.StatusOK || !r.OK {
			t.Fatalf("%s 应返回 200/ok，实际 %d（%s）", path, code, r.Error)
		}
	}

	// 无 token 应当被鉴权拦成 401，而不是 404。
	// 这两个状态码的差别就是"路由到底在不在"的证据。
	req, _ := http.NewRequest(http.MethodGet, h.ts.URL+"/api/v1/policy/rules", nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("无 token 应当是 401（路由存在）而不是 %d", res.StatusCode)
	}
}

func TestGeoProvincesEndpoint(t *testing.T) {
	h := newHarness(t)

	_, r := h.call(http.MethodGet, "/api/v1/geoip/provinces", nil)
	list, ok := h.data(r)["provinces"].([]any)
	if !ok {
		t.Fatalf("provinces 不是数组：%s", string(r.Data))
	}
	if len(list) != 34 {
		t.Fatalf("省级行政区应有 34 个，实际 %d 个", len(list))
	}
	first, _ := list[0].(map[string]any)
	if first["name"] != "北京" {
		t.Errorf("候选名应当是归一化形态（北京），实际 %v", first["name"])
	}
	if first["full"] != "北京市" {
		t.Errorf("应当同时给出完整名供展示，实际 %v", first["full"])
	}
	if first["area"] != "华北" {
		t.Errorf("应当给出大区供分组，实际 %v", first["area"])
	}
}

// 完整走一遍：PUT /policy 带 rules → 落库 → 判定引擎里真的有了。
func TestSavePolicyWithRulesEndToEnd(t *testing.T) {
	h := newHarness(t)
	base := h.policyBody()

	body := withRules(base, []map[string]any{
		{"name": "扫描端口", "ports": "443, 8443", "per_sec": 5},
		{"name": "广东访客", "provinces": "广东省", "countries": "hk", "per_sec": 5,
			"window_seconds": 30, "threshold": 3, "ban_durations": "60,300"},
	})

	if code, r := h.call(http.MethodPut, "/api/v1/policy", body); code != http.StatusOK {
		t.Fatalf("保存应当成功，实际 %d：%s", code, r.Error)
	}

	rules := h.rules()
	if len(rules) != 2 {
		t.Fatalf("应当有 2 条规则，实际 %d 条：%v", len(rules), rules)
	}
	first, _ := rules[0].(map[string]any)
	second, _ := rules[1].(map[string]any)

	// 顺序 = 数组下标，是配置的一部分，不能被改动
	if first["name"] != "扫描端口" || second["name"] != "广东访客" {
		t.Errorf("顺序被改动了：%v / %v", first["name"], second["name"])
	}
	// 落点是算出来一起返回的，界面直接显示
	if first["layer"] != model.LayerApp {
		t.Errorf("带端口的规则应当标成应用层，实际 %v", first["layer"])
	}
	if second["layer"] != model.LayerApp {
		t.Errorf("不带端口的规则应当标成应用层，实际 %v", second["layer"])
	}
	// 端口、省份、国家码都要归一化后再落库
	if first["ports"] != "443,8443" {
		t.Errorf("端口应当去掉空格，实际 %v", first["ports"])
	}
	if second["provinces"] != "广东" {
		t.Errorf("省份应当归一化（广东省 → 广东），实际 %v", second["provinces"])
	}
	if second["countries"] != "HK" {
		t.Errorf("国家码应当规范化为大写，实际 %v", second["countries"])
	}

	// 最关键的一步：规则要真的进到判定引擎里，而不只是躺在数据库里。
	// 只断言接口回显的话，Refresh / 编译整段挂掉也照样"通过"。
	if n := h.srv.guard.AppRuleCount(); n != 2 {
		t.Errorf("应用层规则应当有 2 条生效，实际 %d 条", n)
	}
	st := h.srv.guard.Stats()
	if st.KernelRuleCount != 0 {
		t.Errorf("应用层限速不应产生内核规则，实际 %d 条", st.KernelRuleCount)
	}
	if len(st.RuleProblems) != 0 {
		t.Errorf("不该有编译不过的规则：%v", st.RuleProblems)
	}
}

// rules 字段缺席 ≠ 空数组。
//
// 这是最容易写错、后果也最重的一条：两者混成一种的话，一个不带 rules 的请求
// （脚本、旧版前端）会把用户配好的规则全删掉，而且返回 200、没有任何提示。
func TestSavePolicyRulesAbsentDoesNotWipe(t *testing.T) {
	h := newHarness(t)
	base := h.policyBody()

	saved := withRules(base, []map[string]any{{"name": "保留", "countries": "HK", "per_sec": 5}})
	if code, r := h.call(http.MethodPut, "/api/v1/policy", saved); code != http.StatusOK {
		t.Fatalf("保存失败：%d %s", code, r.Error)
	}
	if n := len(h.rules()); n != 1 {
		t.Fatalf("预设的规则没存上：%d 条", n)
	}

	// 不带 rules 再存一次：规则必须原样还在
	if code, r := h.call(http.MethodPut, "/api/v1/policy", base); code != http.StatusOK {
		t.Fatalf("保存失败：%d %s", code, r.Error)
	}
	if n := len(h.rules()); n != 1 {
		t.Fatalf("不带 rules 的保存把规则清掉了：现在剩 %d 条", n)
	}

	// 显式传空数组才清空
	if code, r := h.call(http.MethodPut, "/api/v1/policy", withRules(base, []map[string]any{})); code != http.StatusOK {
		t.Fatalf("保存失败：%d %s", code, r.Error)
	}
	if n := len(h.rules()); n != 0 {
		t.Fatalf("显式空数组应当清空规则，实际还剩 %d 条", n)
	}
	if n := h.srv.guard.AppRuleCount(); n != 0 {
		t.Errorf("清空后应用层规则应当归零，实际 %d 条", n)
	}
}

// 校验失败不能留下半截状态：策略没改、规则没动。
func TestSavePolicyRejectsAndLeavesNoPartialState(t *testing.T) {
	h := newHarness(t)
	base := h.policyBody()

	before := h.srv.guard.AppRuleCount()
	beforeThreshold := base["threshold"]

	body := withRules(base, []map[string]any{
		{"name": "混搭", "countries": "HK", "ports": "70000", "per_sec": 5},
	})
	body["threshold"] = 7777 // 故意改一个字段，验证它不会被写进去

	code, r := h.call(http.MethodPut, "/api/v1/policy", body)
	if code != http.StatusBadRequest {
		t.Fatalf("应当返回 400，实际 %d（%s）", code, r.Error)
	}
	if !strings.Contains(r.Error, "无法识别") {
		t.Errorf("错误信息应当说明为什么不能生效，实际 %q", r.Error)
	}

	_, p := h.call(http.MethodGet, "/api/v1/policy", nil)
	if got := h.data(p)["threshold"]; got != beforeThreshold {
		t.Errorf("校验失败时策略不该被写进去：阈值 %v → %v", beforeThreshold, got)
	}
	if got := h.srv.guard.AppRuleCount(); got != before {
		t.Errorf("被拒的规则不该生效：%d → %d", before, got)
	}
}

func TestSavePolicyAcceptsBanOnPortRule(t *testing.T) {
	h := newHarness(t)

	body := withRules(h.policyBody(), []map[string]any{
		{"name": "内核封禁", "ports": "443", "per_sec": 5,
			"window_seconds": 60, "threshold": 3, "ban_durations": "60"},
	})

	code, r := h.call(http.MethodPut, "/api/v1/policy", body)
	if code != http.StatusOK {
		t.Fatalf("端口规则应支持阈值封禁: %d %s", code, r.Error)
	}
}

// 错误信息里要带上是第几条 —— 界面上是按顺序编号的，只说"封禁配置不完整"
// 用户得自己一条条数过去。
func TestSavePolicyRejectsPointsAtIndex(t *testing.T) {
	h := newHarness(t)

	body := withRules(h.policyBody(), []map[string]any{
		{"name": "好的", "countries": "HK", "per_sec": 5},
		{"name": "坏的", "per_sec": 5}, // 没有任何条件
	})

	code, r := h.call(http.MethodPut, "/api/v1/policy", body)
	if code != http.StatusBadRequest {
		t.Fatalf("应当返回 400，实际 %d（%s）", code, r.Error)
	}
	if !strings.HasPrefix(r.Error, "第 2 条规则：") {
		t.Errorf("错误信息应当以「第 2 条规则：」开头，实际 %q", r.Error)
	}
}

// 规则里「代理（隧道）名」的往返与两条硬约束。
//
// 往返要测是因为这条链上有个专门的守卫（TestRateRuleInputCoversAllWritableFields）
// 只检查"字段在不在 DTO 里"，不检查值有没有真的落库 —— 少一个字段赋值，
// 保存返回 200、读回来却是空的，界面上表现为"填了代理名，保存后没了"。
func TestRateRuleProxyNameRoundTrip(t *testing.T) {
	h := newHarness(t)

	code, r := h.call(http.MethodPut, "/api/v1/policy", withRules(h.policyBody(), []map[string]any{{
		"name":       "web-ssh 专用限速",
		"enabled":    true,
		"proxy_name": "web-ssh",
		"per_sec":    10,
	}}))
	if code != http.StatusOK {
		t.Fatalf("保存应当 200，实际 %d %s", code, r.Error)
	}

	list := h.rules()
	if len(list) != 1 {
		t.Fatalf("应当存下 1 条规则，实际 %d 条", len(list))
	}
	row, _ := list[0].(map[string]any)
	if row["proxy_name"] != "web-ssh" {
		t.Fatalf("读回来的 proxy_name = %v，期望 web-ssh（值没落库的话界面上就是"+
			"填了又消失，而保存返回的是 200）", row["proxy_name"])
	}
}

// 代理 + 端口必须被拒：带端口条件的规则下发到内核，那里认不出 frp 的隧道名。
// 与"地区 + 端口"是同一类冲突，只是方向不同 —— 漏掉这一半，用户配出来的规则
// 会静默少生效一半。
func TestRateRuleRejectsProxyWithPortsWithoutMapping(t *testing.T) {
	h := newHarness(t)

	code, r := h.call(http.MethodPut, "/api/v1/policy", withRules(h.policyBody(), []map[string]any{{
		"name":       "冲突规则",
		"enabled":    true,
		"proxy_name": "web-ssh",
		"ports":      "7000",
		"per_sec":    10,
	}}))
	if code != http.StatusBadRequest || !strings.Contains(r.Error, "目的端口留空") {
		t.Fatalf("没有映射时需明确拒绝组合: %d %s", code, r.Error)
	}

}

// /events/proxy-names 给规则编辑器提供候选。
//
// 排序按"最近出现"而不是字母序：用户要找的是最近在动的那个隧道，字母序会把
// 一堆 test-xxx 顶在最前面。空库必须返回空数组而不是 null —— 前端拿 null 就得
// 处处兜底（见 store 里其它列表的同一条约定）。
func TestProxyNamesEndpoint(t *testing.T) {
	h := newHarness(t)

	code, r := h.call(http.MethodGet, "/api/v1/events/proxy-names", nil)
	if code != http.StatusOK {
		t.Fatalf("应 200，实际 %d %s", code, r.Error)
	}
	items, ok := h.data(r)["items"].([]any)
	if !ok {
		t.Fatalf("items 应当是数组（空库也不能是 null），实际 %s", string(r.Data))
	}
	if len(items) != 0 {
		t.Fatalf("空库应当返回空数组，实际 %v", items)
	}

	now := time.Now()
	for i, e := range []model.Event{
		{Category: model.EvtUserConn, ProxyName: "web-1", Ts: now.Add(-2 * time.Hour)},
		{Category: model.EvtUserConn, ProxyName: "web-ssh", Ts: now.Add(-time.Minute)},
		{Category: model.EvtUserConn, ProxyName: "web-ssh", Ts: now.Add(-time.Second)},
		{Category: model.EvtLoginAttempt, Ts: now}, // 登录回调没有代理名，不该进候选
	} {
		_ = i
		if err := h.srv.store.AddEvent(&e); err != nil {
			t.Fatal(err)
		}
	}

	_, r = h.call(http.MethodGet, "/api/v1/events/proxy-names", nil)
	items, ok = h.data(r)["items"].([]any)
	if !ok {
		t.Fatalf("items 应当是数组，实际 %s", string(r.Data))
	}
	if len(items) != 2 {
		t.Fatalf("去重后应当是 2 个代理名，实际 %v", items)
	}
	// 最近出现过的 web-ssh 排在前面
	if items[0] != "web-ssh" || items[1] != "web-1" {
		t.Errorf("应当按最近出现排序，实际 %v", items)
	}
}
