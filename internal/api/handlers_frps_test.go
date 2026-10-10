package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/dreamstation625/FrpFireWall/internal/config"
)

// TestFrpsSnippetFormats /frps/snippet 同时下发 TOML 与 JSON 两份接入配置。
//
// frp 从 v0.52.0 起三种格式都支持（TOML / YAML / JSON），用户能用的那份取决于
// 他手上配置文件的后缀。只给 TOML 的话，用 frps.json 的人得自己把片段翻译成
// JSON —— 而字段名是驼峰、改大小写会被 frp 的严格校验直接拒掉，这种翻译很容易出错。
func TestFrpsSnippetFormats(t *testing.T) {
	h := newHarness(t)

	code, r := h.call(http.MethodGet, "/api/v1/frps/snippet", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /frps/snippet 应 200，得到 %d %s", code, r.Error)
	}
	data := h.data(r)

	tomlStr := strOf(data, "snippet")
	jsonStr := strOf(data, "snippet_json")
	if tomlStr == "" {
		t.Fatal("缺少 TOML 片段")
	}
	if jsonStr == "" {
		t.Fatal("缺少 JSON 片段")
	}

	// JSON 片段必须能解析。这同时说明里面没有注释 —— 标准 JSON 不支持注释，
	// 把 TOML 那几行说明顺手带过来，frps 会在解析阶段就报
	// invalid character '/'。
	var doc struct {
		HTTPPlugins []struct {
			Name string   `json:"name"`
			Addr string   `json:"addr"`
			Path string   `json:"path"`
			Ops  []string `json:"ops"`
		} `json:"httpPlugins"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &doc); err != nil {
		t.Fatalf("下发的 JSON 片段无法解析：%v\n--- JSON ---\n%s", err, jsonStr)
	}
	if len(doc.HTTPPlugins) != 1 {
		t.Fatalf("应有 1 个 httpPlugins 元素，得到 %d", len(doc.HTTPPlugins))
	}
	p := doc.HTTPPlugins[0]

	// 三处必须描述同一件事：接口下发的 addr/path/ops、JSON 片段、TOML 片段。
	// 任何一处漂移，用户复制走的那份就是错的，而界面上两个 tab 看起来都「有内容」。
	if p.Addr != strOf(data, "addr") {
		t.Errorf("JSON addr = %q，接口 addr = %q", p.Addr, strOf(data, "addr"))
	}
	if p.Path != strOf(data, "path") {
		t.Errorf("JSON path = %q，接口 path = %q", p.Path, strOf(data, "path"))
	}

	opsRaw, ok := data["ops"].([]any)
	if !ok || len(opsRaw) == 0 {
		t.Fatalf("ops 下发异常：%v", data["ops"])
	}
	if len(p.Ops) != len(opsRaw) {
		t.Fatalf("JSON ops 有 %d 项，接口下发 %d 项", len(p.Ops), len(opsRaw))
	}
	for i, o := range opsRaw {
		s, _ := o.(string)
		if p.Ops[i] != s {
			t.Errorf("第 %d 个 op 不一致：JSON = %q，接口 = %q", i+1, p.Ops[i], s)
		}
		// ops 里绝不能出现 Ping：心跳每客户端 30s 一次，挂上来会让插件调用量
		// 乘以客户端数，小内存机器上足以把 frps 拖垮。
		if s == "Ping" {
			t.Errorf("ops 里不能包含 Ping：%v", opsRaw)
		}
	}

	for _, want := range []string{
		`name = "` + p.Name + `"`,
		`addr = "` + p.Addr + `"`,
		`path = "` + p.Path + `"`,
	} {
		if !strings.Contains(tomlStr, want) {
			t.Errorf("TOML 片段与 JSON 不一致，缺少 %q\n--- TOML ---\n%s", want, tomlStr)
		}
	}
}

func TestFrpsSnippetExposesProxyPortMappings(t *testing.T) {
	h := newHarness(t)
	_, r := h.call(http.MethodGet, "/api/v1/frps/snippet", nil)
	if rows, ok := h.data(r)["proxy_port_mappings"].([]any); !ok || len(rows) != 0 {
		t.Fatalf("空映射应返回数组: %v", h.data(r))
	}
	if err := h.srv.guard.RegisterProxyPort("u", "session", "web", "tcp", 25666, ""); err != nil {
		t.Fatal(err)
	}
	_, r = h.call(http.MethodGet, "/api/v1/frps/snippet", nil)
	rows, ok := h.data(r)["proxy_port_mappings"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("应展示端口映射: %v", h.data(r))
	}
	row := rows[0].(map[string]any)
	if row["proxy_name"] != "web" || row["port"] != float64(25666) || row["observed"] != false {
		t.Fatalf("申报不能被展示为监听已成功: %v", row)
	}
}

// TestFrpsConfigFormats 加固项同样要给两种格式。
func TestFrpsConfigFormats(t *testing.T) {
	h := newHarness(t)

	code, r := h.call(http.MethodGet, "/api/v1/frps/config", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /frps/config 应 200，得到 %d %s", code, r.Error)
	}
	data := h.data(r)

	if strOf(data, "hardening") == "" {
		t.Error("缺少 TOML 加固项")
	}
	if strOf(data, "plugin_snippet_json") == "" {
		t.Error("缺少 plugin_snippet_json")
	}

	jsonStr := strOf(data, "hardening_json")
	if jsonStr == "" {
		t.Fatal("缺少 JSON 加固项")
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &doc); err != nil {
		t.Fatalf("加固项 JSON 无法解析：%v\n--- JSON ---\n%s", err, jsonStr)
	}

	// JSON 版本里**不能**出现 auth：TOML 版本的 auth.additionalScopes 是注释掉的
	// 可选项，而 JSON 没有注释语法，写进去就等于替用户打开了 —— 它会让插件调用量
	// 随客户端数一起上涨，必须由用户自己决定。这条只放在界面上以文字说明。
	if _, bad := doc["auth"]; bad {
		t.Errorf("JSON 加固项不该包含 auth：%s", jsonStr)
	}

	transport, ok := doc["transport"].(map[string]any)
	if !ok {
		t.Fatalf("加固项缺少 transport：%s", jsonStr)
	}
	tls, ok := transport["tls"].(map[string]any)
	if !ok {
		t.Fatalf("加固项缺少 transport.tls：%s", jsonStr)
	}
	if tls["force"] != true {
		t.Errorf("transport.tls.force 应为 true，得到 %v", tls["force"])
	}
	if doc["maxPortsPerClient"] != float64(10) {
		t.Errorf("maxPortsPerClient 应为 10，得到 %v", doc["maxPortsPerClient"])
	}
}

// TestFrpsProtectPortsFlow 钉住"受保护端口可手动编辑"这条链路。
//
// 受保护端口 = bind_port ∪ 代理端口，写接口只改代理端口那一半：
// 再引入一个独立的"受保护端口"字段会出现同一件事有两个真相，而全局限速的兜底
// 规则、"仅 frp 端口"的黑名单都指着它，写岔了在界面上完全看不出来。
//
// bind_port 必须无条件包含在内：它是 frps 的接入端口，把它从受保护范围里去掉
// 等于让"仅 frp 端口"的封禁漏掉最该封的那一个。
func TestFrpsProtectPortsFlow(t *testing.T) {
	h := newHarness(t)

	code, r := h.call(http.MethodGet, "/api/v1/frps/protect-ports", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /frps/protect-ports 应 200，得到 %d %s", code, r.Error)
	}
	d := h.data(r)
	if got := strOf(d, "proxy_ports"); got != "80,443" {
		t.Fatalf("默认代理端口 = %q，期望 80,443", got)
	}
	if got := strOf(d, "ports"); got != "80,443,7000" {
		t.Fatalf("默认受保护端口 = %q，期望 80,443,7000（bind_port 必须包含在内）", got)
	}

	// 写：乱序 + 重复 + 区间，后端负责归一化
	code, r = h.call(http.MethodPut, "/api/v1/frps/protect-ports",
		map[string]any{"proxy_ports": "9000-9100, 8080 ,8080"})
	if code != http.StatusOK {
		t.Fatalf("PUT /frps/protect-ports 应 200，得到 %d %s", code, r.Error)
	}
	d = h.data(r)
	if got := strOf(d, "proxy_ports"); got != "8080,9000-9100" {
		t.Errorf("归一化后的代理端口 = %q，期望 8080,9000-9100", got)
	}
	if got := strOf(d, "ports"); got != "7000,8080,9000-9100" {
		t.Errorf("受保护端口 = %q，期望 7000,8080,9000-9100", got)
	}

	// 落了库：重启后 FromSettings 读的就是这个键，值必须能原样还原。
	saved, err := h.srv.store.GetSetting(config.KeyProxyPorts)
	if err != nil {
		t.Fatalf("读回配置失败：%v", err)
	}
	if saved != "8080,9000-9100" {
		t.Errorf("库里的代理端口 = %q，期望 8080,9000-9100", saved)
	}

	// 立即生效：再读一次拿到的是新值，不是启动时的快照
	code, r = h.call(http.MethodGet, "/api/v1/frps/protect-ports", nil)
	if code != http.StatusOK {
		t.Fatalf("再次 GET 应 200，得到 %d %s", code, r.Error)
	}
	if got := strOf(h.data(r), "ports"); got != "7000,8080,9000-9100" {
		t.Errorf("重新读取的受保护端口 = %q，说明没有热更", got)
	}

	// 热更过的字段不该再让配置页报"需要重启"：它已经在生效了。
	// 报错会让用户去重启一个完全不必要的服务，重启期间所有隧道都会断。
	code, r = h.call(http.MethodGet, "/api/v1/config", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /config 应 200，得到 %d %s", code, r.Error)
	}
	if need, _ := h.data(r)["restart_required"].(bool); need {
		t.Error("只改过代理端口，却被判定为需要重启")
	}
}

// TestFrpsProtectPortsRejectsBadInput 端口写错必须当场报错，不能静默落一个
// "看起来配了、其实没生效"的值。
func TestFrpsProtectPortsRejectsBadInput(t *testing.T) {
	h := newHarness(t)

	cases := []struct {
		name string
		body map[string]any
	}{
		// 空值会被 FromSettings 当成"没配过"回落成默认的 80,443，
		// 于是保存完看着生效了、重启之后又变回去。
		{"缺字段", map[string]any{}},
		{"空串", map[string]any{"proxy_ports": ""}},
		{"只有分隔符", map[string]any{"proxy_ports": " , ; "}},
		{"非法写法", map[string]any{"proxy_ports": "8080~9000"}},
		{"越界端口", map[string]any{"proxy_ports": "70000"}},
		{"写成布尔", map[string]any{"proxy_ports": true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, r := h.call(http.MethodPut, "/api/v1/frps/protect-ports", c.body)
			if code != http.StatusBadRequest {
				t.Fatalf("应 400，得到 %d %s", code, r.Error)
			}
		})
	}

	// 报错之后旧值必须原封不动：半路失败留下一份改了一半的配置是最坏的结果。
	code, r := h.call(http.MethodGet, "/api/v1/frps/protect-ports", nil)
	if code != http.StatusOK {
		t.Fatalf("GET 应 200，得到 %d %s", code, r.Error)
	}
	if got := strOf(h.data(r), "proxy_ports"); got != "80,443" {
		t.Errorf("一连串失败请求之后代理端口 = %q，期望仍是默认的 80,443", got)
	}
}
