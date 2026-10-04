package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
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
