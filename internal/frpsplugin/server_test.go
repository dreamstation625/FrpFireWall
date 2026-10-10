package frpsplugin

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	testAddr = "127.0.0.1:9100"
	testPath = "/frps/handler"
)

// TestSnippetTOML 锁住 TOML 片段的形态。
//
// 这段文本会被用户直接复制进 frps.toml，写错了 frps 起不来，而界面上的预览
// 只能看个大概。所以逐条断言关键行。
func TestSnippetTOML(t *testing.T) {
	got := Snippet(testAddr, testPath)

	for _, want := range []string{
		"[[httpPlugins]]",
		`name = "frpfirewall"`,
		`addr = "127.0.0.1:9100"`,
		`path = "/frps/handler"`,
		`ops = ["Login", "NewProxy", "CloseProxy", "NewUserConn"]`,
		"tlsVerify = false",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("片段缺少 %q\n--- 实际 ---\n%s", want, got)
		}
	}

	// ops 里绝不能出现 Ping。心跳是每客户端 30s 一次，挂上来会让插件 QPS
	// 乘以客户端数，小内存机器上足以把 frps 拖垮 —— 这条约束靠注释提醒不够，
	// 得让改错的人立刻挂测试。
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "ops") && strings.Contains(line, "Ping") {
			t.Errorf("ops 里不能包含 Ping：%s", line)
		}
	}
}

// TestSnippetJSON 锁住 JSON 片段的形态。
//
// 字段名是 frp 的 json tag（驼峰），大小写写错会被 frp 的严格校验拒掉，
// 报 "json: unknown field" —— 用户拿到手上才发现，排查成本很高。
// 下面这些写法用 frps v0.71.0 的 `frps verify -c` 实测过（syntax is ok）。
func TestSnippetJSON(t *testing.T) {
	got := SnippetJSON(testAddr, testPath)

	// 1. 必须是合法 JSON。能解析成功同时也说明里面没有注释 ——
	//    标准 JSON 不支持注释，把 TOML 那几行说明带过来会直接解析失败。
	var doc struct {
		HTTPPlugins []struct {
			Name      string   `json:"name"`
			Addr      string   `json:"addr"`
			Path      string   `json:"path"`
			Ops       []string `json:"ops"`
			TLSVerify bool     `json:"tlsVerify"`
		} `json:"httpPlugins"`
	}
	if err := json.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatalf("生成的 JSON 无法解析：%v\n--- 实际 ---\n%s", err, got)
	}

	// 2. 内容与 TOML 版本等价。
	if len(doc.HTTPPlugins) != 1 {
		t.Fatalf("应只有一个 httpPlugins 元素，得到 %d 个", len(doc.HTTPPlugins))
	}
	p := doc.HTTPPlugins[0]
	if p.Name != "frpfirewall" {
		t.Errorf("name = %q，期望 frpfirewall", p.Name)
	}
	if p.Addr != testAddr {
		t.Errorf("addr = %q，期望 %q", p.Addr, testAddr)
	}
	if p.Path != testPath {
		t.Errorf("path = %q，期望 %q", p.Path, testPath)
	}
	if strings.Join(p.Ops, ",") != "Login,NewProxy,CloseProxy,NewUserConn" {
		t.Errorf("ops = %v，期望 [Login NewProxy CloseProxy NewUserConn]", p.Ops)
	}
	if p.TLSVerify {
		t.Error("tlsVerify 应为 false（插件只监听回环，无需 TLS）")
	}

	// 3. 字段名按驼峰输出。JSON 解析是大小写不敏感的，光看解析结果发现不了
	//    `tls_verify` 这种错写法，必须直接断言文本。
	if strings.Contains(got, "tls_verify") {
		t.Errorf("字段名应为驼峰 tlsVerify，不能写成下划线：\n%s", got)
	}
	if !strings.Contains(got, `"tlsVerify": false`) {
		t.Errorf("缺少 %q\n%s", `"tlsVerify": false`, got)
	}

	// 4. 不能有注释符。TOML 版本的说明文字如果被顺手复制到 JSON 里，
	//    frps 会在解析阶段就报错。
	if strings.Contains(got, "#") {
		t.Errorf("JSON 里不能出现注释：\n%s", got)
	}
}

// TestSnippetJSONEscapesValues 特殊字符不能让生成的配置变成非法 JSON。
//
// addr / path 来自配置，虽然界面上有校验，但生成配置这步不该依赖上游校验 ——
// 一份语法都不合法的配置丢给用户，他只会看到 frps 启动失败。
func TestSnippetJSONEscapesValues(t *testing.T) {
	got := SnippetJSON(`1.2.3.4:9100"`, `/handler"x`)

	var doc map[string]any
	if err := json.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatalf("含特殊字符时生成了非法 JSON：%v\n%s", err, got)
	}

	plugins, ok := doc["httpPlugins"].([]any)
	if !ok || len(plugins) != 1 {
		t.Fatalf("结构不对：%v", doc)
	}
	p := plugins[0].(map[string]any)
	if p["addr"] != `1.2.3.4:9100"` {
		t.Errorf("addr 转义后应还原为原值，得到 %q", p["addr"])
	}
}

// TestSnippetsAgree TOML 与 JSON 两份配置必须描述同一件事。
//
// 这是最容易漂移的地方：两份输出由两个函数生成，改了一个漏改另一个时，
// 界面看两个 tab 都「有内容」，只有复制到 frps 上才发现不一致。
func TestSnippetsAgree(t *testing.T) {
	tomlStr := Snippet(testAddr, testPath)

	var doc struct {
		HTTPPlugins []struct {
			Name string   `json:"name"`
			Addr string   `json:"addr"`
			Path string   `json:"path"`
			Ops  []string `json:"ops"`
		} `json:"httpPlugins"`
	}
	if err := json.Unmarshal([]byte(SnippetJSON(testAddr, testPath)), &doc); err != nil {
		t.Fatalf("JSON 无法解析：%v", err)
	}
	p := doc.HTTPPlugins[0]

	// 把 JSON 侧的值按 TOML 语法回写，逐条确认 TOML 侧也有同样的值。
	for _, want := range []string{
		`name = "` + p.Name + `"`,
		`addr = "` + p.Addr + `"`,
		`path = "` + p.Path + `"`,
		`ops = ["` + strings.Join(p.Ops, `", "`) + `"]`,
	} {
		if !strings.Contains(tomlStr, want) {
			t.Errorf("TOML 片段与 JSON 不一致，缺少 %q\n--- TOML ---\n%s", want, tomlStr)
		}
	}
}

// TestOpsReturnsCopy 传入的 ops 是副本，调用方改不动内部状态。
//
// API 层会把它直接下发给前端，前端改一下（或某个 handler 顺手 append）
// 就会污染所有后续请求的 ops，表现出来是「ops 越用越多」。
func TestOpsReturnsCopy(t *testing.T) {
	first := Ops()
	if len(first) != 4 {
		t.Fatalf("ops 应有 4 项，得到 %v", first)
	}

	first[0] = "Ping"

	if got := Ops()[0]; got != "Login" {
		t.Errorf("改返回值污染了内部状态，第二次拿到 %q", got)
	}
}
