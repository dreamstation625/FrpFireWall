package api

import (
	"net/http"
	"strings"
	"testing"
)

func strOf(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// TestGeoSourcesEndpoint 下载源与加速源都是下发给前端的。
//
// 加速源列表由后端给、前端不自己存一份：两边各存一份时，后端换了源前端不知道，
// 用户会选到一个后端不认识的 ID，只能拿到报错。
func TestGeoSourcesEndpoint(t *testing.T) {
	h := newHarness(t)

	code, r := h.call(http.MethodGet, "/api/v1/geoip/sources", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /geoip/sources 应 200，得到 %d %s", code, r.Error)
	}
	data := h.data(r)

	srcs, ok := data["sources"].([]any)
	if !ok || len(srcs) != 3 {
		t.Fatalf("应下发 3 个下载源，得到 %v", data["sources"])
	}
	names := make([]string, 0, len(srcs))
	for _, s := range srcs {
		m, ok := s.(map[string]any)
		if !ok {
			t.Fatalf("下载源不是对象：%v", s)
		}
		names = append(names, strOf(m, "name"))
		if strOf(m, "url") == "" || strOf(m, "repo") == "" {
			t.Errorf("下载源缺少 url / repo：%v", m)
		}
		if !strings.HasPrefix(strOf(m, "url"), "https://") {
			t.Errorf("下载源地址必须是 https：%v", m)
		}
		// repo 是界面上「前往下载源仓库」的跳转目标，前端直接拿来用。
		// 退化成 owner/repo 前端就会跳到一个坏链接，而这种错在界面上看不出来。
		if !strings.HasPrefix(strOf(m, "repo"), "https://") {
			t.Errorf("下载源 repo 必须是完整 https 地址：%v", m)
		}
		// 预估大小显示在下载按钮旁，空着用户就没法预估耗时。
		if strOf(m, "size") == "" {
			t.Errorf("下载源缺少预估大小 size：%v", m)
		}
	}
	for i, want := range []string{"GeoLite2-Country.mmdb", "GeoLite2-City.mmdb", "ip2region.xdb"} {
		if names[i] != want {
			t.Errorf("第 %d 个下载源应是 %s，得到 %s", i+1, want, names[i])
		}
	}
	// 上游文件名和落地名不一样（ip2region_v4.xdb → ip2region.xdb），
	// 前端会把它展示给用户，写错就下错文件。
	if u := strOf(srcs[2].(map[string]any), "url"); !strings.Contains(u, "ip2region_v4.xdb") {
		t.Errorf("ip2region 的上游地址应指向 ip2region_v4.xdb，得到 %q", u)
	}

	ms, ok := data["mirrors"].([]any)
	if !ok || len(ms) == 0 {
		t.Fatalf("加速源列表不能为空：%v", data["mirrors"])
	}
	for _, mm := range ms {
		m, ok := mm.(map[string]any)
		if !ok {
			t.Fatalf("加速源不是对象：%v", mm)
		}
		if strOf(m, "id") == "" || strOf(m, "name") == "" {
			t.Errorf("加速源缺少 id / name：%v", m)
		}
	}
	// 直连排最后：国内环境下 raw.githubusercontent.com 基本不可达，
	// 先试加速源能少等一轮超时。
	if last := ms[len(ms)-1].(map[string]any); strOf(last, "prefix") != "" {
		t.Errorf("直连应排在最后，最后一个是 %q", strOf(last, "name"))
	}

	if data["auto"] != "auto" {
		t.Errorf("auto 的保留值应是 auto，得到 %v", data["auto"])
	}
}

// TestGeoDownloadValidation 覆盖参数校验。
//
// 这些用例全部在发网络请求之前就返回，所以测试不依赖外网 —— 这是唯一能安全
// 断言的部分。真正下载到字节流那一段由 internal/geoip 的测试覆盖。
func TestGeoDownloadValidation(t *testing.T) {
	h := newHarness(t)

	cases := []struct {
		name    string
		body    map[string]any
		wantErr string
	}{
		{
			// 白名单外的文件名，防 ../ 越界写
			name:    "白名单外的文件名",
			body:    map[string]any{"name": "../evil.mmdb", "mirror": "auto"},
			wantErr: "不支持下载",
		},
		{
			// 加速源前缀只能来自内置表。允许调用方传前缀等于开放任意 URL 转发，
			// 面板能连到的内网地址会被逐个探测一遍。
			name:    "未知的加速源",
			body:    map[string]any{"name": "GeoLite2-Country.mmdb", "mirror": "https://attacker.example/"},
			wantErr: "未知的加速源",
		},
		{
			name:    "缺少 name",
			body:    map[string]any{},
			wantErr: "缺少 name",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, r := h.call(http.MethodPost, "/api/v1/geoip/download", c.body)
			if code != http.StatusBadRequest {
				t.Fatalf("应 400，得到 %d（%s）", code, r.Error)
			}
			if !strings.Contains(r.Error, c.wantErr) {
				t.Errorf("错误信息应含 %q，得到 %q", c.wantErr, r.Error)
			}
		})
	}
}

// TestGeoDownloadRequiresAuth 下载是写操作，不能匿名触发。
func TestGeoDownloadRequiresAuth(t *testing.T) {
	h := newHarness(t)

	req, err := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/geoip/download",
		strings.NewReader(`{"name":"GeoLite2-Country.mmdb"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("不带 token 应 401，得到 %d", res.StatusCode)
	}
}
