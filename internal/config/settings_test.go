package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dreamstation625/FrpFireWall/internal/portrange"
)

// 端口配置的持久化格式：库里存的就是用户在设置页里敲的那串文本，
// 中间不做任何结构转换，也就不会出现"转换时悄悄丢了一半"。
func TestProxyPortsSettingsRoundTrip(t *testing.T) {
	c := Default()
	c.Frps.ProxyPorts = portrange.Ports(7020).Merge(portrange.Span(20000, 30000))

	m := c.ToSettings()
	if got := m[KeyProxyPorts]; got != "7020,20000-30000" {
		t.Fatalf("落库文本 %q，期望 7020,20000-30000", got)
	}

	back, err := FromSettings(m)
	if err != nil {
		t.Fatalf("FromSettings 报错: %v", err)
	}
	if got := back.Frps.ProxyPorts.String(); got != "7020,20000-30000" {
		t.Fatalf("回读得到 %q", got)
	}
}

// 老库里的值就是 "80,443" 这种纯数字列表，升级后必须原样读出来。
func TestFromSettingsAcceptsLegacyPortList(t *testing.T) {
	m := Default().ToSettings()
	m[KeyProxyPorts] = "80,443"

	c, err := FromSettings(m)
	if err != nil {
		t.Fatalf("FromSettings 报错: %v", err)
	}
	if got := c.Frps.ProxyPorts.String(); got != "80,443" {
		t.Fatalf("= %q，期望 80,443", got)
	}
}

// 库里没有这个键时用默认值 —— 首次启动就是这个状态，
// 默认配置从来不写库（settings 表里只有密码、JWT 这类运行期凭据）。
func TestFromSettingsDefaultsPorts(t *testing.T) {
	m := Default().ToSettings()
	delete(m, KeyProxyPorts)

	c, err := FromSettings(m)
	if err != nil {
		t.Fatalf("FromSettings 报错: %v", err)
	}
	if got := c.Frps.ProxyPorts.String(); got != "80,443" {
		t.Fatalf("= %q，期望回落默认的 80,443", got)
	}
}

// 库里的值被手工改坏时回落到默认端口，而不是空集合 ——
// 空集合会让「仅 frp 端口」封禁一条规则都下发不出来，
// 而界面上那条黑名单看起来仍然是生效的。
func TestFromSettingsFallsBackOnBrokenPorts(t *testing.T) {
	m := Default().ToSettings()
	m[KeyProxyPorts] = "20000~30000"

	c, err := FromSettings(m)
	if err != nil {
		t.Fatalf("FromSettings 不该因此报错: %v", err)
	}
	if got := c.Frps.ProxyPorts.String(); got != "80,443" {
		t.Fatalf("= %q，坏值应回落默认的 80,443", got)
	}
}

// 归一化会在读取配置时也做一遍：区间合并能实打实减少下发的规则条数。
func TestFromSettingsNormalizesPorts(t *testing.T) {
	m := Default().ToSettings()
	m[KeyProxyPorts] = "20000-25000, 24000-30000, 7020, 7020"

	c, err := FromSettings(m)
	if err != nil {
		t.Fatalf("FromSettings 报错: %v", err)
	}
	if got := c.Frps.ProxyPorts.String(); got != "7020,20000-30000" {
		t.Fatalf("= %q，期望合并去重后的 7020,20000-30000", got)
	}
}

// 配错端口写法时必须带上能看懂的原因。
//
// 这类错误发生在 JSON 绑定阶段，而绑定失败的老写法只回一句"请求格式不正确"——
// 用户对着它不知道该改哪儿。encoding/json 会把自定义 UnmarshalJSON 的错误
// 原样抛出、不做包装，所以这里能直接断言到具体端口。
func TestBadPortsJSONExplainsWhy(t *testing.T) {
	var c Config
	err := json.Unmarshal([]byte(`{"frps":{"proxy_ports":"20000~30000"}}`), &c)
	if err == nil {
		t.Fatal("非法端口写法应该报错")
	}
	if !strings.Contains(err.Error(), "无法识别") || !strings.Contains(err.Error(), "20000~30000") {
		t.Fatalf("错误信息没能说清是哪个端口写错了：%v", err)
	}
}

// 合法值要能正常绑定，且归一化结果与文本形式一致。
func TestPortsJSONBindAndNormalize(t *testing.T) {
	var c Config
	if err := json.Unmarshal([]byte(`{"frps":{"proxy_ports":"20000-30000, 7020, 7020"}}`), &c); err != nil {
		t.Fatalf("绑定报错: %v", err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate 报错: %v", err)
	}
	if got := c.Frps.ProxyPorts.String(); got != "7020,20000-30000" {
		t.Fatalf("= %q，期望 7020,20000-30000", got)
	}
}

// 手写请求体里写成裸数字或数字数组的情况也不能直接报错。
func TestPortsJSONAcceptsLegacyShapes(t *testing.T) {
	for _, in := range []string{`7000`, `[80,443]`} {
		var c Config
		if err := json.Unmarshal([]byte(`{"frps":{"proxy_ports":`+in+`}}`), &c); err != nil {
			t.Fatalf("proxy_ports=%s 应当被接受，实际报错: %v", in, err)
		}
	}
}
