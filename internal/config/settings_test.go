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

// 事件保留期的持久化。
//
// 重点是 0 能原样往返：它表示"永久保留"，落地时最容易被"非正数就取默认"
// 这类写法吃掉，而吃掉的后果是自动清理被悄悄关掉 —— 界面上显示的还是 0，
// 与行为一致，所以看不出来。
func TestEventRetentionRoundTrip(t *testing.T) {
	c := Default()
	if c.Event.RetentionDays != DefaultEventRetentionDays {
		t.Fatalf("默认保留天数 = %d，期望 %d", c.Event.RetentionDays, DefaultEventRetentionDays)
	}
	if got := c.ToSettings()[KeyEventRetention]; got != "30" {
		t.Fatalf("落库文本 %q，期望 30", got)
	}

	for _, want := range []int{DefaultEventRetentionDays, 7, 0, 365} {
		c.Event.RetentionDays = want
		back, err := FromSettings(c.ToSettings())
		if err != nil {
			t.Fatalf("FromSettings(%d) 报错: %v", want, err)
		}
		if back.Event.RetentionDays != want {
			t.Errorf("回读 = %d，期望 %d", back.Event.RetentionDays, want)
		}
	}
}

// 老库（升级上来的）里没有这个键，必须回落到默认的 30 天而不是 0 ——
// 0 的含义是永久保留，会把自动清理关掉，事件表从此无限增长。
func TestEventRetentionDefaultsWhenMissing(t *testing.T) {
	m := Default().ToSettings()
	delete(m, KeyEventRetention)

	c, err := FromSettings(m)
	if err != nil {
		t.Fatalf("FromSettings 报错: %v", err)
	}
	if c.Event.RetentionDays != DefaultEventRetentionDays {
		t.Fatalf("= %d，期望回落默认的 %d（0 会关掉自动清理）", c.Event.RetentionDays, DefaultEventRetentionDays)
	}
}

// 库里被手工改成坏值时回落默认，不让进程起不来。
// 接口保存路径上的负数由 normalize 拦，读库这条路径上必须自己兜住。
func TestEventRetentionFallsBackOnBrokenValue(t *testing.T) {
	for _, bad := range []string{"-1", "-30", "abc", "3.5", ""} {
		m := Default().ToSettings()
		m[KeyEventRetention] = bad

		c, err := FromSettings(m)
		if err != nil {
			t.Fatalf("坏值 %q 不该让 FromSettings 报错: %v", bad, err)
		}
		if c.Event.RetentionDays != DefaultEventRetentionDays {
			t.Errorf("坏值 %q 回读 = %d，期望默认 %d", bad, c.Event.RetentionDays, DefaultEventRetentionDays)
		}
	}
}

// 接口保存路径要拒负数，但要放行 0。
//
// 负数静默归零是个坏选择：0 恰好是"永久保留"，等于顺手把自动清理关掉了，
// 而用户可能只是漏打了一位（300 → 00 之类的笔误）。
func TestEventRetentionRejectsNegative(t *testing.T) {
	c := Default()
	c.Event.RetentionDays = -1
	err := c.Validate()
	if err == nil {
		t.Fatal("负数保留期应当被拒绝")
	}
	if !strings.Contains(err.Error(), "保留") {
		t.Fatalf("错误信息没说清是哪个字段：%v", err)
	}

	c.Event.RetentionDays = 0
	if err := c.Validate(); err != nil {
		t.Fatalf("0 是合法值（永久保留），不该报错: %v", err)
	}
}
