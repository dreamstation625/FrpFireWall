package model

import (
	"strings"
	"testing"
)

func TestRateRuleLayer(t *testing.T) {
	cases := []struct {
		name string
		rule RateRule
		want string
	}{
		{"只有地区 → 应用层", RateRule{Countries: "HK"}, LayerApp},
		{"只有省份 → 应用层", RateRule{Provinces: "广东省"}, LayerApp},
		{"只有地址段 → 应用层", RateRule{CIDRs: "1.2.3.0/24"}, LayerApp},
		{"地区 + 地址段 → 应用层", RateRule{Countries: "HK", CIDRs: "1.2.3.0/24"}, LayerApp},
		{"有端口 → 内核层", RateRule{Ports: "20000-30000"}, LayerKernel},
		{"地址段 + 端口 → 内核层", RateRule{CIDRs: "1.2.3.0/24", Ports: "443"}, LayerKernel},
		{"空白端口不算条件", RateRule{Countries: "HK", Ports: "  "}, LayerApp},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.rule.Layer(); got != c.want {
				t.Fatalf("Layer() = %q，期望 %q", got, c.want)
			}
		})
	}
}

func TestRateRuleValidateAccepts(t *testing.T) {
	cases := []struct {
		name string
		rule RateRule
	}{
		{
			"内核层：只有限速",
			RateRule{Name: "扫描限速", Ports: "20000-30000", PerSec: 5},
		},
		{
			"内核层：带来源段",
			RateRule{Name: "某段限速", CIDRs: "1.2.3.0/24", Ports: "443", PerSec: 20, Burst: 40},
		},
		{
			"应用层：只封禁",
			RateRule{Name: "香港封禁", Countries: "HK", WindowSeconds: 60, Threshold: 10, BanDurations: "600,3600"},
		},
		{
			"应用层：只限速",
			RateRule{Name: "某段限速", CIDRs: "1.2.3.0/24", PerSec: 3},
		},
		{
			"应用层：限速 + 封禁",
			RateRule{
				Name: "广东组合", Provinces: "广东省", PerSec: 5,
				WindowSeconds: 60, Threshold: 20, BanDurations: "0",
			},
		},
		{
			"永久封禁（阶梯为 0）",
			RateRule{Name: "永久", Countries: "US", WindowSeconds: 30, Threshold: 5, BanDurations: "0"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.rule.Validate(); err != nil {
				t.Fatalf("期望通过校验，却报错：%v", err)
			}
		})
	}
}

func TestRateRuleValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		rule RateRule
		want string // 错误里必须出现的关键字
	}{
		{
			"没有名字",
			RateRule{Countries: "HK", PerSec: 1},
			"规则名不能为空",
		},
		{
			"没有任何条件",
			RateRule{Name: "空规则", PerSec: 1},
			"没有任何匹配条件",
		},
		{
			"条件全是空白",
			RateRule{Name: "空规则", Countries: "  ", CIDRs: "\n", Ports: " "},
			"没有任何匹配条件",
		},
		{
			"地区 + 端口",
			RateRule{Name: "混搭", Countries: "HK", Ports: "443", PerSec: 1},
			"无法生效",
		},
		{
			"省份 + 端口",
			RateRule{Name: "混搭", Provinces: "广东省", Ports: "443", PerSec: 1},
			"无法生效",
		},
		{
			"内核层缺限速",
			RateRule{Name: "内核无限速", Ports: "443"},
			"每秒连接数上限",
		},
		{
			"内核层配封禁",
			RateRule{
				Name: "内核封禁", Ports: "443", PerSec: 5,
				WindowSeconds: 60, Threshold: 10, BanDurations: "600",
			},
			"不能配置封禁",
		},
		{
			"内核层只配了半截封禁",
			RateRule{Name: "内核半截", Ports: "443", PerSec: 5, Threshold: 10},
			"不能配置封禁",
		},
		{
			"应用层什么都没配",
			RateRule{Name: "空动作", Countries: "HK"},
			"什么都不会发生",
		},
		{
			"应用层封禁缺一半",
			RateRule{Name: "半截", Countries: "HK", WindowSeconds: 60, Threshold: 10},
			"封禁配置不完整",
		},
		{
			"封禁阶梯为空串",
			RateRule{Name: "半截", Countries: "HK", WindowSeconds: 60, Threshold: 10, BanDurations: " , "},
			"封禁配置不完整",
		},
		{
			"窗口越界",
			RateRule{Name: "窗口越界", Countries: "HK", WindowSeconds: 99999, Threshold: 10, BanDurations: "600"},
			"统计窗口",
		},
		{
			"阈值越界",
			RateRule{Name: "阈值越界", Countries: "HK", WindowSeconds: 60, Threshold: 999999, BanDurations: "600"},
			"触发阈值",
		},
		{
			"国家码只有一位",
			RateRule{Name: "坏国家", Countries: "H", PerSec: 1},
			"格式不正确",
		},
		{
			"国家码带数字",
			RateRule{Name: "坏国家", Countries: "H1", PerSec: 1},
			"格式不正确",
		},
		{
			"地址段写错",
			RateRule{Name: "坏地址", CIDRs: "1.2.3.0/33", PerSec: 1},
			"格式不正确",
		},
		{
			"地址段是域名",
			RateRule{Name: "坏地址", CIDRs: "example.com", PerSec: 1},
			"格式不正确",
		},
		{
			"端口写错",
			RateRule{Name: "坏端口", Ports: "70000", PerSec: 1},
			"无法识别",
		},
		{
			"端口是区间但起止写反也接受，越界才拒",
			RateRule{Name: "坏端口", Ports: "20000-", PerSec: 1},
			"无法识别",
		},
		{
			"名字太长",
			RateRule{Name: strings.Repeat("规", 65), Countries: "HK", PerSec: 1},
			"太长",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.rule.Validate()
			if err == nil {
				t.Fatalf("期望报错，却通过了")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("错误信息里没有 %q：%v", c.want, err)
			}
		})
	}
}

func TestRateRuleNormalize(t *testing.T) {
	cases := []struct {
		name string
		in   RateRule
		want func(r RateRule) bool
		desc string
	}{
		{
			"国家码大写去重排序无关",
			RateRule{Countries: "hk, US, hk"},
			func(r RateRule) bool { return r.Countries == "HK,US" },
			`Countries == "HK,US"`,
		},
		{
			"全角逗号也认",
			RateRule{Countries: "HK，US"},
			func(r RateRule) bool { return r.Countries == "HK,US" },
			`Countries == "HK,US"`,
		},
		{
			"裸 IP 补成 /32",
			RateRule{CIDRs: "1.2.3.4"},
			func(r RateRule) bool { return r.CIDRs == "1.2.3.4/32" },
			`CIDRs == "1.2.3.4/32"`,
		},
		{
			"网段按掩码归位",
			RateRule{CIDRs: "1.2.3.5/24"},
			func(r RateRule) bool { return r.CIDRs == "1.2.3.0/24" },
			`CIDRs == "1.2.3.0/24"`,
		},
		{
			"IPv6 裸地址补 /128",
			RateRule{CIDRs: "2001:db8::1"},
			func(r RateRule) bool { return r.CIDRs == "2001:db8::1/128" },
			`CIDRs == "2001:db8::1/128"`,
		},
		{
			"端口区间归一化并合并相邻",
			RateRule{Ports: "80, 81, 20000-30000, 80"},
			func(r RateRule) bool { return r.Ports == "80-81,20000-30000" },
			`Ports == "80-81,20000-30000"`,
		},
		{
			"突发额度自动补齐",
			RateRule{PerSec: 20},
			func(r RateRule) bool { return r.Burst == 40 },
			"Burst == 40",
		},
		{
			"已有突发额度不动",
			RateRule{PerSec: 20, Burst: 7},
			func(r RateRule) bool { return r.Burst == 7 },
			"Burst == 7",
		},
		{
			"没配限速就不补突发",
			RateRule{Countries: "HK"},
			func(r RateRule) bool { return r.Burst == 0 },
			"Burst == 0",
		},
		{
			// 去重和归一化会一起发生：全称被收敛成简称，简称本身不变。
			"省份去重并归一化",
			RateRule{Provinces: "广东省, 广东省 ,福建省"},
			func(r RateRule) bool { return r.Provinces == "广东,福建" },
			`Provinces == "广东,福建"`,
		},
		{
			// 同一条规则里混着全称和简称，归一到同一个之后要去重成一条，
			// 否则列表里会出现两个看着一样、实际写法不同的选项。
			"省份全称与简称归一后去重",
			RateRule{Provinces: "广东,广东省"},
			func(r RateRule) bool { return r.Provinces == "广东" },
			`Provinces == "广东"`,
		},
		{
			"名字与备注去空白",
			RateRule{Name: "  香港  ", Remark: "  备注 "},
			func(r RateRule) bool { return r.Name == "香港" && r.Remark == "备注" },
			`Name == "香港" 且 Remark == "备注"`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := c.in
			r.Normalize()
			if !c.want(r) {
				t.Fatalf("归一化后不符合 %s：%+v", c.desc, r)
			}
		})
	}
}

// 归一化必须把"写错了"的字段原样留着，不能悄悄抹掉 ——
// 抹掉之后用户看到的是"保存成功了但条件没了"。
func TestRateRuleNormalizeKeepsBadInput(t *testing.T) {
	r := RateRule{CIDRs: "1.2.3.0/33", Ports: "not-a-port"}
	r.Normalize()
	if r.CIDRs != "1.2.3.0/33" {
		t.Fatalf("非法地址段被改动：%q", r.CIDRs)
	}
	if r.Ports != "not-a-port" {
		t.Fatalf("非法端口被改动：%q", r.Ports)
	}
}

func TestRateRuleDurationSteps(t *testing.T) {
	cases := []struct {
		in   string
		want []int64
	}{
		{"", nil},
		{"600", []int64{600}},
		{"600,3600,86400,0", []int64{600, 3600, 86400, 0}},
		{" 600 , 3600 ", []int64{600, 3600}},
		{"600,,3600", []int64{600, 3600}},
		{"abc,600", []int64{600}}, // 非法项跳过，不整体失败
		{"-1,600", []int64{600}},  // 负数同样跳过
	}
	for _, c := range cases {
		r := RateRule{BanDurations: c.in}
		got := r.DurationSteps()
		if len(got) != len(c.want) {
			t.Fatalf("输入 %q：得到 %v，期望 %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("输入 %q：得到 %v，期望 %v", c.in, got, c.want)
			}
		}
	}
}

// 空端口集合必须是 nil，否则调用方用 len() 判断"有没有端口条件"会得到反的结论。
func TestRateRulePortSetEmpty(t *testing.T) {
	r := RateRule{}
	set, err := r.PortSet()
	if err != nil {
		t.Fatalf("空端口不该报错：%v", err)
	}
	if len(set) != 0 {
		t.Fatalf("空端口应返回空集合，得到 %v", set)
	}
}

func TestRateRulePrefixList(t *testing.T) {
	r := RateRule{CIDRs: "1.2.3.0/24 2001:db8::/32\n10.0.0.1"}
	ps, err := r.PrefixList()
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if len(ps) != 3 {
		t.Fatalf("期望 3 个前缀，得到 %d 个：%v", len(ps), ps)
	}
	if ps[0].String() != "1.2.3.0/24" || ps[1].String() != "2001:db8::/32" || ps[2].String() != "10.0.0.1/32" {
		t.Fatalf("解析结果不对：%v", ps)
	}
}

// 大小写不该影响国家码的匹配 —— 用户敲 hk 和 HK 是一回事。
func TestRateRuleCountryListIsUppercased(t *testing.T) {
	r := RateRule{Countries: "hk,Us,cn"}
	got := r.CountryList()
	want := []string{"HK", "US", "CN"}
	if len(got) != len(want) {
		t.Fatalf("得到 %v，期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("得到 %v，期望 %v", got, want)
		}
	}
}

// 城市要进 HasGeoCondition：漏掉它的表现是"只按城市匹配的规则"被判成
// "没有任何匹配条件"，保存直接被拒。
func TestRateRuleHasGeoConditionIncludesCities(t *testing.T) {
	if (&RateRule{Cities: "深圳"}).HasGeoCondition() != true {
		t.Error("只填城市也算有地区条件")
	}
	if (&RateRule{Cities: "深圳市"}).HasGeoCondition() != true {
		t.Error("城市归一化不该影响「有没有条件」这个判断")
	}
	if (&RateRule{Cities: "0"}).HasGeoCondition() != true {
		// 占位值在 Validate 里会被挡下（归一到空）。这里返回 true 只是说
		// "字段上有东西"，不是"这条规则有效"—— 两件事不能混。
		t.Error("字段上有内容就该算有地区条件，有效性由 Validate 判")
	}
	if (&RateRule{CIDRs: "1.2.3.4"}).HasGeoCondition() {
		t.Error("网段条件不是地区条件")
	}
}

// 拦截动作与限速/封禁互斥，且必须落在应用层（内核只能丢包）。
func TestRateRuleValidateBlock(t *testing.T) {
	// 只开拦截，别的都不配 —— 合法。
	if err := (&RateRule{Name: "整段拉黑", Countries: "HK", Block: true}).Validate(); err != nil {
		t.Errorf("只开直接拦截应当合法，实际：%v", err)
	}

	cases := []struct {
		name string
		rule RateRule
		want string
	}{
		{
			"拦截 + 限速",
			RateRule{Name: "x", Countries: "HK", Block: true, PerSec: 5},
			"只保留一个",
		},
		{
			"拦截 + 封禁阈值",
			RateRule{Name: "x", Countries: "HK", Block: true,
				WindowSeconds: 60, Threshold: 10, BanDurations: "60"},
			"只保留一个",
		},
		{
			// 端口落内核，内核只能丢包、表达不出"拒绝"这一步
			"拦截 + 端口",
			RateRule{Name: "x", Ports: "443", Block: true},
			"去掉端口条件",
		},
	}
	for _, c := range cases {
		err := c.rule.Validate()
		if err == nil {
			t.Errorf("%s：应当被拒绝", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s：错误信息里没有 %q：%v", c.name, c.want, err)
		}
	}
}

// 城市填了却一个有效值都不剩，不能存进去。
//
// 城市候选集开放、不查真实性（写错城市名不报错是刻意的取舍，见 CanonicalCity），
// 但"整串都是占位值"必须挡 —— 那种规则会永远不命中，属于"配了等于没配"。
//
// 两条路径都要覆盖，因为它们的**报错文案不同**：
//   - 结构化构造（或手工改过的库行）直接 Validate：Cities 还是原始值 "0"，
//     由城市那条检查给出专门的提示；
//   - 接口那条路先 Normalize 再 Validate：Cities 已经被归一成空串，
//     城市检查看不见它了，最后由"没有任何匹配条件"兜住。
//
// 两条都必须拒绝，只是谁先开口的区别。
func TestRateRuleValidateRejectsEmptyCity(t *testing.T) {
	raw := RateRule{Name: "x", Cities: "0"}
	if err := raw.Validate(); err == nil || !strings.Contains(err.Error(), "城市") {
		t.Errorf("未经归一化的占位城市应当由城市检查直接拒绝，实际：%v", err)
	}

	normalized := RateRule{Name: "x", Cities: "0"}
	normalized.Normalize()
	if normalized.Cities != "" {
		t.Fatalf("占位城市归一化后应为空串，实际 %q", normalized.Cities)
	}
	if err := normalized.Validate(); err == nil {
		t.Error("归一化之后仍然必须被拒绝（此时由「没有任何匹配条件」兜住）")
	}
}

// 代理（隧道）名作为匹配条件的三条契约。
//
// 一、**它自己就算一个匹配条件**。"只给某个代理定一套参数"正是只有代理名、
// 没有地区和网段的写法；不把它算进条件里，这种规则会被"没有任何匹配条件"
// 那条检查拒掉，功能直接配不出来。
//
// 二、**不能与端口共存**。代理名来自 frps 的回调，带端口条件的规则下发到内核，
// 内核只看源地址与目的端口、认不出隧道 —— 凑在一起代理条件永远判不上，
// 属于"配了不生效"，必须像"地区 + 端口"那样在保存时挡掉。
//
// 三、**它进封禁来源引用的签名**。改了代理名等于换了一批适用对象，旧的封禁
// 依据不再成立，由它封的地址要跟着解封。
func TestRateRuleProxyNameContract(t *testing.T) {
	// 一、只有代理名也是一条完整规则
	only := RateRule{Name: "web-ssh 限速", ProxyName: "web-ssh", PerSec: 10}
	only.Normalize()
	if err := only.Validate(); err != nil {
		t.Fatalf("只有代理名、没有地区/网段的规则应当合法，实际被拒：%v", err)
	}

	// 二、端口 + 代理必须被拒
	conflict := RateRule{Name: "x", ProxyName: "web-ssh", Ports: "7000", PerSec: 10}
	if err := conflict.Validate(); err == nil || !strings.Contains(err.Error(), "代理") {
		t.Errorf("「代理」+「端口」应当被拒绝并说明原因，实际：%v", err)
	}

	// 三、代理名进签名
	a := RateRule{Name: "x", Enabled: true, ProxyName: "web-ssh", Block: true}
	b := a
	b.ProxyName = "web-1"
	if a.BanRef() == b.BanRef() {
		t.Error("代理名不同却拿到了同一个来源引用 —— 改代理名后旧的封禁不会解封")
	}
	c := a
	c.Name = "换个名字"
	if c.BanRef() != a.BanRef() {
		t.Error("改名字不该改变来源引用（只改名字不该让人解封）")
	}
}

// 代理名只去首尾空白，大小写原样保留。
//
// frp 的代理名区分大小写：悄悄折叠会让一条规则从"命中"变成"永远不命中"，
// 而配置在界面上一个字都没变 —— 这种差异最难查。
func TestRateRuleNormalizeKeepsProxyNameCase(t *testing.T) {
	r := RateRule{Name: "x", ProxyName: "  Web-SSH  ", PerSec: 10}
	r.Normalize()
	if r.ProxyName != "Web-SSH" {
		t.Fatalf("代理名应当是去空白后的 Web-SSH，实际 %q", r.ProxyName)
	}
}
