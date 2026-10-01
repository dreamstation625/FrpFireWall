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
