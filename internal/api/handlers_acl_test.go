package api

import (
	"testing"

	"github.com/dreamstation625/FrpFireWall/internal/model"
)

func TestNormalizeScope(t *testing.T) {
	cases := []struct {
		name  string
		kind  string
		in    string
		want  string
		isErr bool
	}{
		// 白名单恒 all，传什么进来都忽略 —— 范围对豁免列表没有意义
		{"白名单忽略 frp", model.KindWhite, model.ScopeFrp, model.ScopeAll, false},
		{"白名单忽略垃圾值", model.KindWhite, "bogus", model.ScopeAll, false},
		{"白名单空值", model.KindWhite, "", model.ScopeAll, false},

		// 黑名单留空按 all：老客户端不带 scope 字段，语义必须和升级前一致
		{"黑名单空值按 all", model.KindBlack, "", model.ScopeAll, false},
		{"黑名单纯空格按 all", model.KindBlack, "   ", model.ScopeAll, false},
		{"黑名单 all", model.KindBlack, model.ScopeAll, model.ScopeAll, false},
		{"黑名单 frp", model.KindBlack, model.ScopeFrp, model.ScopeFrp, false},
		{"黑名单 custom", model.KindBlack, model.ScopeCustom, model.ScopeCustom, false},
		{"黑名单大写归一化", model.KindBlack, "FRP", model.ScopeFrp, false},
		{"黑名单带空格归一化", model.KindBlack, "  Frp ", model.ScopeFrp, false},

		// 非法值必须报错，不能悄悄降级成 frp（那等于放松封禁）
		{"黑名单非法值报错", model.KindBlack, "port", "", true},
		{"黑名单拼错报错", model.KindBlack, "frpp", "", true},
		// 范围列里那种带端口的写法只属于导入导出文件，接口参数不接受
		{"接口参数不接受 custom:8080", model.KindBlack, "custom:8080", "", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := normalizeScope(c.kind, c.in)
			if c.isErr {
				if err == nil {
					t.Fatalf("期望报错，实际返回 %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("不该报错: %v", err)
			}
			if got != c.want {
				t.Fatalf("scope = %q，期望 %q", got, c.want)
			}
		})
	}
}

func TestParseImportLine(t *testing.T) {
	cases := []struct {
		name       string
		line       string
		defScope   string
		defPorts   string
		wantTarget string
		wantScope  string
		wantPorts  string
		wantRemark string
		isErr      bool
	}{
		{"纯地址", "1.2.3.4", model.ScopeAll, "", "1.2.3.4", model.ScopeAll, "", "", false},
		{"纯地址取默认范围", "1.2.3.4", model.ScopeFrp, "", "1.2.3.4", model.ScopeFrp, "", "", false},
		{"CIDR 取默认范围", "1.2.3.0/24", model.ScopeAll, "", "1.2.3.0/24", model.ScopeAll, "", "", false},
		// 默认范围是自定义端口时，不带范围的行沿用默认的那份端口
		{"纯地址取默认自定义端口", "1.2.3.4", model.ScopeCustom, "8080;9000-9100",
			"1.2.3.4", model.ScopeCustom, "8080,9000-9100", "", false},

		// 老格式（地址,备注）必须原样可导入，否则留档的导出文件就废了
		{"老格式 逗号备注", "1.2.3.4,机房备用机", model.ScopeAll, "", "1.2.3.4", model.ScopeAll, "", "机房备用机", false},
		{"老格式 空格备注", "1.2.3.4 机房备用机", model.ScopeAll, "", "1.2.3.4", model.ScopeAll, "", "机房备用机", false},
		{"老格式 中文逗号备注", "1.2.3.4，机房备用机", model.ScopeAll, "", "1.2.3.4", model.ScopeAll, "", "机房备用机", false},
		// 备注里的分隔符必须保留，不能切开再拼回去
		{"备注含空格", "1.2.3.4 机房 备用机", model.ScopeAll, "", "1.2.3.4", model.ScopeAll, "", "机房 备用机", false},
		{"备注含逗号", "1.2.3.4,机房,备用机", model.ScopeAll, "", "1.2.3.4", model.ScopeAll, "", "机房,备用机", false},

		// 新格式：第二段恰好是范围写法时才当范围
		{"新格式 仅范围", "1.2.3.4,frp", model.ScopeAll, "", "1.2.3.4", model.ScopeFrp, "", "", false},
		{"新格式 范围覆盖默认", "1.2.3.4,all", model.ScopeFrp, "", "1.2.3.4", model.ScopeAll, "", "", false},
		{"新格式 范围+备注", "1.2.3.4,frp,过期机房", model.ScopeAll, "", "1.2.3.4", model.ScopeFrp, "", "过期机房", false},
		{"新格式 空格分隔", "1.2.3.4 frp", model.ScopeAll, "", "1.2.3.4", model.ScopeFrp, "", "", false},
		{"新格式 Tab 分隔", "1.2.3.4\tfrp", model.ScopeAll, "", "1.2.3.4", model.ScopeFrp, "", "", false},
		{"新格式 中文逗号", "1.2.3.4，frp，备注", model.ScopeAll, "", "1.2.3.4", model.ScopeFrp, "", "备注", false},
		{"大写范围归一化", "1.2.3.4,FRP", model.ScopeAll, "", "1.2.3.4", model.ScopeFrp, "", "", false},

		// 自定义端口：端口写在范围列里，用分号分隔（逗号是列分隔符）
		{"自定义端口单选", "1.2.3.4,custom:8080", model.ScopeAll, "",
			"1.2.3.4", model.ScopeCustom, "8080", "", false},
		{"自定义端口多个与区间", "1.2.3.4,custom:8080;9000-9100;9100", model.ScopeAll, "",
			"1.2.3.4", model.ScopeCustom, "8080,9000-9100", "", false},
		{"自定义端口+备注", "1.2.3.4,custom:8080,机房备用机", model.ScopeAll, "",
			"1.2.3.4", model.ScopeCustom, "8080", "机房备用机", false},
		// 行内范围覆盖默认时，默认那份端口不能残留下来
		{"行内范围覆盖默认并清掉端口", "1.2.3.4,frp", model.ScopeCustom, "8080",
			"1.2.3.4", model.ScopeFrp, "", "", false},
		// 只写 custom 不带端口 → 不算范围写法，整体当备注（自定义没有端口生成不出规则）
		{"光 custom 无端口当备注", "1.2.3.4,custom", model.ScopeAll, "",
			"1.2.3.4", model.ScopeAll, "", "custom", false},
		{"custom 端口非法当备注", "1.2.3.4,custom:abc", model.ScopeAll, "",
			"1.2.3.4", model.ScopeAll, "", "custom:abc", false},
		{"custom 端口越界当备注", "1.2.3.4,custom:70000", model.ScopeAll, "",
			"1.2.3.4", model.ScopeAll, "", "custom:70000", false},

		// 默认范围本身非法时回落 all，绝不回落 frp
		{"默认范围非法回落 all", "1.2.3.4", "bogus", "", "1.2.3.4", model.ScopeAll, "", "", false},
		// 默认是自定义却没有端口，同样回落 all
		{"默认自定义无端口回落 all", "1.2.3.4", model.ScopeCustom, "",
			"1.2.3.4", model.ScopeAll, "", "", false},

		// 非范围值的第二段按备注处理
		{"非范围值当备注", "1.2.3.4,port", model.ScopeAll, "", "1.2.3.4", model.ScopeAll, "", "port", false},

		{"空行报错", "   ", model.ScopeAll, "", "", "", "", "", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			target, scope, ports, remark, err := parseImportLine(c.line, c.defScope, c.defPorts)
			if c.isErr {
				if err == nil {
					t.Fatalf("期望报错，实际得到 (%q, %q, %q, %q)", target, scope, ports, remark)
				}
				return
			}
			if err != nil {
				t.Fatalf("不该报错: %v", err)
			}
			if target != c.wantTarget || scope != c.wantScope ||
				ports != c.wantPorts || remark != c.wantRemark {
				t.Fatalf("got (%q, %q, %q, %q)，期望 (%q, %q, %q, %q)",
					target, scope, ports, remark, c.wantTarget, c.wantScope, c.wantPorts, c.wantRemark)
			}
		})
	}
}

// TestParseImportLineRoundTrip 钉住"导出 → 导入"闭环：
// handleExportACL 写出来的那三列格式必须能被 parseImportLine 原样读回。
//
// 这里刻意调用 renderScopeField 而不是在用例里手写范围文本：手写的样本只能
// 证明"我抄对了"，证明不了导出函数写对了 —— 而丢端口、丢备注恰恰是导出函数
// 那一侧的问题。
func TestParseImportLineRoundTrip(t *testing.T) {
	cases := []struct{ scope, ports, remark string }{
		{model.ScopeAll, "", ""},
		{model.ScopeAll, "", "机房备用机"},
		{model.ScopeFrp, "", ""},
		{model.ScopeFrp, "", "过期机房"},
		{model.ScopeCustom, "8080", ""},
		{model.ScopeCustom, "8080,9000-9100", "机房备用机"},
		// 库里被手工改坏的行：范围是自定义但没有端口 → 导出成 all
		{model.ScopeCustom, "", "坏行"},
		// 非自定义范围上残留的端口字段一律导出成空，不残留
		{model.ScopeAll, "8080", "残留端口"},
	}
	for _, c := range cases {
		line := "1.2.3.4," + renderScopeField(c.scope, c.ports)
		if c.remark != "" {
			line += "," + c.remark
		}
		target, scope, ports, remark, err := parseImportLine(line, model.ScopeAll, "")
		if err != nil {
			t.Fatalf("%q 解析失败: %v", line, err)
		}
		want := c
		if !model.ScopeNeedsPorts(c.scope) {
			want.ports = "" // 非自定义范围导出时不带端口
		}
		if c.scope == model.ScopeCustom && c.ports == "" {
			want = struct{ scope, ports, remark string }{model.ScopeAll, "", c.remark}
		}
		if target != "1.2.3.4" || scope != want.scope || ports != want.ports || remark != want.remark {
			t.Fatalf("%q 回读为 (%q, %q, %q, %q)，期望 (%q, %q, %q)",
				line, target, scope, ports, remark, want.scope, want.ports, want.remark)
		}
	}
}

// TestNormalizeScopePorts 钉住"非自定义范围一律不带端口"这条不变式。
//
// 库里残留一份不参与生效的端口，是"配置里写着、实际不生效"那类最难的排查题：
// 界面上完全看不出来，只有去数内核规则条数才会发现。
func TestNormalizeScopePorts(t *testing.T) {
	cases := []struct {
		name  string
		scope string
		ports string
		want  string
		isErr bool
	}{
		{"全部端口清空端口字段", model.ScopeAll, "8080", "", false},
		{"仅 frp 端口清空端口字段", model.ScopeFrp, "8080", "", false},
		{"自定义端口归一化", model.ScopeCustom, " 9100-9000 , 8080 ,8080", "8080,9000-9100", false},
		{"自定义端口为空报错", model.ScopeCustom, "", "", true},
		{"自定义端口全是空格报错", model.ScopeCustom, "   ", "", true},
		{"自定义端口非法报错", model.ScopeCustom, "8080~9000", "", true},
		{"自定义端口越界报错", model.ScopeCustom, "70000", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := normalizeScopePorts(c.scope, c.ports)
			if c.isErr {
				if err == nil {
					t.Fatalf("期望报错，实际返回 %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("不该报错: %v", err)
			}
			if got != c.want {
				t.Fatalf("ports = %q，期望 %q", got, c.want)
			}
		})
	}
}
