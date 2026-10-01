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
		{"黑名单大写归一化", model.KindBlack, "FRP", model.ScopeFrp, false},
		{"黑名单带空格归一化", model.KindBlack, "  Frp ", model.ScopeFrp, false},

		// 非法值必须报错，不能悄悄降级成 frp（那等于放松封禁）
		{"黑名单非法值报错", model.KindBlack, "port", "", true},
		{"黑名单拼错报错", model.KindBlack, "frpp", "", true},
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
		wantTarget string
		wantScope  string
		wantRemark string
		isErr      bool
	}{
		{"纯地址", "1.2.3.4", model.ScopeAll, "1.2.3.4", model.ScopeAll, "", false},
		{"纯地址取默认范围", "1.2.3.4", model.ScopeFrp, "1.2.3.4", model.ScopeFrp, "", false},
		{"CIDR 取默认范围", "1.2.3.0/24", model.ScopeAll, "1.2.3.0/24", model.ScopeAll, "", false},

		// 老格式（地址,备注）必须原样可导入，否则留档的导出文件就废了
		{"老格式 逗号备注", "1.2.3.4,机房备用机", model.ScopeAll, "1.2.3.4", model.ScopeAll, "机房备用机", false},
		{"老格式 空格备注", "1.2.3.4 机房备用机", model.ScopeAll, "1.2.3.4", model.ScopeAll, "机房备用机", false},
		{"老格式 中文逗号备注", "1.2.3.4，机房备用机", model.ScopeAll, "1.2.3.4", model.ScopeAll, "机房备用机", false},
		// 备注里的分隔符必须保留，不能切开再拼回去
		{"备注含空格", "1.2.3.4 机房 备用机", model.ScopeAll, "1.2.3.4", model.ScopeAll, "机房 备用机", false},
		{"备注含逗号", "1.2.3.4,机房,备用机", model.ScopeAll, "1.2.3.4", model.ScopeAll, "机房,备用机", false},

		// 新格式：第二段恰好是范围值时才当范围
		{"新格式 仅范围", "1.2.3.4,frp", model.ScopeAll, "1.2.3.4", model.ScopeFrp, "", false},
		{"新格式 范围覆盖默认", "1.2.3.4,all", model.ScopeFrp, "1.2.3.4", model.ScopeAll, "", false},
		{"新格式 范围+备注", "1.2.3.4,frp,过期机房", model.ScopeAll, "1.2.3.4", model.ScopeFrp, "过期机房", false},
		{"新格式 空格分隔", "1.2.3.4 frp", model.ScopeAll, "1.2.3.4", model.ScopeFrp, "", false},
		{"新格式 Tab 分隔", "1.2.3.4\tfrp", model.ScopeAll, "1.2.3.4", model.ScopeFrp, "", false},
		{"新格式 中文逗号", "1.2.3.4，frp，备注", model.ScopeAll, "1.2.3.4", model.ScopeFrp, "备注", false},
		{"大写范围归一化", "1.2.3.4,FRP", model.ScopeAll, "1.2.3.4", model.ScopeFrp, "", false},

		// 默认范围本身非法时回落 all，绝不回落 frp
		{"默认范围非法回落 all", "1.2.3.4", "bogus", "1.2.3.4", model.ScopeAll, "", false},

		// 非范围值的第二段按备注处理
		{"非范围值当备注", "1.2.3.4,port", model.ScopeAll, "1.2.3.4", model.ScopeAll, "port", false},

		{"空行报错", "   ", model.ScopeAll, "", "", "", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			target, scope, remark, err := parseImportLine(c.line, c.defScope)
			if c.isErr {
				if err == nil {
					t.Fatalf("期望报错，实际得到 (%q, %q, %q)", target, scope, remark)
				}
				return
			}
			if err != nil {
				t.Fatalf("不该报错: %v", err)
			}
			if target != c.wantTarget || scope != c.wantScope || remark != c.wantRemark {
				t.Fatalf("got (%q, %q, %q)，期望 (%q, %q, %q)",
					target, scope, remark, c.wantTarget, c.wantScope, c.wantRemark)
			}
		})
	}
}

// TestParseImportLineRoundTrip 钉住"导出 → 导入"闭环：
// handleExportACL 写出来的三列格式必须能被 parseImportLine 原样读回。
func TestParseImportLineRoundTrip(t *testing.T) {
	cases := []struct{ scope, remark string }{
		{model.ScopeAll, ""},
		{model.ScopeAll, "机房备用机"},
		{model.ScopeFrp, ""},
		{model.ScopeFrp, "过期机房"},
	}
	for _, c := range cases {
		line := "1.2.3.4," + c.scope
		if c.remark != "" {
			line += "," + c.remark
		}
		target, scope, remark, err := parseImportLine(line, model.ScopeAll)
		if err != nil {
			t.Fatalf("%q 解析失败: %v", line, err)
		}
		if target != "1.2.3.4" || scope != c.scope || remark != c.remark {
			t.Fatalf("%q 回读为 (%q, %q, %q)", line, target, scope, remark)
		}
	}
}
