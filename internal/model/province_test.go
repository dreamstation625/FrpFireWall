package model

import "testing"

func TestCanonicalProvince(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// 省
		{"广东省", "广东"},
		{"广东", "广东"},
		{"广东省 ", "广东"},
		{" 福建省", "福建"},

		// 直辖市：MaxMind 的 zh-CN 分区名带「市」，ip2region 不带
		{"北京市", "北京"},
		{"北京", "北京"},
		{"上海市", "上海"},
		{"重庆市", "重庆"},

		// 自治区：这一组是后缀表顺序错了就会切错的
		{"内蒙古自治区", "内蒙古"},
		{"内蒙古", "内蒙古"},
		{"广西壮族自治区", "广西"},
		{"广西", "广西"},
		{"新疆维吾尔自治区", "新疆"},
		{"宁夏回族自治区", "宁夏"},
		{"西藏自治区", "西藏"},

		// 地区
		{"中国香港", "香港"},
		{"香港特别行政区", "香港"},
		{"香港", "香港"},
		{"中国澳门", "澳门"},
		{"澳门特别行政区", "澳门"},
		{"中国台湾", "台湾"},
		{"台湾省", "台湾"},

		// 空与占位
		{"", ""},
		{"   ", ""},
		{"0", ""}, // ip2region 表示"无该级数据"的占位符
		{"中国", "中国"},
		{"火星", "火星"}, // 不认识的照原样返回，交给 Validate 去拒

		// 幂等：归一化过的再归一化不能再变
		{"广东", "广东"},
	}
	for _, c := range cases {
		if got := CanonicalProvince(c.in); got != c.want {
			t.Errorf("CanonicalProvince(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
}

// 候选表和归一化函数必须永远一致。
//
// 这两份东西分开写（一张手写的表 + 一个后缀剥离函数），一旦不一致，
// 界面下拉框给用户的就是一个**永远不命中**的值 —— 而且不报错。
// 这条测试就是那条约束的可执行版本：改表忘了改函数，或者函数改了表没跟上，都会挂。
func TestProvincesAreCanonical(t *testing.T) {
	list := Provinces()
	if len(list) != 34 {
		t.Fatalf("省级行政区应当有 34 个，实际 %d 个", len(list))
	}

	seenName := make(map[string]bool, len(list))
	seenFull := make(map[string]bool, len(list))
	for _, p := range list {
		if p.Area == "" || p.Full == "" {
			t.Errorf("%q 缺大区或全称：%+v", p.Name, p)
		}
		if got := CanonicalProvince(p.Full); got != p.Name {
			t.Errorf("候选表里 %q 的全称 %q 归一后是 %q，对不上 —— 下拉框会给用户一个永不命中的值",
				p.Name, p.Full, got)
		}
		if got := CanonicalProvince(p.Name); got != p.Name {
			t.Errorf("候选名 %q 本身不是归一架形态（归一后是 %q）", p.Name, got)
		}
		if seenName[p.Name] {
			t.Errorf("候选名 %q 重复", p.Name)
		}
		if seenFull[p.Full] {
			t.Errorf("全称 %q 重复", p.Full)
		}
		seenName[p.Name] = true
		seenFull[p.Full] = true
	}
}

func TestIsKnownProvince(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"广东", true},
		{"广东省", true}, // 全称也要认，用户可能从属地库结果里直接复制
		{"内蒙古自治区", true},
		{"香港", true},
		{"中国香港", true},
		{"", false},
		{"0", false},
		{"火星", false},
		{"Guangdong", false}, // 属地库缺中文名时会返回英文，那种情况只能靠国家码兜
	}
	for _, c := range cases {
		if got := IsKnownProvince(c.in); got != c.want {
			t.Errorf("IsKnownProvince(%q) = %v，期望 %v", c.in, got, c.want)
		}
	}
}

// 返回的候选表不能是内部切片本身，否则调用方一改就把全局状态改了。
func TestProvincesReturnsCopy(t *testing.T) {
	a := Provinces()
	a[0].Name = "被改了"
	if Provinces()[0].Name == "被改了" {
		t.Fatal("Provinces() 返回的是内部切片，调用方能改到全局")
	}
}
