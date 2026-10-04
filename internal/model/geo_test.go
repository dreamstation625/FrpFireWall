package model

import (
	"strings"
	"testing"
)

func TestIsGeoTargetType(t *testing.T) {
	for _, tt := range []string{TargetGeoCountry, TargetGeoProvince, TargetGeoCity} {
		if !IsGeoTargetType(tt) {
			t.Errorf("%s 应当被认成地区类型", tt)
		}
	}
	// 这几个必须为 false：地址类型一旦被误判成地区类型，归一化会走进
	// NormalizeGeoTarget 的默认分支，报一句"未知的地区类型"，而真正的问题
	// 是"这条根本不是地区条目"。
	for _, tt := range []string{"", "ipv4", "ipv6", "cidr4", "cidr6", "invalid", "geo"} {
		if IsGeoTargetType(tt) {
			t.Errorf("%q 不该被认成地区类型", tt)
		}
	}
}

func TestCanonicalCity(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"深圳", "深圳"},
		{"深圳市", "深圳"},
		{" 深圳市 ", "深圳"},
		// ip2region 对国家/地区带「中国」前缀时会连城市一起带出来
		{"中国香港", "香港"},
		{"中国澳门", "澳门"},

		// 占位与空
		{"", ""},
		{"0", ""},
		{"  0  ", ""},

		// 只去「市」这一种后缀。直辖市的区、国外的行政区名一律不动 ——
		// 猜得越多，错得越隐蔽。
		{"朝阳区", "朝阳区"},
		{"Brisbane", "Brisbane"},
		{"New York", "New York"},
	}
	for _, c := range cases {
		if got := CanonicalCity(c.in); got != c.want {
			t.Errorf("CanonicalCity(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeGeoTargetCountry(t *testing.T) {
	// 小写要收敛成大写：属地库返回的是大写 ISO 码，名单里写小写就会永远不命中。
	got, err := NormalizeGeoTarget(TargetGeoCountry, "cn, us,cn")
	if err != nil {
		t.Fatalf("不该报错：%v", err)
	}
	if got != "CN,US" {
		t.Errorf("归一化结果应为 CN,US，实际 %q", got)
	}

	// 分号 / 中文逗号 / 空格都是合法的分隔符（导出文件用分号）。
	got, err = NormalizeGeoTarget(TargetGeoCountry, "CN;US，JP HK")
	if err != nil {
		t.Fatalf("不该报错：%v", err)
	}
	if got != "CN,US,JP,HK" {
		t.Errorf("多分隔符归一化结果应为 CN,US,JP,HK，实际 %q", got)
	}

	for _, bad := range []string{"CHN", "C", "12", "C1", ""} {
		if _, err := NormalizeGeoTarget(TargetGeoCountry, bad); err == nil {
			t.Errorf("%q 应当被拒绝", bad)
		}
	}
	// 报错文案要指向真正的原因：国家码写错时报"非法的 IP 地址"会把人带偏。
	if _, err := NormalizeGeoTarget(TargetGeoCountry, "CHN"); err == nil ||
		!strings.Contains(err.Error(), "两位字母") {
		t.Errorf("国家码格式错的报错应当说明是两位字母，实际 %v", err)
	}
}

func TestNormalizeGeoTargetProvince(t *testing.T) {
	// 省份归一化后要落进候选表，否则匹配时两边对不上（库返回「广东省」）。
	got, err := NormalizeGeoTarget(TargetGeoProvince, "广东省；福建省")
	if err != nil {
		t.Fatalf("不该报错：%v", err)
	}
	if got != "广东,福建" {
		t.Errorf("省份归一化结果应为 广东,福建，实际 %q", got)
	}

	got, err = NormalizeGeoTarget(TargetGeoProvince, "内蒙古自治区,中国香港")
	if err != nil {
		t.Fatalf("不该报错：%v", err)
	}
	if got != "内蒙古,香港" {
		t.Errorf("自治区与地区归一化结果应为 内蒙古,香港，实际 %q", got)
	}

	// 省份候选集封闭，写错必须报错：写错的后果是静默不命中，那种"配了等于
	// 没配"只能在保存时变成一句明确的提示。
	if _, err := NormalizeGeoTarget(TargetGeoProvince, "深证"); err == nil {
		t.Error("无法识别的省份应当被拒绝")
	}
	if _, err := NormalizeGeoTarget(TargetGeoProvince, "0"); err == nil {
		t.Error("全是占位值的省份应当被拒绝")
	}
}

func TestNormalizeGeoTargetCity(t *testing.T) {
	got, err := NormalizeGeoTarget(TargetGeoCity, "深圳市;广州，深圳")
	if err != nil {
		t.Fatalf("不该报错：%v", err)
	}
	if got != "深圳,广州" {
		t.Errorf("城市归一化结果应为 深圳,广州，实际 %q", got)
	}

	// 城市候选集开放，不查真实性 —— 写「没这个城市」不报错。
	// 这是有意的取舍，不是漏了校验：几百个地级市加国外城市，列不全。
	if _, err := NormalizeGeoTarget(TargetGeoCity, "不存在的城市"); err != nil {
		t.Errorf("城市不该做真实性校验，实际报错：%v", err)
	}

	// 但"填了却一个有效值都不剩"必须挡住：那种条目会永远不命中，
	// 界面上却看着配了属地条件。
	if _, err := NormalizeGeoTarget(TargetGeoCity, "0"); err == nil {
		t.Error("城市全是占位值时应当被拒绝")
	}
	if _, err := NormalizeGeoTarget(TargetGeoCity, "  "); err == nil {
		t.Error("城市为空时应当被拒绝")
	}
}

func TestNormalizeGeoTargetUnknownType(t *testing.T) {
	if _, err := NormalizeGeoTarget("ipv4", "1.2.3.4"); err == nil {
		t.Error("未知的地区类型应当被拒绝，而不是当成地址处理")
	}
}

// MatchGeo 是"名单侧已归一化、查询侧必须过同样的归一化"这条约定的落点。
// 查询侧少过一遍归一化，表现是"规则配了却永远不命中"，而这在界面上看不出来。
func TestMatchGeo(t *testing.T) {
	cases := []struct {
		name       string
		targetType string
		list       string
		country    string
		province   string
		city       string
		want       bool
	}{
		{"国家命中", TargetGeoCountry, "CN,US", "CN", "", "", true},
		{"国家命中（库里小写）", TargetGeoCountry, "CN", "cn", "", "", true},
		{"国家不命中", TargetGeoCountry, "US", "CN", "", "", false},
		{"国家为空不命中", TargetGeoCountry, "CN", "", "", "", false},

		// 库里返回「广东省」，名单里存的是归一化后的「广东」
		{"省份命中（库带后缀）", TargetGeoProvince, "广东", "CN", "广东省", "", true},
		{"省份命中（名单带后缀）", TargetGeoProvince, "广东省", "CN", "广东", "", true},
		{"省份不命中", TargetGeoProvince, "广东", "CN", "福建", "", false},
		{"省份为空不命中", TargetGeoProvince, "广东", "CN", "", "", false},

		{"城市命中（库带市字）", TargetGeoCity, "深圳", "CN", "广东", "深圳市", true},
		{"城市不命中", TargetGeoCity, "深圳", "CN", "广东", "广州", false},
		{"城市为空不命中", TargetGeoCity, "深圳", "CN", "广东", "", false},

		// 属地查不到时返回 false。反过来做的话，"只封某国"会在属地库没加载的
		// 机器上变成"封住所有人"。
		{"属地全空不命中", TargetGeoProvince, "广东,福建", "", "", "", false},

		{"空名单不命中", TargetGeoCountry, "", "CN", "", "", false},
		{"未知类型不命中", "ipv4", "CN", "CN", "", "", false},
	}
	for _, c := range cases {
		got := MatchGeo(c.targetType, c.list, c.country, c.province, c.city)
		if got != c.want {
			t.Errorf("%s：MatchGeo(%q, %q, %q, %q, %q) = %v，期望 %v",
				c.name, c.targetType, c.list, c.country, c.province, c.city, got, c.want)
		}
	}
}

func TestGeoTargetLabel(t *testing.T) {
	if GeoTargetLabel(TargetGeoCountry) == "" ||
		GeoTargetLabel(TargetGeoProvince) == "" ||
		GeoTargetLabel(TargetGeoCity) == "" {
		t.Error("地区类型应当都有中文名，否则事件详情里会出现内部常量")
	}
	if GeoTargetLabel("ipv4") != "" {
		t.Error("非地区类型不该有地区标签")
	}
}
