package geoip

import (
	"net/netip"
	"testing"

	"github.com/dreamstation625/FrpFireWall/internal/model"
)

func TestParseRegion(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want regionRecord
	}{
		{
			"国内完整",
			"中国|江苏省|南京市|0|CN",
			regionRecord{country: "中国", province: "江苏省", city: "南京市", isp: "0", code: "CN"},
		},
		{
			"直辖市",
			"中国|北京市|北京市|电信|CN",
			regionRecord{country: "中国", province: "北京市", city: "北京市", isp: "电信", code: "CN"},
		},
		{
			"国外完整",
			"United States|California|0|Google LLC|US",
			regionRecord{country: "United States", province: "California", city: "0", isp: "Google LLC", code: "US"},
		},
		{
			"保留地址",
			"Reserved|Reserved|Reserved|0|0",
			regionRecord{country: "Reserved", province: "Reserved", city: "Reserved", isp: "0", code: "0"},
		},
		{
			"带空格",
			" 中国 | 北京市 | 北京市 | 电信 | CN ",
			regionRecord{country: "中国", province: "北京市", city: "北京市", isp: "电信", code: "CN"},
		},
		{
			// 段数不足时缺的位置给空串，不能越界。
			"段数不足",
			"中国|北京市",
			regionRecord{country: "中国", province: "北京市"},
		},
		{"空串", "", regionRecord{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseRegion(c.in)
			if got != c.want {
				t.Fatalf("parseRegion(%q) = %+v，期望 %+v", c.in, got, c.want)
			}
		})
	}
}

// TestParseRegionDoesNotShiftFields 钉住字段位置。
//
// 老实现按 "国家|区域|省份|城市|ISP" 从索引 2 起取，而 xdb 的格式是
// "国家|省份|城市|ISP|国家码"，于是真库上读出来是 省份=南京市、城市=0、ISP=CN，
// 看起来毫无异常。后果是省份规则只对北京/上海/天津/重庆四个直辖市生效
// （它们省市同名），拿直辖市测根本发现不了。
func TestParseRegionDoesNotShiftFields(t *testing.T) {
	rec := parseRegion("中国|江苏省|南京市|0|CN")
	if rec.province != "江苏省" {
		t.Errorf("省份应是「江苏省」，得到 %q（拿到城市名说明字段位置又错了）", rec.province)
	}
	if rec.city != "南京市" {
		t.Errorf("城市应是「南京市」，得到 %q", rec.city)
	}
	if rec.isp == "CN" {
		t.Errorf("ISP 被读成了国家码，字段位置错了：%+v", rec)
	}
	if rec.code != "CN" {
		t.Errorf("国家码应是 CN，得到 %q", rec.code)
	}
}

func TestIsPlaceholder(t *testing.T) {
	for _, s := range []string{"", "0", "Reserved", "reserved", "  RESERVED  "} {
		if !isPlaceholder(s) {
			t.Errorf("isPlaceholder(%q) 应为 true", s)
		}
	}
	for _, s := range []string{"江苏省", "CN", "南京市", "Reserved City", "10086"} {
		if isPlaceholder(s) {
			t.Errorf("isPlaceholder(%q) 应为 false", s)
		}
	}
}

// TestRegionFallbackCountry 钉住国家兜底用的是 ISO 国家码。
//
// 不能拿「有没有省市」当判据：ip2region 同样收录国外记录，而且**国外记录也带省市**
// —— 1.1.1.1 返回 "Australia|Queensland|Brisbane|0|AU"。早期按「有省市就算中国」
// 写，结果 Cloudflare 的澳洲节点被标成 CN，「只放行中国」的白名单形同虚设，
// 界面上还照样显示「中国」，看不出异常。
//
// 也不能按国名比对（中英混用：「中国」/「China」/「United States」）。
// 唯一稳的是最后一段的国家码，而且它不只能判 CN —— 直接用它的值兜底更准。
func TestRegionFallbackCountry(t *testing.T) {
	cases := []struct{ in, want string }{
		{"中国|江苏省|南京市|0|CN", "CN"},
		{"中国|北京市|北京市|电信|CN", "CN"},
		{"Australia|Queensland|Brisbane|0|AU", "AU"},
		{"United States|California|0|Google LLC|US", "US"},
		{"United States|California|San Francisco|0|US", "US"},
		// 小写要归一成大写，ISO 码统一大写。
		{"中国|江苏省|南京市|0|cn", "CN"},
		// 保留地址段：国家码是占位符，不能当国家用。
		{"Reserved|Reserved|Reserved|0|0", ""},
		{"", ""},
		// 段数不足时不要越界。
		{"中国|江苏省|南京市", ""},
	}
	for _, c := range cases {
		if got := parseRegion(c.in).fallbackCountry(); got != c.want {
			t.Errorf("parseRegion(%q).fallbackCountry() = %q，期望 %q", c.in, got, c.want)
		}
	}
}

// TestRealRecordsFeedProvinceRules 真实记录里的省份要能被规则侧的归一化认出来。
//
// 老代码把城市名塞进 Province，CanonicalProvince("南京市") 归一成 "南京"，
// 而候选表里是省级的 "江苏" —— 省份规则永远不命中，还不报错。
func TestRealRecordsFeedProvinceRules(t *testing.T) {
	for _, c := range []struct{ raw, want string }{
		{"中国|江苏省|南京市|0|CN", "江苏"},
		{"中国|内蒙古自治区|呼和浩特市|0|CN", "内蒙古"},
		{"中国|北京市|北京市|电信|CN", "北京"},
		{"中国|广东省|深圳市|电信|CN", "广东"},
	} {
		rec := parseRegion(c.raw)
		if got := model.CanonicalProvince(rec.province); got != c.want {
			t.Errorf("CanonicalProvince(%q) = %q，期望 %q", rec.province, got, c.want)
		}
		if !model.IsKnownProvince(rec.province) {
			t.Errorf("真实记录里的省份 %q 应能被规则侧识别", rec.province)
		}
	}
}

// TestLookupSkipsPrivateAddresses 内网地址不查库，且**不能**置 Found。
// 判定层要求 Found && Country != "" 才做国家封禁（judge.go），
// 内网要是置了 Found 又带个空国家码，行为就飘了。
func TestLookupSkipsPrivateAddresses(t *testing.T) {
	r := New(t.TempDir())
	for _, s := range []string{
		"127.0.0.1", "::1", "0.0.0.0",
		"192.168.1.1", "10.0.0.1", "172.16.0.1",
		"169.254.1.1",
	} {
		info := r.Lookup(netip.MustParseAddr(s))
		if info.CountryName != "内网" {
			t.Errorf("%s: CountryName = %q，期望 %q", s, info.CountryName, "内网")
		}
		if info.Found {
			t.Errorf("%s: Found 应为 false，内网没有属地意义", s)
		}
		if info.Country != "" {
			t.Errorf("%s: Country 应留空，得到 %q", s, info.Country)
		}
	}
}

// TestLookupWithoutAnyDatabase 没有库文件时，公网 IP 也不能凭空造出属地。
// 这条同时挡住「把查不到的 IP 一律当中国」这类兜底。
func TestLookupWithoutAnyDatabase(t *testing.T) {
	r := New(t.TempDir())
	if r.Available() {
		t.Fatal("空数据目录不应判定为可用")
	}
	info := r.Lookup(netip.MustParseAddr("8.8.8.8"))
	if info.Found || info.Country != "" || info.Province != "" || info.City != "" {
		t.Fatalf("未加载任何库时不应给出属地，得到 %+v", info)
	}
	if info.IP != "8.8.8.8" {
		t.Fatalf("IP 字段应原样回填，得到 %q", info.IP)
	}
}

func TestLookupStringAcceptsAddrPort(t *testing.T) {
	r := New(t.TempDir())

	if got := r.LookupString("192.168.1.1:7000"); got.CountryName != "内网" {
		t.Errorf("带端口的内网地址应识别出来，得到 %+v", got)
	}
	if got := r.LookupString("  8.8.8.8  "); got.IP != "8.8.8.8" {
		t.Errorf("应去掉首尾空白，得到 %q", got.IP)
	}
	if got := r.LookupString("不是 IP"); got.IP != "不是 IP" {
		t.Errorf("解析失败的入参应原样回填 IP 字段，得到 %q", got.IP)
	}
}

// TestSaveUploadRejectsUnknownName 上传接口只能写白名单里的文件名，
// 否则一个 ../ 就能把库文件写到数据目录外面。
func TestSaveUploadRejectsUnknownName(t *testing.T) {
	r := New(t.TempDir())
	for _, name := range []string{"../evil.mmdb", "GeoLite2-ASN.mmdb", "", "geoip.mmdb"} {
		if err := r.SaveUpload(name, nil); err == nil {
			t.Errorf("SaveUpload(%q) 应被拒绝", name)
		}
	}
}
