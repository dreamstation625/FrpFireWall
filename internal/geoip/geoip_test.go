package geoip

import (
	"net/netip"
	"testing"
)

func TestParseRegion(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		prov, city string
		isp        string
	}{
		{"国内完整", "中国|0|广东省|深圳市|电信", "广东省", "深圳市", "电信"},
		{"直辖市", "中国|0|北京市|北京市|联通", "北京市", "北京市", "联通"},
		{"国外记录", "美国|0|0|0|0", "0", "0", "0"},
		{"只到国家级", "中国|0|0|0|0", "0", "0", "0"},
		{"段数不足", "中国|0|广东省", "广东省", "", ""},
		{"空串", "", "", "", ""},
		{"带空格", "中国|0| 广东省 | 深圳市 |电信", "广东省", "深圳市", "电信"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prov, city, isp := parseRegion(c.in)
			if prov != c.prov || city != c.city || isp != c.isp {
				t.Fatalf("parseRegion(%q) = (%q, %q, %q)，期望 (%q, %q, %q)",
					c.in, prov, city, isp, c.prov, c.city, c.isp)
			}
		})
	}
}

// TestRegionImpliesCN 钉住「xdb 查到了」≠「这个 IP 在中国」。
//
// ip2region 同样收录国外记录，返回形如 "美国|0|0|0|0"。早期实现把兜底条件写成
// 「xdb 查到了就补 CN」，于是只装 ip2region 没装 mmdb 的机器上，任何国外 IP 都会
// 被标成 CN —— 「只放行中国」的白名单等于放行全世界，而且界面上显示的国家名还是
// 「中国」，完全看不出异常。这个测试守的就是这条。
func TestRegionImpliesCN(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"中国|0|广东省|深圳市|电信", true},
		{"中国|0|广东省|0|0", true},  // 只有省没有市，也算国内明细
		{"中国|0|0|深圳市|电信", true}, // 只有市没有省，同样算
		{"美国|0|0|0|0", false},
		{"日本|0|0|0|0", false},
		{"中国|0|0|0|0", false}, // 只到国家级：宁可漏标，也不拿它当依据
		{"", false},
	}
	for _, c := range cases {
		if got := regionImpliesCN(c.in); got != c.want {
			t.Errorf("regionImpliesCN(%q) = %v，期望 %v", c.in, got, c.want)
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
