package model

import (
	"fmt"
	"strings"
)

// 黑名单里的「地区条目」。
//
// 地区条目与 IP 条目共用一张表：对用户来说它们是同一个概念（"这个来源不许来"），
// 只是匹配方式不同。拆成两张表会带来两套 CRUD、两套导入导出、页面上两个列表，
// 而它们本该在同一个列表里一眼看完。
//
// 一条条目只装一个粒度：粒度之间没有 OR 的语义（"拒绝 CN 或深圳"等价于
// "拒绝 CN"），混在一个字段里只会让"到底拒了什么"说不清。粒度内可以填多个值，
// 逗号分隔，命中任意一个即算命中。
//
// **地区条件无法下沉到内核。** mmdb / ip2region 都是查询型库，没法反向枚举出
// 一个国家的 CIDR 列表，所以地区条目不产生任何内核规则；它的落地方式是
// "命中之后把这个具体 IP 封掉"（见 DESIGN D8 与新增的 D22）。这条限制决定了
// 地区条目挡不住非 frp 的入口 —— 未命中过的地址在内核里没有任何痕迹。
const (
	// TargetGeoCountry 按国家/地区码匹配（ISO 3166-1 alpha-2，如 CN、HK）。
	TargetGeoCountry = "geo_country"
	// TargetGeoProvince 按省级行政区匹配（归一化形态，如 广东、内蒙古）。
	TargetGeoProvince = "geo_province"
	// TargetGeoCity 按城市匹配（归一化形态，如 深圳、Brisbane）。
	TargetGeoCity = "geo_city"
)

// IsGeoTargetType 判断目标类型是否按地区匹配。
//
// 单独一个判断函数而不是在调用处列举取值：地区条目与 IP 条目在**落地方式**上
// 完全不同（地区不写内核规则、命中后靠封禁具体 IP 生效），凡是需要分岔的地方
// 都应当问这个函数，而不是各自写一遍枚举 —— 漏掉一处的表现是"某条路径上
// 地区条目被当成了 IP 去解析"，静默失效。
func IsGeoTargetType(t string) bool {
	switch t {
	case TargetGeoCountry, TargetGeoProvince, TargetGeoCity:
		return true
	}
	return false
}

// CanonicalCity 把城市名归一成统一形态。
//
// 与省份不同，城市名的候选集是**开放的** —— 全国几百个地级市，还有国外的，
// 这里做不了"必须出现在候选表里"那种强制校验，只能统一写法：去掉「市」后缀、
// 剥掉「中国」前缀、把 ip2region 的 "0" 占位当成空。
//
// 代价必须说清楚：**城市名写错不会报错，只会永远不命中**。省份之所以能强制
// 校验，是因为它只有 34 个值、且写错的后果同样是静默失效 —— 那种情况下报错是
// 唯一合理的处理；城市只能靠界面上的提示 + 属地查询工具让用户自己核对。
func CanonicalCity(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return ""
	}
	// ip2region 对国家/地区会带「中国」前缀，国外城市名不带；剥掉之后
	// 「中国香港」这类也能和规则里的写法对上。
	if rest := strings.TrimPrefix(s, "中国"); rest != "" && rest != s {
		s = rest
	}
	// 只去「市」。直辖市的区、国外的行政区后缀（City / -shi 之类）一律不动 ——
	// 猜得越多，错得越隐蔽。
	s = strings.TrimSuffix(s, "市")
	return strings.TrimSpace(s)
}

// NormalizeGeoTarget 按目标类型归一化地区文本，并做该粒度能做的校验。
//
// 归一化的结果就是入库形态，也是匹配时拿来做比较的形态。三种粒度的校验强度
// 不同，这是有意的，不是没写完：
//
//   - 国家码：**只校验格式**（两位字母），不查"是不是真实存在的国家"。
//     看着像少了一道校验，其实是查不了：能查的只有 geoip 包那份国家表，
//     而它是**刻意只收常见来源地**的（未收录的国家按 ISO 码展示，不影响功能），
//     拿它当白名单会把哈萨克斯坦、古巴、巴拿马这类真实国家一起拒掉。
//     要真校验得先有一份完整 ISO 3166-1 表，那是另一件事。
//     （也不能靠 geoip 包解决依赖问题：它的包内测试引用了 model，
//     model 反向依赖会构成测试期循环依赖。）
//   - 省份：查真实性。候选集**完整且封闭**（34 个省级行政区），而写错的后果是
//     静默不命中 —— 这种情况下报错是唯一合理的处理。
//   - 城市：只归一化，不查真实性。候选集开放（全国几百个地级市，还有国外的），
//     列不全，见 CanonicalCity。
//
// 国家与城市都因此有一个共同的边界：**写错不会报错，只会永远不命中**。
// 界面上的提示与属地查询工具是给这个边界兜底的最后一环。
func NormalizeGeoTarget(targetType, raw string) (string, error) {
	switch targetType {
	case TargetGeoCountry:
		out := make([]string, 0, 4)
		for _, c := range splitList(raw) {
			c = strings.ToUpper(c)
			if len(c) != 2 || c[0] < 'A' || c[0] > 'Z' || c[1] < 'A' || c[1] > 'Z' {
				return "", fmt.Errorf("国家/地区码「%s」格式不正确，应为两位字母（如 CN、HK）", c)
			}
			out = append(out, c)
		}
		if len(out) == 0 {
			return "", fmt.Errorf("国家/地区不能为空")
		}
		return strings.Join(dedupeStrings(out), ","), nil

	case TargetGeoProvince:
		out := make([]string, 0, 4)
		for _, p := range splitList(raw) {
			c := CanonicalProvince(p)
			if c == "" {
				continue
			}
			if !IsKnownProvince(c) {
				return "", fmt.Errorf("省份「%s」无法识别，请从候选列表中选择（如 广东、内蒙古、中国香港）", p)
			}
			out = append(out, c)
		}
		if len(out) == 0 {
			return "", fmt.Errorf("省份不能为空")
		}
		return strings.Join(dedupeStrings(out), ","), nil

	case TargetGeoCity:
		out := make([]string, 0, 4)
		for _, c := range splitList(raw) {
			if v := CanonicalCity(c); v != "" {
				out = append(out, v)
			}
		}
		if len(out) == 0 {
			return "", fmt.Errorf("城市不能为空")
		}
		return strings.Join(dedupeStrings(out), ","), nil
	}
	return "", fmt.Errorf("未知的地区类型「%s」", targetType)
}

// MatchGeo 判断一条地区条目是否命中所给属地。
//
// 三个属地参数是**原始值**（属地库返回什么就传什么），归一化在这里做：
// 名单侧在保存时已经归一化，查询侧不过一遍同样的归一化就永远对不上 ——
// 这是省份上踩过的坑（见 province.go 的注释），城市同理。
//
// 属地查不到时返回 false。反过来做的话，"只封某国"会在属地库没加载时
// 变成"封住所有人"，而那台机器上恰好可能还没有库文件。
func MatchGeo(targetType, list, country, province, city string) bool {
	switch targetType {
	case TargetGeoCountry:
		c := strings.ToUpper(strings.TrimSpace(country))
		if c == "" {
			return false
		}
		for _, v := range splitList(list) {
			if strings.ToUpper(v) == c {
				return true
			}
		}
	case TargetGeoProvince:
		p := CanonicalProvince(province)
		if p == "" {
			return false
		}
		for _, v := range splitList(list) {
			if CanonicalProvince(v) == p {
				return true
			}
		}
	case TargetGeoCity:
		c := CanonicalCity(city)
		if c == "" {
			return false
		}
		for _, v := range splitList(list) {
			if CanonicalCity(v) == c {
				return true
			}
		}
	}
	return false
}

// GeoTargetLabel 返回地区类型给界面看的中文名。
func GeoTargetLabel(t string) string {
	switch t {
	case TargetGeoCountry:
		return "国家/地区"
	case TargetGeoProvince:
		return "省份"
	case TargetGeoCity:
		return "城市"
	}
	return ""
}
