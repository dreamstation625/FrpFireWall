package geoip

import (
	"sort"
	"strings"
)

// countryNames 是 ISO 3166-1 alpha-2 → 中文名 的映射。
//
// 只收录常见来源地（覆盖绝大多数攻击与访客来源），
// 未收录的国家直接展示 ISO 码，不影响功能。
//
// 注意：中国香港、中国台湾、中国澳门是中国的一部分，按规范标注为地区名。
var countryNames = map[string]string{
	"CN": "中国",
	"HK": "中国香港",
	"TW": "中国台湾",
	"MO": "中国澳门",

	"US": "美国", "CA": "加拿大", "MX": "墨西哥",
	"BR": "巴西", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚", "PE": "秘鲁",
	"VE": "委内瑞拉", "EC": "厄瓜多尔", "BO": "玻利维亚", "PY": "巴拉圭", "UY": "乌拉圭",

	"JP": "日本", "KR": "韩国", "KP": "朝鲜", "MN": "蒙古",
	"SG": "新加坡", "MY": "马来西亚", "TH": "泰国", "VN": "越南",
	"ID": "印度尼西亚", "PH": "菲律宾", "IN": "印度", "PK": "巴基斯坦",
	"BD": "孟加拉国", "LK": "斯里兰卡", "NP": "尼泊尔", "MM": "缅甸",
	"KH": "柬埔寨", "LA": "老挝", "BN": "文莱",

	"RU": "俄罗斯", "UA": "乌克兰", "BY": "白俄罗斯", "KZ": "哈萨克斯坦",
	"UZ": "乌兹别克斯坦", "GE": "格鲁吉亚", "AM": "亚美尼亚", "AZ": "阿塞拜疆",

	"DE": "德国", "FR": "法国", "GB": "英国", "IE": "爱尔兰",
	"NL": "荷兰", "BE": "比利时", "LU": "卢森堡", "CH": "瑞士", "AT": "奥地利",
	"IT": "意大利", "ES": "西班牙", "PT": "葡萄牙", "GR": "希腊",
	"PL": "波兰", "CZ": "捷克", "SK": "斯洛伐克", "HU": "匈牙利",
	"RO": "罗马尼亚", "BG": "保加利亚", "RS": "塞尔维亚", "HR": "克罗地亚",
	"SI": "斯洛文尼亚", "BA": "波黑", "AL": "阿尔巴尼亚", "MK": "北马其顿",
	"SE": "瑞典", "NO": "挪威", "DK": "丹麦", "FI": "芬兰", "IS": "冰岛",
	"EE": "爱沙尼亚", "LV": "拉脱维亚", "LT": "立陶宛", "MD": "摩尔多瓦",

	"TR": "土耳其", "IL": "以色列", "SA": "沙特阿拉伯", "AE": "阿联酋",
	"QA": "卡塔尔", "KW": "科威特", "BH": "巴林", "OM": "阿曼",
	"JO": "约旦", "LB": "黎巴嫩", "SY": "叙利亚", "IQ": "伊拉克",
	"IR": "伊朗", "AF": "阿富汗",

	"EG": "埃及", "ZA": "南非", "NG": "尼日利亚", "KE": "肯尼亚",
	"MA": "摩洛哥", "TN": "突尼斯", "DZ": "阿尔及利亚", "LY": "利比亚",
	"ET": "埃塞俄比亚", "GH": "加纳", "TZ": "坦桑尼亚", "UG": "乌干达",
	"CM": "喀麦隆", "CI": "科特迪瓦", "SN": "塞内加尔", "ZW": "津巴布韦",
	"MZ": "莫桑比克", "AO": "安哥拉", "SD": "苏丹", "SO": "索马里",

	"AU": "澳大利亚", "NZ": "新西兰", "FJ": "斐济", "PG": "巴布亚新几内亚",
}

// CountryName 返回国家/地区的中文名；未收录时原样返回 ISO 码。
func CountryName(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return ""
	}
	if n, ok := countryNames[code]; ok {
		return n
	}
	return code
}

// Country 是国家选项，供前端下拉多选。
type Country struct {
	Code string `json:"code"`
	Name string `json:"name"`
	// Common 标记常见来源地，前端可置顶展示。
	Common bool `json:"common"`
}

// 常见的攻击/扫描来源地，前端选项里置顶。
var commonCodes = map[string]bool{
	"US": true, "RU": true, "CN": true, "IN": true, "BR": true,
	"VN": true, "ID": true, "DE": true, "NL": true, "FR": true,
	"GB": true, "KR": true, "JP": true, "SG": true, "HK": true,
	"TW": true, "UA": true, "TR": true, "IR": true, "TH": true,
}

// Countries 返回全部可选国家/地区，常见项排前面。
func Countries() []Country {
	out := make([]Country, 0, len(countryNames))
	for code, name := range countryNames {
		out = append(out, Country{Code: code, Name: name, Common: commonCodes[code]})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Common != out[j].Common {
			return out[i].Common
		}
		return out[i].Code < out[j].Code
	})
	return out
}

// IsKnownCountry 判断是否是已知国家/地区码（用于校验用户输入）。
func IsKnownCountry(code string) bool {
	_, ok := countryNames[strings.ToUpper(strings.TrimSpace(code))]
	return ok
}
