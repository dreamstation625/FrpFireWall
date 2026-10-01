package model

import "strings"

// 省份名的归一化与候选表。
//
// 为什么不直接拿字符串比：省份名有多个来源，写法不一样 ——
// MaxMind 的 zh-CN 分区名是「广东省」「内蒙古自治区」，ip2region 是「广东」「内蒙古」，
// 用户在界面里手敲的时候又可能是任意一种。
//
// 直接比字符串的后果是：界面下拉框给的是「广东省」，而某个 IP 查出来是「广东」，
// 这条规则**永远不命中，且没有任何报错**。配规则的人只会觉得"我明明配了却没生效"，
// 在界面和日志里都找不到原因。
//
// 所以规则侧和查询侧都过一遍 CanonicalProvince，把行政级别后缀去掉，
// 收敛成「广东」「内蒙古」「香港」这种最短可辨识形态。

// 后缀按**从长到短**排列，只去掉第一个命中的。
//
// 顺序不能乱：先匹配「壮族自治区」才能把「广西壮族自治区」切成「广西」，
// 要是先撞上「自治区」只剩「广西壮族」，或者先撞上「区」就更离谱。
var provinceSuffixes = []string{
	"特别行政区",
	"维吾尔自治区",
	"壮族自治区",
	"回族自治区",
	"自治区",
	"省",
	"市",
}

// CanonicalProvince 把各种写法的省份名归一成统一形态。
//
// 空、ip2region 的 "0" 占位、以及去掉后缀后什么都不剩的输入，一律返回空串 ——
// 空串在匹配时算"没有属地"，不会命中任何带省份条件的规则。
func CanonicalProvince(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return ""
	}

	// ip2region 对国家/地区会带上「中国」前缀（「中国香港」），去掉。
	// 判断非空是为了别把单独的「中国」也削成空串。
	if rest := strings.TrimPrefix(s, "中国"); rest != "" && rest != s {
		s = rest
	}

	for _, suf := range provinceSuffixes {
		if rest := strings.TrimSuffix(s, suf); rest != "" && rest != s {
			return rest
		}
	}
	return s
}

// Province 是一个省份候选值，供前端下拉选择。
type Province struct {
	// Name 归一化后的名字 —— **规则里存的就是这个**，也是匹配时实际比较的值。
	Name string `json:"name"`
	// Full 完整行政区名，只用于界面展示。
	Full string `json:"full"`
	// Area 大区，前端按它分组。
	Area string `json:"area"`
}

// 34 个省级行政区。Name 已按 CanonicalProvince 的规则手工写好，
// 由 TestProvincesAreCanonical 保证这份表跟归一化函数永远一致。
var provinceTable = []Province{
	{Name: "北京", Full: "北京市", Area: "华北"},
	{Name: "天津", Full: "天津市", Area: "华北"},
	{Name: "河北", Full: "河北省", Area: "华北"},
	{Name: "山西", Full: "山西省", Area: "华北"},
	{Name: "内蒙古", Full: "内蒙古自治区", Area: "华北"},

	{Name: "辽宁", Full: "辽宁省", Area: "东北"},
	{Name: "吉林", Full: "吉林省", Area: "东北"},
	{Name: "黑龙江", Full: "黑龙江省", Area: "东北"},

	{Name: "上海", Full: "上海市", Area: "华东"},
	{Name: "江苏", Full: "江苏省", Area: "华东"},
	{Name: "浙江", Full: "浙江省", Area: "华东"},
	{Name: "安徽", Full: "安徽省", Area: "华东"},
	{Name: "福建", Full: "福建省", Area: "华东"},
	{Name: "江西", Full: "江西省", Area: "华东"},
	{Name: "山东", Full: "山东省", Area: "华东"},

	{Name: "河南", Full: "河南省", Area: "华中"},
	{Name: "湖北", Full: "湖北省", Area: "华中"},
	{Name: "湖南", Full: "湖南省", Area: "华中"},

	{Name: "广东", Full: "广东省", Area: "华南"},
	{Name: "广西", Full: "广西壮族自治区", Area: "华南"},
	{Name: "海南", Full: "海南省", Area: "华南"},

	{Name: "重庆", Full: "重庆市", Area: "西南"},
	{Name: "四川", Full: "四川省", Area: "西南"},
	{Name: "贵州", Full: "贵州省", Area: "西南"},
	{Name: "云南", Full: "云南省", Area: "西南"},
	{Name: "西藏", Full: "西藏自治区", Area: "西南"},

	{Name: "陕西", Full: "陕西省", Area: "西北"},
	{Name: "甘肃", Full: "甘肃省", Area: "西北"},
	{Name: "青海", Full: "青海省", Area: "西北"},
	{Name: "宁夏", Full: "宁夏回族自治区", Area: "西北"},
	{Name: "新疆", Full: "新疆维吾尔自治区", Area: "西北"},

	// 中国香港、中国台湾、中国澳门是中国的一部分，按规范标为地区。
	{Name: "香港", Full: "中国香港", Area: "港澳台"},
	{Name: "澳门", Full: "中国澳门", Area: "港澳台"},
	{Name: "台湾", Full: "中国台湾", Area: "港澳台"},
}

// ProvinceNames 是候选名的集合，用于校验。
//
// 单独存一份是为了让 IsKnownProvince 是 O(1)：校验会在每条规则的每次保存、
// 以及每次 Refresh 编译规则时跑到，没必要为了 34 个元素线性扫。
var provinceNames = func() map[string]bool {
	m := make(map[string]bool, len(provinceTable))
	for _, p := range provinceTable {
		m[p.Name] = true
	}
	return m
}()

// Provinces 返回全部省份候选值，顺序固定（大区顺序 + 区内顺序）。
func Provinces() []Province {
	out := make([]Province, len(provinceTable))
	copy(out, provinceTable)
	return out
}

// IsKnownProvince 判断（任意写法的）省份名是否能归一到候选表里的某一项。
func IsKnownProvince(s string) bool {
	c := CanonicalProvince(s)
	return c != "" && provinceNames[c]
}
