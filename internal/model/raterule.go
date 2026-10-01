package model

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/portrange"
)

// 频控规则的两种落点。
//
// 落点不是用户选的，是由"有没有端口条件"推出来的，原因见 RateRule 的注释。
const (
	// LayerKernel 内核层：由防火墙按 dport 丢包，只能限速。
	LayerKernel = "kernel"
	// LayerApp 应用层：由 frps 插件判定，能限速也能封禁。
	LayerApp = "app"
)

// RateRule 是一条细分频控规则。
//
// 为什么落点由"有没有端口条件"决定，而不是由"有没有地区条件"决定：
//
//   - 需要按"访问了哪个端口"分流，只能在内核做 —— frps 的插件回调
//     （Login / NewUserConn）里根本没有被访问的端口，只有来源地址。
//   - 反过来，需要按"来源属地"分流，只能在应用层做 —— DESIGN 的 D8 定了
//     不把地区下沉到内核，而且 mmdb / ip2region 是查询型库，没法反向枚举出
//     一个国家的 CIDR 列表，想下沉也做不到。
//
// 两条合起来：**端口和地区不可能同时出现在一条规则里**，Validate 会直接拒绝，
// 而不是保存下来之后静默地少生效一半。
//
// 内核层还有一条硬边界：它只能丢包。超限的包在内核就被丢了，根本到不了 frps，
// 应用层自然也无从"发现它超限"，所以内核规则**不能封禁**，只有限速。
type RateRule struct {
	ID   uint   `gorm:"primaryKey" json:"id"`
	Name string `gorm:"size:64;not null" json:"name"`
	// Enabled 注意**没有** default:true，这是踩过坑之后故意的。
	//
	// GORM 对"带默认值的字段"有一条规则：INSERT 时如果该字段是零值，就把它
	// 从 SQL 里省掉，让数据库默认值生效。默认值是 true 的布尔字段，零值恰好
	// 就是 false —— 两条规则叠起来的结果是：**显式写入的 false 会被丢掉，
	// 存进去变成 true**（实测过，`Select("*")` 也绕不过去，那个判断在
	// selectColumns 之前，不受它影响）。
	//
	// 表现就是"把规则停用，保存后又是启用的"，而且库里看不出痕迹。
	// 所以这里不加 default，让 Enabled 老老实实按写入的值存。
	// "新建规则默认启用"是接口层的事，由请求 DTO 用 *bool 承接（见 api 层）。
	Enabled bool `gorm:"not null" json:"enabled"`
	// Priority 匹配顺序，数值小的先匹配。相同则按 ID。不叫 order 是因为
	// order 是 SQL 关键字，列名会得多绕一层引号。
	Priority int `gorm:"not null;default:0" json:"priority"`

	// ---- 匹配条件。同一维度内多个值是 OR，不同维度之间是 AND。----

	// Countries 国家/地区码（ISO 3166-1 alpha-2），逗号分隔，如 "HK,US"。
	Countries string `gorm:"size:512;not null;default:''" json:"countries"`
	// Provinces 省份名，逗号分隔。取值与 ip2region / GeoLite2 返回的一致，
	// 如 "广东省,福建省"。只在有属地库时才有意义。
	Provinces string `gorm:"size:512;not null;default:''" json:"provinces"`
	// CIDRs 来源地址段，逗号/空格/换行分隔，如 "1.2.3.0/24, 2001:db8::/32"。
	//
	// 显式指定列名：GORM 的命名策略把 "CIDRs" 拆成了 C + ID + Rs
	// （ID 在 commonInitialisms 里），不加 column 的话列名会是 c_id_rs。
	CIDRs string `gorm:"column:cidrs;size:4096;not null;default:''" json:"cidrs"`
	// Ports 被访问的目的端口，区间写法，如 "20000-30000,443"。
	//
	// **这个字段一旦非空，规则就落在内核层**，且不能再有国家/省份条件。
	Ports string `gorm:"size:1024;not null;default:''" json:"ports"`

	// ---- 动作：限速 ----

	// PerSec 单个来源 IP 每秒允许的连接数。0 表示不限速。
	PerSec int `gorm:"not null;default:0" json:"per_sec"`
	// Burst 突发额度。PerSec > 0 且 Burst <= 0 时按 PerSec*2 自动补齐。
	Burst int `gorm:"not null;default:0" json:"burst"`

	// ---- 动作：封禁（内核层规则用不上，见类型注释）----

	// WindowSeconds 统计窗口秒数。0 表示这条规则不封禁。
	WindowSeconds int `gorm:"not null;default:0" json:"window_seconds"`
	// Threshold 窗口内达到该次数即封禁。
	Threshold int `gorm:"not null;default:0" json:"threshold"`
	// BanDurations 本规则自己的阶梯封禁时长（秒），逗号分隔，0 表示永久。
	//
	// 阶梯序号仍按"该地址最近一次封禁是第几级"推导（与全局策略一致），
	// 只是**用本规则的表**去取时长。理由：升级说的是"这个人屡教不改"，
	// 跟触发它的是哪条规则无关；而"封多久"是这条规则自己说了算。
	BanDurations string `gorm:"not null;default:''" json:"ban_durations"`

	Remark    string    `gorm:"size:255" json:"remark"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Layer 返回规则落点：有端口条件落内核，否则落应用层。
//
// 只看字段是否为空，不做解析 —— 这个方法要给界面用，非法输入应当先被
// Validate 拦下，而不是让落点跟着解析结果飘。
func (r *RateRule) Layer() string {
	if strings.TrimSpace(r.Ports) != "" {
		return LayerKernel
	}
	return LayerApp
}

// HasGeoCondition 是否带属地条件。
func (r *RateRule) HasGeoCondition() bool {
	return strings.TrimSpace(r.Countries) != "" || strings.TrimSpace(r.Provinces) != ""
}

// CountryList 把国家码拆开，统一大写去重。
func (r *RateRule) CountryList() []string {
	out := make([]string, 0, 4)
	for _, s := range splitList(r.Countries) {
		out = append(out, strings.ToUpper(s))
	}
	return dedupeStrings(out)
}

// ProvinceList 把省份拆开、归一化、去重。
//
// 归一化放在这里（而不是只在 Normalize 里）是为了让**所有**读出省份的地方
// 拿到的是同一套形态：校验用它、落库用它、guard 编译规则也用它。
// 只要有一处拿到的是原始字符串，规则就可能在"看着配了"和"实际生效"之间错位。
func (r *RateRule) ProvinceList() []string {
	out := make([]string, 0, 4)
	for _, s := range splitList(r.Provinces) {
		if c := CanonicalProvince(s); c != "" {
			out = append(out, c)
		}
	}
	return dedupeStrings(out)
}

// PrefixList 解析来源地址段。单个 IP 也接受，会补成 /32 或 /128。
func (r *RateRule) PrefixList() ([]netip.Prefix, error) {
	toks := splitList(r.CIDRs)
	out := make([]netip.Prefix, 0, len(toks))
	for _, tok := range toks {
		p, err := parsePrefixOrAddr(tok)
		if err != nil {
			return nil, fmt.Errorf("来源地址「%s」格式不正确，写单个 IP（1.2.3.4）或网段（1.2.3.0/24）", tok)
		}
		out = append(out, p)
	}
	return out, nil
}

// PortSet 解析端口条件。
func (r *RateRule) PortSet() (portrange.Set, error) {
	if strings.TrimSpace(r.Ports) == "" {
		return nil, nil
	}
	set, err := portrange.Parse(r.Ports)
	if err != nil {
		return nil, fmt.Errorf("端口「%s」无法识别：写单个端口（80）或区间（20000-30000），取值 1-65535", strings.TrimSpace(r.Ports))
	}
	return set, nil
}

// DurationSteps 解析本规则的阶梯封禁时长。
func (r *RateRule) DurationSteps() []int64 {
	out := make([]int64, 0, 4)
	for _, s := range strings.Split(r.BanDurations, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		v, err := strconv.ParseInt(s, 10, 64)
		if err == nil && v >= 0 {
			out = append(out, v)
		}
	}
	return out
}

// BanConfigured 判断这条规则是否配了封禁动作。
func (r *RateRule) BanConfigured() bool {
	return r.WindowSeconds > 0 || r.Threshold > 0 || strings.TrimSpace(r.BanDurations) != ""
}

// RateConfigured 判断这条规则是否配了限速动作。
func (r *RateRule) RateConfigured() bool { return r.PerSec > 0 }

// Normalize 把各字段改写成规范形态并回写。
//
// 存储形态就是用户敲进去的那串文本（去重、排序之后），中间不做结构转换 ——
// 这样界面读回来的和用户写下去的是一回事，排查时不用在脑子里做一次翻译。
// 返回改了什么，供调用方提示用户。
func (r *RateRule) Normalize() {
	r.Name = strings.TrimSpace(r.Name)
	r.Remark = strings.TrimSpace(r.Remark)
	r.Countries = strings.Join(dedupeStrings(r.CountryList()), ",")

	// 省份归一化后回写：见 province.go。存下来的形态和候选表、
	// 以及匹配时用的形态保持同一套，界面里不会出现"我选了广东，
	// 存进去成了广东省"这种对不上的情况。
	r.Provinces = strings.Join(r.ProvinceList(), ",")

	// 地址段按解析后的规范形态回写：把 1.2.3.4 补成 1.2.3.4/32，
	// 把 1.2.3.5/24 归成 1.2.3.0/24。内核规则是按这个字符串下发的。
	if ps, err := r.PrefixList(); err == nil && len(ps) > 0 {
		parts := make([]string, 0, len(ps))
		for _, p := range ps {
			parts = append(parts, p.String())
		}
		r.CIDRs = strings.Join(parts, ",")
	}

	if set, err := r.PortSet(); err == nil && set != nil {
		r.Ports = set.String()
	}

	if r.PerSec > 0 && r.Burst <= 0 {
		r.Burst = r.PerSec * 2
	}
}

// Validate 校验规则。错误信息直接展示给用户，所以要指出是哪一条规则的哪个字段。
//
// 返回值第一项是给用户看的完整描述（带规则名），第二项是纯原因。
func (r *RateRule) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("规则名不能为空")
	}
	if len([]rune(r.Name)) > 64 {
		return fmt.Errorf("规则名「%s」太长，最多 64 个字", r.Name)
	}
	if r.Priority < 0 {
		return fmt.Errorf("规则「%s」的排序值不能为负", r.Name)
	}

	hasGeo := r.HasGeoCondition()
	hasCIDR := strings.TrimSpace(r.CIDRs) != ""
	hasPorts := strings.TrimSpace(r.Ports) != ""
	if !hasGeo && !hasCIDR && !hasPorts {
		return fmt.Errorf("规则「%s」没有任何匹配条件，会命中所有流量；全量兜底请用上方的全局规则", r.Name)
	}

	// 条件解析失败要在这里挡掉，不能留到下发时才炸。
	//
	// 国家码只查格式（两位字母），"是不是真实存在的国家"放在 api 层查 ——
	// 那需要 geoip 包，而 model 不该反过来依赖它。
	for _, c := range r.CountryList() {
		if len(c) != 2 || c[0] < 'A' || c[0] > 'Z' || c[1] < 'A' || c[1] > 'Z' {
			return fmt.Errorf("规则「%s」的国家/地区码「%s」格式不正确，应为两位字母（如 HK、US）", r.Name, c)
		}
	}
	// 省份反过来要查真实性：它的候选集是封闭的（34 个省级行政区），
	// 而且拼错一个字的后果是**永远不命中且不报错** —— 这种"配了等于没配"
	// 必须在保存时就变成一句明确的报错。
	for _, p := range r.ProvinceList() {
		if !IsKnownProvince(p) {
			return fmt.Errorf("规则「%s」的省份「%s」无法识别，请从下拉列表中选择（如 广东、内蒙古、中国香港）", r.Name, p)
		}
	}
	if _, err := r.PrefixList(); err != nil {
		return fmt.Errorf("规则「%s」：%w", r.Name, err)
	}
	ports, err := r.PortSet()
	if err != nil {
		return fmt.Errorf("规则「%s」：%w", r.Name, err)
	}

	// 端口 + 地区：两个条件各自只有一层能判，凑在一起必然有一条不生效。
	if hasPorts && hasGeo {
		return fmt.Errorf(
			"规则「%s」同时写了「地区」和「端口」，无法生效：地区只有 frps 插件能判（它拿不到被访问的端口），"+
				"端口只有内核能判（见 DESIGN D16）。请拆成两条规则", r.Name)
	}

	if len(ports) > 0 {
		// ---- 内核层 ----
		if r.PerSec < 1 {
			return fmt.Errorf("规则「%s」落在内核层，必须填写「每秒连接数上限」", r.Name)
		}
		if r.Burst < 0 {
			return fmt.Errorf("规则「%s」的突发额度不能为负数", r.Name)
		}
		if r.BanConfigured() {
			return fmt.Errorf(
				"规则「%s」落在内核层，不能配置封禁：超限的包在内核就被丢了，到不了 frps，"+
					"应用层无从知道它超限。只保留限速，或去掉端口条件改走应用层", r.Name)
		}
		return nil
	}

	// ---- 应用层 ----
	if r.PerSec < 0 {
		return fmt.Errorf("规则「%s」的每秒连接数上限不能为负数", r.Name)
	}
	if r.Burst < 0 {
		return fmt.Errorf("规则「%s」的突发额度不能为负数", r.Name)
	}
	if !r.RateConfigured() && !r.BanConfigured() {
		return fmt.Errorf("规则「%s」既没有限速也没有封禁阈值，命中后什么都不会发生", r.Name)
	}

	// 封禁的三件套要么齐全、要么都不配。只配一半是最容易配出来的"看起来生效了"。
	banParts := 0
	if r.WindowSeconds > 0 {
		banParts++
	}
	if r.Threshold > 0 {
		banParts++
	}
	if len(r.DurationSteps()) > 0 {
		banParts++
	}
	if banParts != 0 && banParts != 3 {
		return fmt.Errorf("规则「%s」的封禁配置不完整：「统计窗口」「触发阈值」「封禁阶梯」要么都填，要么都不填", r.Name)
	}
	if r.WindowSeconds < 0 || r.WindowSeconds > 86400 {
		return fmt.Errorf("规则「%s」的统计窗口需在 1 ~ 86400 秒之间", r.Name)
	}
	if r.Threshold < 0 || r.Threshold > 100000 {
		return fmt.Errorf("规则「%s」的触发阈值需在 1 ~ 100000 之间", r.Name)
	}
	for _, v := range r.DurationSteps() {
		if v < 0 {
			return fmt.Errorf("规则「%s」的阶梯时长不能为负数", r.Name)
		}
	}
	return nil
}

// ---- 解析辅助 ----

// splitList 按逗号（含中文逗号）、分号、空白拆列表。
//
// 分隔符收得宽一点是有意的：这几栏都是给人手敲的，
// 从别处粘一段出来必然带着换行和全角逗号。
func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	f := func(r rune) bool {
		switch r {
		case ',', '，', ';', '；', ' ', '\t', '\r', '\n':
			return true
		}
		return false
	}
	raw := strings.FieldsFunc(s, f)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// parsePrefixOrAddr 接受 "1.2.3.0/24" 与裸 IP 两种写法。
func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, fmt.Errorf("空")
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}
