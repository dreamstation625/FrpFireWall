package model

import (
	"fmt"
	"hash/fnv"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/portrange"
)

// 细分规则在应用层匹配和计数，内核只执行已触发的封禁。
const (
	LayerKernel = "kernel" // 兼容旧版接口常量，不再用于细分频控。
	LayerApp    = "app"
)

// RateRule 同一维度多个值为 OR，不同维度之间为 AND。
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
	// Cities 城市名，逗号分隔，如 "深圳,广州"。
	//
	// 与省份的关键差别：城市名**不校验真实性**，只做写法归一（见 CanonicalCity）。
	// 候选集是开放的（全国几百个地级市加上海外城市），而写错的后果同样是静默
	// 不命中 —— 省份只有 34 个值、能做成封闭校验，城市做不到，只能靠界面提示。
	Cities string `gorm:"size:512;not null;default:''" json:"cities"`
	// CIDRs 来源地址段，逗号/空格/换行分隔，如 "1.2.3.0/24, 2001:db8::/32"。
	//
	// 显式指定列名：GORM 的命名策略把 "CIDRs" 拆成了 C + ID + Rs
	// （ID 在 commonInitialisms 里），不加 column 的话列名会是 c_id_rs。
	CIDRs string `gorm:"column:cidrs;size:4096;not null;default:''" json:"cidrs"`
	// Ports 实际被访问的目的端口，仅是匹配条件，不决定封禁范围。
	// 本版本仅在 Login 使用 bindPort；代理名规则必须留空。
	Ports string `gorm:"size:1024;not null;default:''" json:"ports"`
	// ProxyName frp 的代理（隧道）名，精确匹配，单个值。
	//
	// 空 = 不限代理，这条规则对所有连接生效（与老行为一致）。
	// 非空 = 只有回调里报上来的代理名与它完全相同时才命中，用来给不同隧道
	// 定不同的力度（给某个代理单独限速 / 单独封禁）。
	//
	// 只支持单个值而不是列表：多个代理要不同规则，就建多条规则 —— 一条规则
	// 绑一串名字的话，"这条命中了是因为哪个"又说不清了。
	//
	// 它只能落在应用层：代理名来自 frps 的 NewUserConn 回调，内核层压根没有
	// 这个概念。**Login 回调不带代理名**（隧道还没建立），所以带这条件件的
	// 规则在登录阶段一律不命中 —— 这不是缺陷，是那一刻还没有这个信息。
	//
	// 填了它就已经算一个匹配条件（Validate 认），所以可以出现"只有代理名、
	// 没有地区和网段"的规则 —— 那正是"给这个隧道定一套自己的参数"的写法。
	ProxyName string `gorm:"size:128;not null;default:''" json:"proxy_name"`

	// ---- 动作 ----

	// Block 命中即拦截：直接拒绝这次连接，不计数、不限速。
	//
	// 直接拦截首次命中后才产生来源封禁；默认仍为全端口。
	// 不能与限速 / 封禁配置同时出现：命中就直接拒了，后面那些参数永远轮不到
	// 生效。留着就是"配了不生效"的陷阱，Validate 会直接拒绝这种组合。
	// 这里带 default:false 并不违背上面 Enabled 那条"不加 default"的经验：
	// 那个坑的条件是**默认值为 true** —— 零值 false 被省略，就变成库里默认的 true。
	// 默认值本身就是 false 时，省略与不省略的结果一致，所以留着无妨。
	// 但别顺手把它改成 default:true：那会立刻复现同一个 bug 的反向版本
	//（显式写入的 false 读回来变成 true，"关掉拦截"保存后还在拦）。
	Block bool `gorm:"not null;default:false" json:"block"`

	// ---- 动作：限速 ----

	// PerSec 单个来源 IP 每秒允许的连接数。0 表示不限速。
	PerSec int `gorm:"not null;default:0" json:"per_sec"`
	// Burst 突发额度。PerSec > 0 且 Burst <= 0 时按 PerSec*2 自动补齐。
	Burst int `gorm:"not null;default:0" json:"burst"`

	// ---- 动作：封禁 ----

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

// Layer 返回判定位置：所有细分规则统一在应用层。
func (r *RateRule) Layer() string { return LayerApp }

// HasProxyCondition 是否指定了代理（隧道）名。空 = 不限代理。
func (r *RateRule) HasProxyCondition() bool {
	return strings.TrimSpace(r.ProxyName) != ""
}

// HasGeoCondition 是否带属地条件。
func (r *RateRule) HasGeoCondition() bool {
	return strings.TrimSpace(r.Countries) != "" ||
		strings.TrimSpace(r.Provinces) != "" ||
		strings.TrimSpace(r.Cities) != ""
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

// CityList 把城市拆开、归一化、去重。
//
// 归一化放在这里（而不是只在 Normalize 里）的理由与 ProvinceList 相同：
// 让所有读出城市的地方拿到同一套形态 —— 校验用它、落库用它、guard 编译规则
// 也用它。只要有一处拿到原始字符串，规则就可能在"看着配了"和"实际生效"之间错位。
func (r *RateRule) CityList() []string {
	out := make([]string, 0, 4)
	for _, s := range splitList(r.Cities) {
		if c := CanonicalCity(s); c != "" {
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

// BanRef 返回这条规则在封禁记录里的来源引用，停用的规则返回空串。
//
// 用**内容签名**而不是规则 ID：rate_rules 表是整体替换的（保存时先清空再插入，
// ID 每次都会变），拿 ID 当引用的话，保存一次规则之后历史封禁里的 "rule:5"
// 就指向了另一条规则 —— 删掉它会把不相干的地址一起解封。
//
// 签名只取影响判定的字段，不含名字：改个名字不该让谁解封；而条件一改，旧的
// 封禁依据就不成立了，旧签名随之消失、由它封的地址跟着解封，正是想要的。
// 停用的规则不产生封禁，所以直接返回空串 —— 这样"停用"天然落进"旧签名消失"
// 的那一类，不需要单独判一次。
func (r *RateRule) BanRef() string {
	if !r.Enabled {
		return ""
	}
	// ProxyName 必须在签名里：它决定这条规则对谁生效。改了代理名等于换了
	// 一批适用对象，旧的封禁依据不再成立，应由它们跟着解封。
	sig := strings.Join([]string{
		strconv.FormatBool(r.Block),
		r.Countries, r.Provinces, r.Cities, r.CIDRs, r.Ports, r.ProxyName,
	}, "|")
	h := fnv.New32a()
	_, _ = h.Write([]byte(sig))
	return BanRefRule + ":" + strconv.FormatUint(uint64(h.Sum32()), 16)
}

// RateRuleBanRefs 返回一组规则的封禁来源引用集合（停用的不计）。
//
// 保存规则时用它做前后对比：旧集合里有、新集合里没有的，就是"依据已经消失"
// 的那些 —— 被删掉的、被停用的、条件被改动的，三种情况一并覆盖。
func RateRuleBanRefs(rules []RateRule) map[string]bool {
	out := make(map[string]bool, len(rules))
	for i := range rules {
		if ref := rules[i].BanRef(); ref != "" {
			out[ref] = true
		}
	}
	return out
}

// Normalize 把各字段改写成规范形态并回写。
//
// 存储形态就是用户敲进去的那串文本（去重、排序之后），中间不做结构转换 ——
// 这样界面读回来的和用户写下去的是一回事，排查时不用在脑子里做一次翻译。
// 返回改了什么，供调用方提示用户。
func (r *RateRule) Normalize() {
	r.Name = strings.TrimSpace(r.Name)
	r.Remark = strings.TrimSpace(r.Remark)
	// 代理名只去首尾空白，不做大小写折叠：frp 的代理名是区分大小写的，
	// 界面上看见的是 "Web-SSH" 就必须按 "Web-SSH" 去比，悄悄改大小写会让
	// 一条规则从"命中"变成"永远不命中"，而配置看起来一字没变。
	r.ProxyName = strings.TrimSpace(r.ProxyName)
	r.Countries = strings.Join(dedupeStrings(r.CountryList()), ",")

	// 省份归一化后回写：见 province.go。存下来的形态和候选表、
	// 以及匹配时用的形态保持同一套，界面里不会出现"我选了广东，
	// 存进去成了广东省"这种对不上的情况。
	r.Provinces = strings.Join(r.ProvinceList(), ",")

	// 城市同理：存下来的形态与匹配时用的形态保持同一套。
	r.Cities = strings.Join(r.CityList(), ",")

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
	if strings.TrimSpace(r.BanDurations) != "" {
		if _, err := ParseDurationSteps(r.BanDurations); err != nil {
			return fmt.Errorf("封禁配置不完整或非法: %w", err)
		}
	}
	if r.PerSec > 1000000 || r.Burst > 2000000 {
		return fmt.Errorf("连接速率或突发额度超出上限")
	}
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
	hasProxy := r.HasProxyCondition()
	// 代理名本身就是一种匹配条件：只有它、没有地区和网段，是"给这个隧道单独
	// 定一套参数"的正常写法（不同代理不同力度）。不加进来的话这种规则会被
	// 当成"没有任何条件、会命中所有流量"给拒掉，功能直接配不出来。
	if !hasGeo && !hasCIDR && !hasPorts && !hasProxy {
		return fmt.Errorf("规则「%s」没有任何匹配条件，会命中所有流量；全量兜底请用上方的全局规则", r.Name)
	}
	// NewUserConn 没有目的端口；本版本不接入端口映射，不能保存永远不命中的组合。
	if hasProxy && hasPorts {
		return fmt.Errorf("规则「%s」未接入代理端口映射：按代理名对新连接做频控时，请将目的端口留空", r.Name)
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
	// 城市不校验真实性（候选集开放），但要挡住"填了却一个有效值都不剩"：
	// 那种规则会落在应用层、界面上看着配了属地条件，实际永远不命中 ——
	// 与省份写错是同一类问题，只是这里只能用"归一到空"这个更弱的判据。
	if strings.TrimSpace(r.Cities) != "" && len(r.CityList()) == 0 {
		return fmt.Errorf("规则「%s」的城市「%s」没有一个能识别，请检查写法（如 深圳、广州）", r.Name, r.Cities)
	}
	if _, err := r.PrefixList(); err != nil {
		return fmt.Errorf("规则「%s」：%w", r.Name, err)
	}
	_, err := r.PortSet()
	if err != nil {
		return fmt.Errorf("规则「%s」：%w", r.Name, err)
	}

	if r.PerSec < 0 || r.PerSec > 1000000 || r.Burst > 2000000 {
		return fmt.Errorf("规则「%s」的每秒连接数上限不能为负数", r.Name)
	}
	if r.Burst < 0 {
		return fmt.Errorf("规则「%s」的突发额度不能为负数", r.Name)
	}

	// 命中即拦截的规则不需要、也不允许再配限速 / 封禁：命中就拒了，那些参数
	// 永远轮不到生效。
	if r.Block {
		if r.RateConfigured() || r.BanConfigured() {
			return fmt.Errorf(
				"规则「%s」同时配置了「直接拦截」和限速/封禁：命中就直接拒绝了，后面的限速与阈值"+
					"永远不会被用到。两者只保留一个", r.Name)
		}
		return nil
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
