package guard

import (
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/firewall"
	"github.com/dreamstation625/FrpFireWall/internal/geoip"
	"github.com/dreamstation625/FrpFireWall/internal/model"
	"github.com/dreamstation625/FrpFireWall/internal/portrange"
)

// globalRateKey 是全局兜底规则在内核对象名里的 Key。
//
// 用固定字符串而不是"某条规则的 ID"：全局规则不来自 rate_rules 表，
// 它的对象名必须在重启、改配置、换规则之后都保持不变，否则每次同步都会
// 新建一个内核对象、再删掉旧的。
const globalRateKey = "global"

// appRule 是一条细分规则在运行时的形态（落点在应用层）。
//
// 条件在编译期就解析成 map 与前缀切片，判定时只做比较 —— 判定跑在 frps 插件
// 回调的关键路径上（硬超时 100ms），每个连接现 parse 一遍字符串是不合适的。
type appRule struct {
	id   uint
	name string

	countries map[string]bool
	provinces map[string]bool
	cities    map[string]bool
	prefixes  []netip.Prefix
	// proxy 是代理（隧道）名，空串表示不限代理。
	// 与上面几个一样是 AND 关系：写了就必须对得上。
	proxy string

	// block 为 true 表示这条规则的动作是"命中即拦截"：条件对上就直接拒绝，
	// 后面的 window/threshold/bucket 都不会被用到（Validate 也不允许它们共存）。
	block bool

	// ref 是这条规则在封禁记录里的来源引用（内容签名，见 model.RateRule.BanRef）。
	// 不用规则 ID —— 规则表整体替换，ID 每次保存都会变。
	ref string

	// window / threshold / steps 来自规则自己的封禁配置。
	// threshold <= 0 表示这条规则只管限速、不封禁。
	window    time.Duration
	threshold int
	steps     []int64

	// bucket 为 nil 表示这条规则不限速。perSec 只用于拼错误信息，
	// 真正的计数在 bucket 里（那里按来源 IP 分开算）。
	bucket *tokenBucket
	perSec int
}

// tag 是这条规则在窗口计数里的标识。
//
// 用 id 而不是名字：名字可以改，改了之后窗口计数会从头开始（可以接受），
// 但两个规则重名时会共用一个窗口（不可接受）。
func (r *appRule) tag() string { return "r" + strconv.FormatUint(uint64(r.id), 10) }

// match 判断这条规则是否命中所给来源。
//
// 语义：不同维度之间是 AND，同一维度里的多个值是 OR。
// 属地条件写了但查不到属地（库里没记录、或属地库没加载）时**算不命中** ——
// 反过来做的话，"只限制某国"会在库没加载时变成"限制所有人"。
//
// proxy 是调用方报上来的代理名（Login 回调没有，传空串）。规则指定过代理名
// 就必须相等才算命中，所以**登录阶段的连接永远匹配不上带代理条件的规则** ——
// 那一刻隧道还没建立，没有这个信息，留空比拿别的维度凑合诚实。
func (r *appRule) match(addr netip.Addr, geo *geoip.Info, proxy string) bool {
	if r.proxy != "" && r.proxy != proxy {
		return false
	}
	if len(r.countries) > 0 {
		if geo == nil || !r.countries[geo.Country] {
			return false
		}
	}
	if len(r.provinces) > 0 {
		// 查询侧也要归一化：属地库返回的是「广东省」「内蒙古自治区」这类全称，
		// 而规则里存的是归一后的「广东」「内蒙古」。不归一的话两边永远对不上，
		// 而且是静默不命中。
		if geo == nil || !r.provinces[model.CanonicalProvince(geo.Province)] {
			return false
		}
	}
	if len(r.cities) > 0 {
		// 城市同理。注意城市名的候选集是开放的：写成「深圳」还是「深圳市」
		// 由 CanonicalCity 统一，但写成别的城市名不会报错、只会不命中 ——
		// 这一点在界面上必须说清楚（见 model.CanonicalCity）。
		if geo == nil || !r.cities[model.CanonicalCity(geo.City)] {
			return false
		}
	}
	if len(r.prefixes) > 0 {
		hit := false
		for _, p := range r.prefixes {
			if p.Contains(addr) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

// kernelRule 是一条细分规则在内核侧的形态（落点在内核）。
//
// 内核只有丢包一种动作，所以这里没有窗口/阈值/阶梯。
type kernelRule struct {
	key    string
	name   string
	srcs   []string
	ports  portrange.Set
	perSec int
	burst  int
}

// ruleKey 派生一条规则的内核对象 Key。
//
// 内含 ID，所以规则被删掉重建之后对象名会变 —— 这是可以接受的：
// 内核对象每次同步都整体重建，旧的会被清理掉（见 nftables 的 pruneRateSets）。
func ruleKey(id uint) string { return "r" + strconv.FormatUint(uint64(id), 36) }

// compileRules 把库里的规则编译成运行时结构，顺序保持不变（库按 priority 返回）。
//
// 编译不过的规则**逐条跳过**并给出原因，不让一条坏规则把整个引擎带下水：
// 规则是存在数据库里的，手工改库、降级回老版本、改过 geoip 库之后都可能出现
// 编译不过的行，而那时候引擎必须还能起来。
func compileRules(rows []model.RateRule) (app []appRule, kernel []kernelRule, skipped []string) {
	app = make([]appRule, 0, len(rows))
	kernel = make([]kernelRule, 0, len(rows))
	skipped = make([]string, 0)

	for i := range rows {
		row := rows[i]
		if !row.Enabled {
			continue
		}
		if err := row.Validate(); err != nil {
			skipped = append(skipped, err.Error())
			continue
		}

		prefixes, err := row.PrefixList()
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("规则「%s」：%v", row.Name, err))
			continue
		}
		ports, err := row.PortSet()
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("规则「%s」：%v", row.Name, err))
			continue
		}

		if len(ports) > 0 {
			srcs := make([]string, 0, len(prefixes))
			for _, p := range prefixes {
				srcs = append(srcs, p.String())
			}
			kernel = append(kernel, kernelRule{
				key:    ruleKey(row.ID),
				name:   row.Name,
				srcs:   srcs,
				ports:  ports,
				perSec: row.PerSec,
				burst:  row.Burst,
			})
			continue
		}

		a := appRule{
			id:        row.ID,
			name:      row.Name,
			countries: stringSet(row.CountryList()),
			provinces: stringSet(row.ProvinceList()),
			cities:    stringSet(row.CityList()),
			prefixes:  prefixes,
			proxy:     row.ProxyName,
			block:     row.Block,
			ref:       row.BanRef(),
		}
		if row.WindowSeconds > 0 && row.Threshold > 0 {
			a.window = time.Duration(row.WindowSeconds) * time.Second
			a.threshold = row.Threshold
			// 阶梯原样带过去，**这里不兜底**。
			//
			// 阶梯的三级兜底（本规则 → 全局策略 → 内置 600 秒）统一由
			// nextDuration 负责（见 ban.go）。这里再兜一个 600 的话，
			// "规则没写阶梯"会拿到硬编码的 600，而不是全局策略里配的那条 ——
			// 同一个概念两处实现，改了一处另一处不动，迟早对不上。
			//
			// 走到这里 steps 一般是非空的：Validate 要求窗口/阈值/阶梯三件套齐全。
			// 留成空切片也只是为了让兜底链还有一层可用，不是正常路径。
			a.steps = row.DurationSteps()
		}
		if row.PerSec > 0 {
			a.perSec = row.PerSec
			a.bucket = newTokenBucket(row.PerSec, row.Burst)
		}
		app = append(app, a)
	}
	return app, kernel, skipped
}

func stringSet(in []string) map[string]bool {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]bool, len(in))
	for _, v := range in {
		out[v] = true
	}
	return out
}

// rateLimitsLocked 编译出本次要下发的内核限速规则。调用方需持有读锁。
//
// **顺序**：细分规则在前，全局兜底在最后。内核规则是"先匹配先生效"
// （iptables 是链上顺序，nft 是插入链首），顺序反了细分规则就永远轮不到。
func (m *Manager) rateLimitsLocked() []firewall.RateLimitRule {
	if m.policy != nil && m.policy.ObserveOnly {
		return nil
	}
	out := make([]firewall.RateLimitRule, 0, len(m.kernelRules)+1)
	for _, r := range m.kernelRules {
		out = append(out, firewall.RateLimitRule{
			Key:     r.key,
			Name:    r.name,
			Sources: r.srcs,
			Ports:   r.ports,
			PerSec:  r.perSec,
			Burst:   r.burst,
		})
	}
	if m.policy != nil && m.policy.RateLimitEnabled && m.policy.RateLimitPerSec > 0 {
		out = append(out, firewall.RateLimitRule{
			Key:    globalRateKey,
			Name:   "全局兜底",
			Ports:  m.protectPortsLocked(),
			PerSec: m.policy.RateLimitPerSec,
			Burst:  m.policy.RateLimitBurst,
		})
	}
	return out
}

// matchAppRule 按优先级找第一条命中的应用层规则，没有则返回 nil。
//
// 返回的指针指向上一次 Refresh 装进来的那份切片。Refresh 是整体换切片
// （不是原地改），所以这里即使在锁外继续用也是安全的：旧切片不会被改写。
func (m *Manager) matchAppRule(addr netip.Addr, geo *geoip.Info, proxy string) *appRule {
	m.mu.RLock()
	rules := m.appRules
	m.mu.RUnlock()
	return pickAppRule(rules, addr, geo, proxy)
}

// pickAppRule 从一串规则里取第一条命中的。抽成自由函数是为了让
// IP 查询工具能复用同一套判定，而不是另写一份"看起来一样"的匹配逻辑。
func pickAppRule(rules []appRule, addr netip.Addr, geo *geoip.Info, proxy string) *appRule {
	for i := range rules {
		if rules[i].match(addr, geo, proxy) {
			return &rules[i]
		}
	}
	return nil
}

// AppRuleCount 返回当前生效的应用层规则条数，供界面展示。
func (m *Manager) AppRuleCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.appRules)
}

// ---------- 应用层令牌桶 ----------

// tokenBucket 是按来源 IP 计数的令牌桶。
//
// 为什么应用层也要一个：内核与应用的匹配维度不同 —— 内核按端口分流，
// 应用层按属地与网段分流。一条"某地区访客限速"的规则在内核里表达不出来
// （插件回调拿不到被访问的端口，内核也拿不到属地，见 DESIGN D16），
// 所以规则落在哪一层，限速就在哪一层做，两边的桶互不影响。
type tokenBucket struct {
	rate  float64
	burst float64

	mu    sync.Mutex
	state map[string]*bucketState
}

type bucketState struct {
	tokens float64
	last   time.Time
}

func newTokenBucket(perSec, burst int) *tokenBucket {
	b := burst
	if b <= 0 {
		b = perSec * 2
	}
	return &tokenBucket{
		rate:  float64(perSec),
		burst: float64(b),
		state: make(map[string]*bucketState),
	}
}

// allow 判断这次连接是否放行，并扣掉一个令牌。
//
// 令牌按流逝的时间懒补齐，不需要后台定时器 —— 每分钟几十万次也不可能，
// 但这套东西跑在 frps 的登录路径上，能不加协程就不加。
func (b *tokenBucket) allow(ip string, now time.Time) bool {
	if b == nil || b.rate <= 0 {
		return true
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	st := b.state[ip]
	if st == nil {
		// 新来源从满桶开始：否则每个新 IP 的第一次连接都会被拒，
		// 表现成"限速一开，所有人第一次连都失败"。
		st = &bucketState{tokens: b.burst, last: now}
		b.state[ip] = st
	}

	st.tokens += now.Sub(st.last).Seconds() * b.rate
	if st.tokens > b.burst {
		st.tokens = b.burst
	}
	st.last = now

	if st.tokens < 1 {
		return false
	}
	st.tokens--
	return true
}

// prune 清掉长时间没活动的条目，防止内存随历史 IP 无限增长。
func (b *tokenBucket) prune(cutoff time.Time) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, st := range b.state {
		if st.last.Before(cutoff) {
			delete(b.state, k)
		}
	}
}
