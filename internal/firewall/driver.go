// Package firewall 定义防火墙后端抽象。
//
// 核心设计：
//  1. 受管对象独占命名空间（iptables 用自定义链，nftables 用前缀集合与普通限速子链），
//     任何情况下都不 flush 整表、不碰用户已有规则。
//  2. 上层只描述"期望状态"，由各驱动翻译成自己的命令。
//  3. 全量 Sync 幂等，可随时重放，用来做崩溃自愈与配置漂移修复。
package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/portrange"
)

type Backend string

const (
	BackendAuto     Backend = "auto"
	BackendIPTables Backend = "iptables"
	BackendNFTables Backend = "nftables"
)

// ErrNotSupported 表示该后端在当前主机不可用。
var ErrNotSupported = errors.New("防火墙后端在当前主机不可用")

// 受管对象的名字，集中在这里方便排查。
//
// iptables 使用三条独占自定义链；nftables 复用可靠探测到的系统 input 链，
// 使用前缀集合与普通限速子链，靠 comment 识别受管规则；无 input 链时才建独立表。
const (
	// ManagedChain iptables 主链名。
	ManagedChain = "FRPFIREWALL_GUARD"
	// managedBlackChain iptables 黑名单子链。
	// 单独拆一个子链，是为了让增量封禁可以用纯追加（-A）和按内容删除（-D），
	// 完全不需要关心规则在主链里的位置。
	managedBlackChain = "FRPFIREWALL_BLACK"

	// managedPortBlackChain 是"只在指定端口上封禁"用的子链，规则带 dport 限定。
	// 与上面那条分开成两条链而不是混在一条里，因为两者的规则形状不同
	// （带不带端口条件），混在一起后按内容删除就得逐条比对整套参数。
	//
	// 所有端口限定分组共用这一条链，而不是每组一条：「仅 frp 端口」与「自定义
	// 端口」渲染出来的规则形状完全一样（都是 -s 加 -p/-m multiport --dports），
	// 同一条链里按顺序排下去即可 —— DROP 之间没有先后之分。
	//
	// 链名里的 FRP 是历史遗留（这个子链最初只装 frp 范围）。值刻意不改：
	// 改名字得同时清掉老链、还要处理"升级后老链残留"的中间态，而链名只是排查
	// 时看一眼的东西，不值得为它动内核里已有的对象。
	managedPortBlackChain = "FRPFIREWALL_BLACK_FRP"

	// commentPrefix 是识别"这条规则属于本程序"的标记前缀。
	//
	// 识别处只能用 Contains(commentPrefix)，绝不能写成 HasPrefix(line, commentBlack)：
	// 下面几个值全都以 commentBlack 开头，前缀匹配会把端口限定的规则误判成全端口。
	// 老版本的 frpfirewall:black-frp 也在这个前缀之内，所以升级时老的端口限定规则
	// 照样能被识别出来删掉。
	commentPrefix = "frpfirewall"
	commentBlack  = "frpfirewall:black"
	commentBlack6 = "frpfirewall:black6"
	// commentPortPrefix 是"端口限定"规则的归属注释前缀，后面跟端口签名的摘要。
	// 带摘要是为了让 `nft list chain` 一眼看出哪条规则对应哪一组端口 ——
	// 多条端口限定规则长得一模一样，只有 dport 不同，光看规则本身分不出来。
	commentPortPrefix = "frpfirewall:black-port:"
	commentRate       = "frpfirewall:rate"
	// nftables 集合名，统一加 frpfirewall_ 前缀避免与系统集合撞名。
	setBlack  = "frpfirewall_black"
	setBlack6 = "frpfirewall_black6"
	// setBlackFrp / setBlack6Frp 是**老版本**「仅 frp 端口」用的固定集合名。
	//
	// 现在改成按端口签名派生名字（见 setPortPrefix），这两个名字只用于识别与回收：
	// 不特判的话它们升级后会永远留在内核里 —— 不再被任何规则引用，却一直出现在
	// `nft list sets` 的排查视野里。
	setBlackFrp  = "frpfirewall_black_frp"
	setBlack6Frp = "frpfirewall_black6_frp"

	// nftables 侧每个端口限定分组一个地址集合，名字由端口签名派生。
	//
	// 必须派生而不是全局共用一个：集合里装的是地址，而"哪些地址被限制在哪些端口"
	// 是分组的属性 —— 共用一个集合会让 A 组的地址在 B 组的端口上也被封。
	// v4 / v6 用不同前缀：inet 家族下两个协议栈共用一张表，集合名不能撞。
	//
	// 也不能直接拼端口文本：nft 标识符不认逗号（正是端口列表的分隔符），
	// 而把分隔符换成下划线会让 "8080,9000" 和 "8080-9000" 这两组语义完全不同的
	// 端口撞成同一个名字。取哈希是这条路上唯一简单且稳定的做法。
	// 代价是 fnv32 只有 32 位，理论上两个不同集合会撞名（见 DESIGN.md D14 的说明）。
	setPortPrefix  = "frpfirewall_black_p_"
	setPort6Prefix = "frpfirewall_black6_p_"

	// nftables 侧每条限速规则一个动态集合，名字加这个前缀。
	//
	// 每条规则一个集合，而不是共用一个：nft 的 `limit rate over` 是挂在集合上的
	// 一个状态对象，一个集合只能有一套速率，共用的话所有规则就只能用同一个速率。
	setRatePrefix = "frpfirewall_rate_"

	// multiportMax 是 iptables multiport 一次能列举的端口数上限。
	// 超过就得拆成多条规则，不然整条命令会被内核拒掉。
	//
	// 注意这里数的是「端口或区间」的个数，不是一个区间里包含多少个端口 ——
	// 单个区间 20000:30000 只占一个名额。
	multiportMax = 15

	// hashlimitMaxName 是内核里 --hashlimit-name 的长度上限。
	// 超了 iptables 直接拒绝整条命令（不是静默截断）。
	hashlimitMaxName = 15
)

// objSuffix 把规则 Key 归一成内核标识符能用的片段：只留字母数字下划线。
//
// 归一后为空、或过长时退化成短哈希。**不能靠截断**：截断会让两个只在尾部
// 不同的 Key 撞成同一个内核对象名，表现成"配了两条规则，实际只有一条生效"，
// 而这种错误在内核里看不出来，只能靠人去比对规则条数。
func objSuffix(key string) string {
	var b strings.Builder
	for _, r := range key {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 || b.Len() > 24 {
		return shortHash(key)
	}
	return b.String()
}

// shortHash 返回 Key 的 8 位十六进制摘要。
func shortHash(key string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return fmt.Sprintf("%08x", h.Sum32())
}

// hashlimitName 把规则 Key 变成合法的 --hashlimit-name。
//
// 表名在内核里是全局共享的（/proc/net/ipt_hashlimit/），所以必须带前缀避免
// 和别的工具撞名；而 15 字符的上限装不下用户给规则起的名字（那是中文），
// 只能从 Key 派生。
func hashlimitName(key string) string {
	if s := objSuffix(key); len("frpfw"+s) <= hashlimitMaxName {
		return "frpfw" + s
	}
	return "frpfw" + shortHash(key)
}

// rateSetName 返回一条限速规则专用的 nft 动态集合名。
func rateSetName(key string) string { return setRatePrefix + objSuffix(key) }

// isRateSetName 判断一个集合名是不是本程序创建的限速集合。
//
// 前缀故意少一个下划线：老版本只有一个全局集合 frpfirewall_rate，
// 用带下划线的前缀就漏掉它，升级之后它会一直留在内核里。
func isRateSetName(name string) bool { return strings.HasPrefix(name, "frpfirewall_rate") }

// rateComment 返回一条限速规则的归属注释。
//
// 带上规则自己的后缀，是为了让 `nft list chain` 的输出能一眼看出哪条规则
// 是哪条配置 —— 多条限速规则长得一模一样，只有速率不同，光看规则本身分不出来。
func rateComment(key string) string { return commentRate + ":" + objSuffix(key) }

// portSetName 返回某个端口限定分组在指定协议栈上的地址集合名。
//
// 名字取端口签名的哈希而不是签名本身：端口签名（"80,443"）里的逗号是非法字符，
// 而 objSuffix 那种"只留字母数字"的归一化会制造碰撞 —— "80,443" 与单端口
// 80443 归一后都是 "80443"，两个不同的端口集合共用一个集合名，效果是 A 组的
// 地址在 B 组的端口上也被封了。哈希不保证零碰撞，但要求"故意构造出碰撞"，
// 而归一化是随手就能撞上。
func portSetName(bits int, key string) string {
	if bits == 128 {
		return setPort6Prefix + shortHash(key)
	}
	return setPortPrefix + shortHash(key)
}

// isPortSetName 判断一个集合名是不是端口限定分组用的集合。
//
// 连两个老名字一起认：老版本只有一份「仅 frp 端口」集合，名字是固定的
// frpfirewall_black(_6)_frp，不符合新前缀。不特判的话升级之后它们既不会被
// 引用、也不会被回收，只能永远留在 `nft list sets` 里。这与 isRateSetName
// 少写一个下划线的用意相同。
func isPortSetName(name string) bool {
	switch name {
	case setBlackFrp, setBlack6Frp:
		return true
	}
	return strings.HasPrefix(name, setPortPrefix) || strings.HasPrefix(name, setPort6Prefix)
}

// portComment 返回一个端口限定分组的归属注释。
func portComment(key string) string { return commentPortPrefix + shortHash(key) }

// filterRateRules 按协议栈筛掉不适用的限速规则，并裁掉来源段里的另一种协议。
//
// 两个驱动都要用它，所以放在这里而不是各自的文件里 —— 这条判断错了不会报错，
// 只会静默地下发一条错规则，属于"必须只有一份实现"的那类逻辑。
//
// 关键：一条只有 IPv6 来源的规则落在 IPv4 这一侧时必须**整条跳过**。
// 过滤完只剩空来源却照样下发，等于把"只限这一小段"悄悄放大成"全网限速"——
// 方向正好反了，而且不会有任何报错。
func filterRateRules(list []RateLimitRule, bits int) []RateLimitRule {
	out := make([]RateLimitRule, 0, len(list))
	for _, r := range list {
		if len(r.Sources) == 0 {
			out = append(out, r)
			continue
		}
		srcs := filterByFamily(r.Sources, bits)
		if len(srcs) == 0 {
			continue
		}
		r.Sources = srcs
		out = append(out, r)
	}
	return out
}

// renderPorts 把端口集合渲染成一段文本。
//
// 两个后端的区间写法不同，iptables 认 20000:30000、nft 认 20000-30000，
// 所以 rangeSep 由调用方给。各驱动再各自包一层（iptPorts / nftPorts），
// 免得在调用点直接传两个长相接近的分隔符，一不留神就传反。
func renderPorts(s portrange.Set, rangeSep, joiner string) string {
	parts := make([]string, 0, len(s))
	for _, r := range s {
		if r.Lo == r.Hi {
			parts = append(parts, strconv.Itoa(r.Lo))
			continue
		}
		parts = append(parts, strconv.Itoa(r.Lo)+rangeSep+strconv.Itoa(r.Hi))
	}
	return strings.Join(parts, joiner)
}

// RateLimitRule 是一条落到内核的连接限速规则。
//
// 内核层只有"丢包"这一种动作，没有"封禁"这回事 —— 超限的包在这里就被丢了，
// 根本到不了 frps，应用层也就无从知道它超限。所以这个结构里只有速率，
// 没有窗口 / 阈值 / 封禁时长（见 model.RateRule 的类型注释）。
//
// 全局规则也走这个结构：上层把"全局兜底"和"细分规则"一起编译好送下来，
// 驱动这边只有一条代码路径，不需要知道哪条是全局的。
type RateLimitRule struct {
	// Key 是规则在本程序内的稳定标识，用来派生内核对象名
	// （iptables 的 --hashlimit-name、nft 的动态集合名）。
	//
	// 关键在于**同一条规则拆出来的多个端口分块必须共用它**：共用才能共享
	// 同一张计数表。各块各算一份配额的话，实际放行量会随块数翻倍。
	Key string
	// Name 是给人看的规则名，写进规则注释，便于在 iptables -S / nft list 里对上号。
	Name string
	// Sources 来源地址段。空表示不限来源。
	//
	// 注意：**只有 IPv6 来源的规则在 IPv4 落点上必须整条跳过**，
	// 不能因为过滤后为空就退化成"不限来源" —— 那是把一条限定规则放大成全网限速。
	Sources []string
	// Ports 目的端口。空表示不限端口。
	Ports portrange.Set
	// PerSec 单 IP 每秒连接数上限。<= 0 的规则不下发。
	PerSec int
	// Burst 突发额度。<= 0 时按 PerSec*2 补齐。
	Burst int
}

// burst 返回实际使用的突发额度。
func (r RateLimitRule) burst() int {
	if r.Burst > 0 {
		return r.Burst
	}
	return r.PerSec * 2
}

// PortBlacklist 是一组"只在指定端口上丢弃"的地址。
//
// 「仅 frp 端口」与「自定义端口」在驱动层是同一回事 —— 都是「一组地址 + 一份
// 端口集合」，区别只在上层怎么算出那份端口。所以驱动这边只有一个类型，
// 以后再加一种按端口细分的封禁范围，两个驱动的渲染逻辑一个字都不用动。
type PortBlacklist struct {
	// Key 是这份端口集合的稳定标识，由上层给出。
	//
	// **同一个端口集合必须映射到同一个 Key**，反过来则不能有两个不同的 Key 对应
	// 同一个端口集合：Key 是内核对象名（nft 集合名、规则注释）的来源，撞了就会出现
	// 两套内容不同的规则共用一个集合，表现成"A 组的地址在 B 组的端口上也被封了"。
	// 派生名字前还会再过一道哈希，所以 Key 只要求"同集合同 Key"，不要求可读。
	Key string
	// Label 是给人看的名字（"仅 frp 端口" / "自定义端口 8080"），只用在告警与
	// 展示里 —— 内核对象名用的是 Key，别拿它去拼命令。
	Label string
	// Prefixes 是地址段（CIDR），不保证顺序，也不必已按协议栈过滤：
	// 驱动自己会按落点筛。留白名单做减法由上层完成（见 guard.desired）。
	Prefixes []string
	// Ports 非空。空端口表达不出 dport 条件，上层不会这么传；
	// 真传了驱动会跳过它并给出告警，而不是悄悄下一条"匹配不到任何端口"的规则。
	Ports portrange.Set
}

// Desired 是上层期望的防火墙状态。驱动负责把它翻译成具体规则。
type Desired struct {
	// Blacklist 需要封禁的 IP / CIDR 列表，作用于该地址到本机的全部端口。
	Blacklist []string
	// PortBlacklists 是"只在指定端口上封禁"的分组，每组一份端口集合。
	//
	// 分组而不是两个并列的字段（全端口那份在上面、端口限定那份在这里），是因为
	// 端口限定的来源会越来越多（frp 端口、自定义端口、以后可能的其它预设），
	// 每加一种就在 Desired 上开一个字段，驱动里就多一份渲染分支。
	PortBlacklists []PortBlacklist
	// Whitelist 豁免封禁的 IP / CIDR 列表（不是全端口放行，见驱动实现）。
	Whitelist []string
	// RateLimits 要下发的内核限速规则，按优先级排列（前面的先生效）。
	//
	// 全局兜底规则也在这里面，由上层编译好 —— 驱动不需要区分。
	RateLimits []RateLimitRule
}

// Capability 描述后端能力，供前端展示"哪些功能在当前后端可用"。
type Capability struct {
	Backend   string `json:"backend"`
	Version   string `json:"version"`
	Supported bool   `json:"supported"`
	// RateLimit 是否支持 per-IP 连接速率限制。
	// iptables 用 hashlimit，nftables 用动态 set，能力上都能做；
	// 老内核/老版本不支持时会置 false，前端对应开关置灰。
	RateLimit bool `json:"rate_limit"`
	// CounterGranularity 是丢包计数能细到哪一层：addr = 按地址，
	// group = 只能按规则/分组（nftables 的集合形态决定的，见 RuleCounter
	// 的说明）。空串表示当前后端读不到计数。
	//
	// 前端据此决定怎么展示：group 档下"每个地址拦了多少包"这个问题本身就
	// 没有答案，硬做成按地址只会给出一堆 0。
	CounterGranularity string `json:"counter_granularity"`
	// Reason 不支持时的原因说明。
	Reason string `json:"reason"`
}

// ManagedRules 是本程序受管规则的展示结构。
type ManagedRules struct {
	Backend string   `json:"backend"`
	Summary []string `json:"summary"`
	Raw     string   `json:"raw"`
}

// 计数条目的种类。Kind 决定 Key 是什么、界面怎么归组。
const (
	// CounterKindAddr 是"一个地址/网段"的计数。只有 iptables 能给到这个粒度
	// —— 它每个地址一条规则，计数天然就是按规则的。
	CounterKindAddr = "addr"
	// CounterKindPort 是"端口限定分组"的计数。
	//
	// iptables 上仍然是按地址（规则里带 dport，一条规则一个地址），
	// nftables 上则是整组：地址装在集合里、规则只有一条，见下面的 group。
	CounterKindPort = "port"
	// CounterKindGroup 是"整条规则"的计数，nftables 专用。
	//
	// nft 把全端口黑名单装进一个集合、用**一条**规则引用它，所以内核只在
	// 规则上数数，数不出"哪个地址被拦了多少"。这是两种后端的能力差异，
	// 不是实现偷懒 —— 要做到按地址只能放弃集合、给每个地址单插规则，
	// 地址一多规则条数就爆炸，代价远大于收益。
	CounterKindGroup = "group"
	// CounterKindRate 是限速规则的计数：被速率限制丢掉的包。
	CounterKindRate = "rate"
)

// RuleCounter 是一条受管规则当前累计丢掉的包数与字节数。
//
// 计数来自内核，不是本程序数的：程序只下发规则，数数是内核在协议栈里做的。
// 由此带来两个必须知道的后果：
//
//  1. **只有被内核丢掉的包才算**。frp 登录阶段被插件拒绝的连接不经过内核，
//     它记在事件日志里（login_blocked），不在这里出现。
//  2. **规则被删掉或重建，计数就归零**。全量 Sync、切换后端、重启防火墙服务
//     都会让数字回到 0，所以这是一个"自上次重建以来的累计值"，不是历史总量。
//     需要跨重建的总量时，上层按采样点做增量累加（见 store.CounterSample）。
type RuleCounter struct {
	// Kind 见上面的常量。
	Kind string `json:"kind"`
	// Key 是条目在本程序内的稳定标识：iptables 上是地址（+端口），
	// nftables 上是规则注释里的签名。不要拿它去拼命令。
	Key string `json:"key"`
	// Label 是给人看的名字，由上层按 Kind + Key 补全（驱动没有端口组的
	// 名称信息），驱动侧留空。
	Label string `json:"label"`
	// Family 是协议栈：ip / ip6。同一个 Key 在两个协议栈下各有一条。
	Family  string `json:"family"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// Driver 是防火墙后端统一抽象。
type Driver interface {
	// Name 返回后端标识：iptables / nftables。
	Name() string
	// Capability 返回当前后端的能力与版本。
	Capability() Capability
	// EnsureBase 幂等创建受管链/表，并把跳转挂到系统链上。
	EnsureBase() error
	// Sync 把受管规则对齐到期望状态（全量、幂等、可重放）。
	Sync(d Desired) error
	// AddBlock / DelBlock 保留增量接口；管理器日常操作使用期望状态合并同步。
	AddBlock(target string) error
	DelBlock(target string) error
	// DumpManaged 返回受管规则（结构化 + 原始文本），用于前端展示。
	DumpManaged() (*ManagedRules, error)
	// Counters 读取受管规则当前的丢包计数。
	//
	// 只读、不修改任何规则。后端读不到计数时返回空切片而不是错误 ——
	// 计数是增强信息，读不到不该让调用方整条链路失败。
	Counters() ([]RuleCounter, error)
	// DumpSystem 返回系统完整规则（只读展示，绝不修改）。
	DumpSystem() (string, error)
	// Preview 只生成规则文本，不落盘，用于"预览变更"与 dry-run 校验。
	Preview(d Desired) (string, error)
	// Snapshot 供检查；iptables Restore 只恢复受管链，nft 禁止重放文本系统快照。
	Snapshot() (string, error)
	Restore(snapshot string) error
}

// runTimeout 是外部命令的默认超时。
// 防火墙命令正常都是毫秒级返回，卡住说明内核或 xtables 锁有问题。
const runTimeout = 10 * time.Second

// run 执行外部命令，参数以数组形式传入，不经过 shell，杜绝命令注入。
func run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	err := cmd.Run()
	out := buf.String()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return out, fmt.Errorf("%s 执行超时: %w", name, ctx.Err())
		}
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out))
	}
	return out, nil
}

// runStdin 执行外部命令并把内容喂给它的 stdin（nft -f - / iptables-restore 用）。
func runStdin(ctx context.Context, stdin string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	err := cmd.Run()
	out := buf.String()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return out, fmt.Errorf("%s 执行超时: %w", name, ctx.Err())
		}
		return out, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(out))
	}
	return out, nil
}

// lookPath 判断命令是否存在。
func lookPath(name string) (string, bool) {
	p, err := exec.LookPath(name)
	if err != nil {
		return "", false
	}
	return p, true
}
