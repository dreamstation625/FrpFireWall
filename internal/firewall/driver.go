// Package firewall 定义防火墙后端抽象。
//
// 核心设计：
//  1. 受管规则独占命名空间（iptables 用自定义链，nftables 用独立表），
//     任何情况下都不 flush 整表、不碰用户已有规则。
//  2. 上层只描述"期望状态"，由各驱动翻译成自己的命令。
//  3. 全量 Sync 幂等，可随时重放，用来做崩溃自愈与配置漂移修复。
package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
// iptables 侧用两条独占的自定义链；nftables 侧不建独立表/链（见 nftables.go 的说明），
// 只创建带前缀的集合，并把规则插进系统的 input 链，靠 comment 标记识别归属。
const (
	// ManagedChain iptables 主链名。
	ManagedChain = "FRPFIREWALL_GUARD"
	// managedBlackChain iptables 黑名单子链。
	// 单独拆一个子链，是为了让增量封禁可以用纯追加（-A）和按内容删除（-D），
	// 完全不需要关心规则在主链里的位置。
	managedBlackChain = "FRPFIREWALL_BLACK"

	// managedBlackFrpChain 是"仅 frp 端口"用的子链，规则带 dport 限定。
	// 与上面那条分开成两条链而不是混在一条里，因为两者的规则形状不同
	// （带不带端口条件），混在一起后按内容删除就得逐条比对整套参数。
	managedBlackFrpChain = "FRPFIREWALL_BLACK_FRP"

	// commentPrefix 是识别"这条规则属于本程序"的标记前缀。
	commentPrefix = "frpfirewall"
	commentBlack  = "frpfirewall:black"
	commentBlack6 = "frpfirewall:black6"
	// 注意这两个值以 commentBlack 开头，所以识别处只能用 Contains(commentPrefix)，
	// 不能写成 HasPrefix(line, commentBlack)，否则 frp 范围的规则会被误判成全端口。
	commentBlackFrp  = "frpfirewall:black-frp"
	commentBlack6Frp = "frpfirewall:black6-frp"
	commentRate      = "frpfirewall:rate"

	// nftables 集合名，统一加 frpfirewall_ 前缀避免与系统集合撞名。
	setBlack     = "frpfirewall_black"
	setBlack6    = "frpfirewall_black6"
	setBlackFrp  = "frpfirewall_black_frp"
	setBlack6Frp = "frpfirewall_black6_frp"
	setRate      = "frpfirewall_rate"

	// multiportMax 是 iptables multiport 一次能列举的端口数上限。
	// 超过就得拆成多条规则，不然整条命令会被内核拒掉。
	//
	// 注意这里数的是「端口或区间」的个数，不是一个区间里包含多少个端口 ——
	// 单个区间 20000:30000 只占一个名额。
	multiportMax = 15
)

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

// RateLimitSpec 连接速率限制配置。
type RateLimitSpec struct {
	Enabled bool `json:"enabled"`
	// PerSec 单 IP 每秒允许的新建连接数。
	PerSec int `json:"per_sec"`
	// Burst 突发额度。
	Burst int `json:"burst"`
}

// Desired 是上层期望的防火墙状态。驱动负责把它翻译成具体规则。
type Desired struct {
	// Blacklist 需要封禁的 IP / CIDR 列表，作用于该地址到本机的全部端口。
	Blacklist []string
	// BlacklistFrp 只封 frp 服务端口（即 ProtectPorts）的 IP / CIDR 列表。
	//
	// 单独一个字段而不是把端口条件塞进 Blacklist，是因为两种规则的写法差得远：
	// 前者光凭地址就能表达，后者必须带上 dport。合成一个列表就得额外传一份
	// "哪几条属于 frp 范围"的映射，不如让上层直接分好再送下来。
	BlacklistFrp []string
	// Whitelist 豁免封禁的 IP / CIDR 列表（不是全端口放行，见驱动实现）。
	Whitelist []string
	// ProtectPorts 受保护的服务端口：速率限制作用于此，BlacklistFrp 也按它生成 dport。
	//
	// 用区间集合而不是 []int：frps 的 allowPorts 常常是一整个大区间，
	// 展开成一个个端口会让下发的规则条数随区间宽度线性膨胀。
	ProtectPorts portrange.Set
	// RateLimit 为 nil 或 Enabled=false 时不下发限速规则。
	RateLimit *RateLimitSpec
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
	// Reason 不支持时的原因说明。
	Reason string `json:"reason"`
}

// ManagedRules 是本程序受管规则的展示结构。
type ManagedRules struct {
	Backend string   `json:"backend"`
	Summary []string `json:"summary"`
	Raw     string   `json:"raw"`
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
	// AddBlock / DelBlock 是增量操作，日常封禁解封走这里，避免全量重建。
	AddBlock(target string) error
	DelBlock(target string) error
	// DumpManaged 返回受管规则（结构化 + 原始文本），用于前端展示。
	DumpManaged() (*ManagedRules, error)
	// DumpSystem 返回系统完整规则（只读展示，绝不修改）。
	DumpSystem() (string, error)
	// Preview 只生成规则文本，不落盘，用于"预览变更"与 dry-run 校验。
	Preview(d Desired) (string, error)
	// Snapshot / Restore 用于变更前备份与失败回滚。
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
