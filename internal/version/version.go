// Package version 保存构建期注入的版本信息，并提供版本号解析、比较与更新筛选。
//
// # 版本号格式
//
// 本项目采用语义化版本的一个子集，只有两种形态：
//
//	0.0.1           正式版
//	0.0.1-pre.01    预发布版
//
// 预发布序号从 01 起，规范输出固定两位；超过 99 时自然进位为三位（pre.100）。
// 同一号段内正式版大于其预发布版：0.0.1 > 0.0.1-pre.99。
//
// 版本号的唯一来源是仓库根目录的 VERSION 文件，构建时经 -ldflags -X 注入下面的
// Version 变量。发布 tag 必须与 VERSION 内容一致，这一点由 CI 强制校验。
package version

import (
	"cmp"
	"fmt"
	"strconv"
	"strings"
)

// DefaultRepo 是本项目在 GitHub 上的仓库，供版本更新检查使用。
const DefaultRepo = "dreamstation625/FrpFireWall"

// 这些变量在构建时通过 -ldflags -X 注入，默认值对应 VERSION 文件的内容。
// 改版本号时 VERSION 与这里的 Version 必须一起改——两者脱节不会让任何
// 构建失败（CI 与 Makefile 走的都是注入路径），只会让裸 go build 出来的
// 二进制自称一个错误的版本号，因此由 TestDefaultVersionMatchesVersionFile 兜底。
var (
	Version   = "0.0.1-pre.19"
	Commit    = "unknown"
	BuildTime = "unknown"
)

// String 返回可读的版本串，带提交号。
func String() string {
	if Commit == "unknown" || Commit == "" {
		return Version
	}
	return Version + " (" + Commit + ")"
}

// Number 是解析后的版本号。
//
// Pre 为预发布序号，0 表示正式版。序号从 1 开始，因此 0 可以安全地当作
// 「非预发布」的哨兵值。
type Number struct {
	Major int
	Minor int
	Patch int
	Pre   int
}

// IsPre 判断是否为预发布版。
func (n Number) IsPre() bool { return n.Pre > 0 }

// IsZero 判断是否为零值（解析失败时可能拿到）。
func (n Number) IsZero() bool { return n == Number{} }

// String 输出规范格式的版本号。预发布序号不足两位时补零。
func (n Number) String() string {
	base := fmt.Sprintf("%d.%d.%d", n.Major, n.Minor, n.Patch)
	if n.Pre <= 0 {
		return base
	}
	return fmt.Sprintf("%s-pre.%02d", base, n.Pre)
}

// Parse 解析版本号字符串，接受 "0.0.1" 与 "0.0.1-pre.01" 两种形态。
//
// 为了容错，额外容忍以下输入：
//   - git tag 常见的 "v" 前缀（v0.0.1）
//   - 构建元数据后缀（0.0.1+abcdef）
//   - 预发布序号不补零的写法（0.0.1-pre.1）
//
// 但主版本段必须是三段数字，预发布段必须形如 -pre.NN，否则报错。
func Parse(s string) (Number, error) {
	raw := strings.TrimSpace(s)

	// 去掉构建元数据，它不参与比较
	if i := strings.IndexByte(raw, '+'); i >= 0 {
		raw = raw[:i]
	}
	raw = strings.TrimPrefix(raw, "v")
	if raw == "" {
		return Number{}, fmt.Errorf("版本号为空")
	}

	core := raw
	preStr := ""
	hasPre := false
	if i := strings.Index(raw, "-"); i >= 0 {
		core = raw[:i]
		rest, found := strings.CutPrefix(raw[i+1:], "pre.")
		if !found {
			return Number{}, fmt.Errorf("版本号 %q 的预发布段应为 -pre.NN", s)
		}
		preStr, hasPre = rest, true
	}

	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return Number{}, fmt.Errorf("版本号 %q 应为主.次.修订 三段", s)
	}

	var nums [3]int
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 {
			return Number{}, fmt.Errorf("版本号 %q 的第 %d 段 %q 不是非负整数", s, i+1, p)
		}
		nums[i] = v
	}

	n := Number{Major: nums[0], Minor: nums[1], Patch: nums[2]}

	if hasPre {
		v, err := strconv.Atoi(preStr)
		if err != nil || v <= 0 {
			return Number{}, fmt.Errorf("版本号 %q 的预发布序号 %q 应为正整数", s, preStr)
		}
		n.Pre = v
	}

	return n, nil
}

// MustParse 解析版本号，失败时返回零值。用于默认值等已知合法的场景。
func MustParse(s string) Number {
	n, err := Parse(s)
	if err != nil {
		return Number{}
	}
	return n
}

// Current 返回构建注入的版本号解析结果。
func Current() (Number, error) { return Parse(Version) }

// Compare 按语义化版本规则比较两个版本号，返回 -1 / 0 / 1。
//
// 主次修订依次比较；三者相同时，正式版大于预发布版
// （0.0.1 > 0.0.1-pre.99），两个预发布版之间比较序号。
func Compare(a, b Number) int {
	if c := cmp.Compare(a.Major, b.Major); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Minor, b.Minor); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Patch, b.Patch); c != 0 {
		return c
	}
	switch {
	case a.Pre == 0 && b.Pre == 0:
		return 0
	case a.Pre == 0:
		return 1
	case b.Pre == 0:
		return -1
	default:
		return cmp.Compare(a.Pre, b.Pre)
	}
}

// SelectUpdate 从候选版本中挑出应当提示给用户的那个更新。
//
// 规则（两条轨道，互不跨越）：
//
//   - 当前是正式版 → 只接受更高的正式版，**永不提示预发布版**；
//   - 当前是预发布版 → 接受更高的任意版本，含更高序号预发布版和同号/更高的正式版。
//
// 返回的 order 是「候选里比当前新的最高版本」在 cands 中的下标；ok 为 false
// 表示没有可提示的更新。
//
// 这样设计的原因：正式版用户要的是稳定，把他引到 pre 上是倒退；
// 而 0.0.1-pre.02 的用户已经在预发布轨道上，0.0.1 正式版一发布就应当被推过去。
func SelectUpdate(cur Number, cands []Number) (Number, int, bool) {
	best := Number{}
	bestIdx := -1

	for i, c := range cands {
		if c.IsZero() || Compare(c, cur) <= 0 {
			continue // 不比当前新
		}
		if !cur.IsPre() && c.IsPre() {
			continue // 正式版不追预发布
		}
		if bestIdx < 0 || Compare(c, best) > 0 {
			best, bestIdx = c, i
		}
	}

	if bestIdx < 0 {
		return Number{}, -1, false
	}
	return best, bestIdx, true
}
