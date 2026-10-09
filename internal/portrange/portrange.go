// Package portrange 用一个「端口区间集合」来表达一组端口。
//
// 为什么不是 []int：frp 的 allowPorts 最常见的写法就是一整个大区间（例如
// 20000-30000）。展开成一万个整数之后，iptables 侧要拆成上千条 multiport 规则、
// nft 侧要生成一个上万元素的集合，而两者其实都只需要一条区间表达式。
// 用区间表达，下发成本退回常量级，用户填的也是他脑子里本来就有的那个区间。
//
// 本包只管三件事：解析用户的文本写法、把结果归一化（合并 / 去重 / 排序）、
// 渲染成各后端要的文本。规则怎么拼是驱动自己的事。
package portrange

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// 端口取值范围，与内核一致。
const (
	MinPort = 1
	MaxPort = 65535
)

// Range 是一段端口，闭区间 [Lo, Hi]。Lo == Hi 表示单个端口。
type Range struct {
	Lo int `json:"lo"`
	Hi int `json:"hi"`
}

// Set 是一组端口区间。
//
// 约定：构造出来的 Set 一律是规范形态 —— 已合并重叠与相邻区间、已按 Lo 升序。
// Parse / Ports / Merge / Normalize 都保证这一点，所以调用方不用再自己归一化。
//
// 把「归一化的义务」留给调用方是上一版踩过的坑：函数签名里没写，调用方带着
// 重复端口进来，生成的规则虽然多半还能被内核接受，但读起来完全无法判断
// 是不是写错了。现在归一化由类型本身兜住，驱动那边再兜一层（见 Normalize）。
type Set []Range

// Contains 判断实际目的端口是否属于集合，不展开区间。
func (s Set) Contains(port int) bool {
	for _, r := range s {
		if port >= r.Lo && port <= r.Hi {
			return true
		}
	}
	return false
}

// Ports 用一组单端口构造集合。
func Ports(ns ...int) Set {
	s := make(Set, 0, len(ns))
	for _, n := range ns {
		s = append(s, Range{Lo: n, Hi: n})
	}
	return s.normalized()
}

// Span 用一段区间构造集合，起止写反会对调。
func Span(lo, hi int) Set {
	return Set{{Lo: lo, Hi: hi}}.normalized()
}

// Parse 解析用户的文本写法，例如 "80,443,20000-30000"。
//
//	分隔符   半角/全角逗号、半角/全角分号、任意空白（含换行）
//	区间     20000-30000 或 20000:30000，起止写反自动对调
//	容错     空项直接忽略（"80,,443" 和结尾多一个逗号都很常见）
//
// 非法项会返回带原文的错误，而不是像早先那样静默丢掉 —— 静默丢掉的后果是
// 用户以为配了、实际没配，这种"以为保护了其实没保护"最难发现。
func Parse(s string) (Set, error) {
	out := make(Set, 0, 4)
	for _, tok := range splitTokens(s) {
		r, err := parseToken(tok)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out.normalized(), nil
}

// Normalize 返回规范形态的副本。
//
// 驱动在入口处再调一次，作为类型约定的兜底：直接手写 Set 字面量（而不是走
// Parse/Ports/Merge）时不会经过归一化，而越界的端口会让整条 iptables 命令
// 被内核拒掉、连带同一次同步里的正常规则一起失败。
func (s Set) Normalize() Set { return s.normalized() }

// Merge 合并两组区间，重叠与相邻的会并成一段。
func (s Set) Merge(other Set) Set {
	out := make(Set, 0, len(s)+len(other))
	out = append(out, s...)
	out = append(out, other...)
	return out.normalized()
}

// Chunks 按 multiport 槽位切块：单端口占 1 槽，区间占 2 槽。
func (s Set) Chunks(n int) []Set {
	if len(s) == 0 {
		return nil
	}
	if n <= 0 {
		return []Set{s}
	}
	var out []Set
	start, used := 0, 0
	for i, r := range s {
		cost := 1
		if r.Lo != r.Hi {
			cost = 2
		}
		if used > 0 && used+cost > n {
			out = append(out, s[start:i])
			start, used = i, 0
		}
		used += cost
	}
	out = append(out, s[start:])
	return out
}

// String 输出规范文本，例如 "80,443,20000-30000"。单端口不写成 "80-80"。
func (s Set) String() string { return s.StringSep(",") }

// StringSep 用指定分隔符输出规范文本，例如 "80;443;20000-30000"。
//
// 需要它是因为有些格式拿逗号当列分隔符（黑白名单导出文件就是 地址,范围,备注），
// 端口列表再拿逗号分项，一列就会被切成两列 —— 而这类错在读文件时看不出，
// 只有导入之后发现备注少了一半才知道。
func (s Set) StringSep(sep string) string {
	if len(s) == 0 {
		return ""
	}
	parts := make([]string, 0, len(s))
	for _, r := range s {
		if r.Lo == r.Hi {
			parts = append(parts, strconv.Itoa(r.Lo))
			continue
		}
		parts = append(parts, strconv.Itoa(r.Lo)+"-"+strconv.Itoa(r.Hi))
	}
	return strings.Join(parts, sep)
}

// MarshalJSON 把集合输出成文本形式。
//
// 刻意不用 [{"lo":80,"hi":80}] 这种结构：这个值在界面上就是一个文本框，
// 文本形式让前端原样显示、原样提交，中间没有任何结构转换，也就不会出现
// "转换时丢掉一半字段"这种只有打开界面才发现的错。
func (s Set) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON 接受文本形式；同时接受 [80,443] 这种纯数字数组和裸数字 7000，
// 让老客户端与手写的请求体不至于直接报错。
func (s *Set) UnmarshalJSON(b []byte) error {
	var text string
	if err := json.Unmarshal(b, &text); err == nil {
		parsed, perr := Parse(text)
		if perr != nil {
			return perr
		}
		*s = parsed
		return nil
	}
	var nums []int
	if err := json.Unmarshal(b, &nums); err == nil {
		*s = Ports(nums...)
		return nil
	}
	var one int
	if err := json.Unmarshal(b, &one); err == nil {
		*s = Ports(one)
		return nil
	}
	return fmt.Errorf(`端口列表要写成字符串（如 "80,443,20000-30000"）或数字数组`)
}

// normalized 返回合并、排序、修剪过的新集合。始终返回非 nil，便于直接判长度。
func (s Set) normalized() Set {
	if len(s) == 0 {
		return Set{}
	}
	// 先排序再折叠，只需要一次线性扫描。
	sorted := make(Set, len(s))
	copy(sorted, s)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Lo != sorted[j].Lo {
			return sorted[i].Lo < sorted[j].Lo
		}
		return sorted[i].Hi < sorted[j].Hi
	})

	out := make(Set, 0, len(sorted))
	for _, r := range sorted {
		if r.Lo > r.Hi {
			r.Lo, r.Hi = r.Hi, r.Lo
		}
		// 夹到合法范围；夹完为空说明整段都越界，直接丢弃。
		if r.Lo < MinPort {
			r.Lo = MinPort
		}
		if r.Hi > MaxPort {
			r.Hi = MaxPort
		}
		if r.Lo > r.Hi {
			continue
		}
		// Hi+1 意味着「相邻」也算重叠：80,81 并成 80-81 之后，匹配集合与
		// 拆分写法完全一致，但 multiport 只占一个名额、nft 集合少一个元素。
		if n := len(out); n > 0 && r.Lo <= out[n-1].Hi+1 {
			if r.Hi > out[n-1].Hi {
				out[n-1].Hi = r.Hi
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// splitTokens 按分隔符切分，顺带丢掉空项。
func splitTokens(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ',', '，', ';', '；', ' ', '\t', '\r', '\n':
			return true
		}
		return false
	})
}

// parseToken 解析单个端口或区间。
func parseToken(tok string) (Range, error) {
	loS, hiS, hasHi := cutRange(tok)
	lo, ok := portNum(loS)
	if !ok {
		return Range{}, badToken(tok)
	}
	if !hasHi {
		return Range{Lo: lo, Hi: lo}, nil
	}
	hi, ok := portNum(hiS)
	if !ok {
		return Range{}, badToken(tok)
	}
	if lo > hi {
		// 起止写反是明显的笔误，语义没有歧义，对调即可。
		lo, hi = hi, lo
	}
	return Range{Lo: lo, Hi: hi}, nil
}

// cutRange 按第一个 - 或 : 切开。没有分隔符就是单端口。
func cutRange(tok string) (lo, hi string, hasHi bool) {
	if i := strings.IndexAny(tok, "-:"); i >= 0 {
		return strings.TrimSpace(tok[:i]), strings.TrimSpace(tok[i+1:]), true
	}
	return tok, "", false
}

// portNum 判定一段文本是不是合法端口。
func portNum(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil || n < MinPort || n > MaxPort {
		return 0, false
	}
	return n, true
}

func badToken(tok string) error {
	return fmt.Errorf("端口 %q 无法识别：写单个端口（80）或区间（20000-30000），取值范围 %d-%d",
		tok, MinPort, MaxPort)
}
