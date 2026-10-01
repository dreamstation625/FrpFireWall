// Command versioncmp 判断候选版本号是否高于已发布的所有版本。
//
// 它是发布工作流的守门员：只有当版本号相对「已发布的 release」真的提升了，
// 才继续走构建与发布流程。这样能挡掉三类无意义的发布：
//
//   - 重复推送同一个 tag（release 已存在，再建会报错）；
//   - 推一个比线上更旧的版本（会把 latest 指回旧版本，用户看到「降级」）；
//   - 推一个比现有正式版更低的预发布版（本该被忽略的倒退）。
//
// # 为什么比较基准是 release 而不是 git tag
//
// tag 在 release 建成之前就已经存在了。如果拿 git tag 当基准，那么
// 「构建失败」或「release 创建失败」之后重跑工作流时，本次 tag 会出现在
// 基准列表里，判定为「没有提升」而被跳过 —— 于是失败的发布永远修不好。
//
// 换成已发布的 release 列表就自洽了：
//
//	首次推送        release 里没有它，候选 > 基准      → 发布
//	发布失败后重跑  release 里仍然没有它，候选 > 基准  → 重新发布
//	已发布后重推    release 里有它，候选 == 基准       → 跳过
//
// # 输出约定
//
// 人类可读的说明写到 stderr（在 Actions 日志里直接可见），机器可读的
// key=value 写到 stdout，方便直接追加重定向到 $GITHUB_OUTPUT。
//
// 用法：
//
//	go run ./tools/versioncmp -candidate v0.0.2-pre.01 -existing released.txt
//
// 基准版本号每行一个，可带 v 前缀，空行忽略，- 表示从标准输入读取。
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/dreamstation625/FrpFireWall/internal/version"
)

// decision 是守门结果。
type decision struct {
	// Publish 为 true 表示版本号确实提升了，应当继续构建发布。
	Publish bool
	// Candidate 是候选版本号的规范形式。
	Candidate version.Number
	// Max 是已发布版本里的最高版本，HasMax 为 false 时无意义。
	Max    version.Number
	HasMax bool
	// Considered 是成功解析并参与比较的基准版本数。
	Considered int
	// Ignored 是无法解析、被跳过的基准条目原文。
	Ignored []string
}

// decide 是纯计算部分，与 IO 分离，便于测试。
func decide(candidate string, existing []string) (decision, error) {
	cand, err := version.Parse(candidate)
	if err != nil {
		return decision{}, fmt.Errorf("候选版本号无法解析：%w", err)
	}
	if cand.IsZero() {
		// 0.0.0 本身合法但毫无意义，当成错误更能防住手滑
		return decision{}, fmt.Errorf("候选版本号 %q 解析为零值", candidate)
	}

	d := decision{Candidate: cand}
	for _, raw := range existing {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		n, err := version.Parse(raw)
		if err != nil || n.IsZero() {
			// 无法解析的历史 tag 不参与比较，但记下来提示
			d.Ignored = append(d.Ignored, raw)
			continue
		}
		d.Considered++
		if !d.HasMax || version.Compare(n, d.Max) > 0 {
			d.Max, d.HasMax = n, true
		}
	}

	d.Publish = !d.HasMax || version.Compare(cand, d.Max) > 0
	return d, nil
}

// reason 返回一句可读的判定理由，用作 Actions 的 notice 文案。
func (d decision) reason() string {
	switch {
	case !d.HasMax:
		return "尚无已发布版本，首个版本直接发布"
	case d.Publish:
		return fmt.Sprintf("高于已发布的最高版本 %s", d.Max)
	default:
		return fmt.Sprintf("不高于已发布的最高版本 %s，跳过构建与发布", d.Max)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("versioncmp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	candidate := fs.String("candidate", "", "候选版本号，可带 v 前缀")
	existingPath := fs.String("existing", "-", "已发布版本号列表文件，每行一个；- 表示标准输入")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *candidate == "" {
		return errors.New("必须通过 -candidate 指定候选版本号")
	}

	var (
		lines []string
		err   error
	)
	if *existingPath == "-" {
		lines, err = readLines(stdin)
	} else {
		f, ferr := os.Open(*existingPath)
		if ferr != nil {
			return fmt.Errorf("读取基准列表：%w", ferr)
		}
		defer f.Close()
		lines, err = readLines(f)
	}
	if err != nil {
		return fmt.Errorf("读取基准列表：%w", err)
	}

	d, err := decide(*candidate, lines)
	if err != nil {
		return err
	}

	fmt.Fprintf(stderr, "候选版本: %s\n", d.Candidate)
	if d.HasMax {
		fmt.Fprintf(stderr, "已发布最高版本: %s（共比较 %d 个）\n", d.Max, d.Considered)
	} else {
		fmt.Fprintf(stderr, "已发布最高版本: 无（共比较 %d 个）\n", d.Considered)
	}
	if len(d.Ignored) > 0 {
		fmt.Fprintf(stderr, "忽略 %d 个无法解析的历史 tag: %s\n", len(d.Ignored), strings.Join(d.Ignored, ", "))
	}
	fmt.Fprintf(stderr, "判定: %s\n", d.reason())

	// stdout 只留机器可读内容，直接重定向到 $GITHUB_OUTPUT
	fmt.Fprintf(stdout, "publish=%t\n", d.Publish)
	fmt.Fprintf(stdout, "candidate=%s\n", d.Candidate)
	if d.HasMax {
		fmt.Fprintf(stdout, "max=%s\n", d.Max)
	} else {
		fmt.Fprintln(stdout, "max=")
	}
	fmt.Fprintf(stdout, "reason=%s\n", d.reason())

	return nil
}

// readLines 按行读取，容忍 CRLF 与末尾无换行。
func readLines(r io.Reader) ([]string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n"), nil
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "versioncmp: %v\n", err)
		os.Exit(1)
	}
}
