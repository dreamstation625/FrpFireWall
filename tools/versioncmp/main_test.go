package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestDecidePublishes(t *testing.T) {
	cases := []struct {
		name      string
		candidate string
		existing  []string
		want      bool
	}{
		// 首次发布：还没有任何 release
		{"首次发布_正式版", "0.0.1", nil, true},
		{"首次发布_预发布版", "0.0.1-pre.01", nil, true},
		{"基准为空字符串", "0.0.1", []string{"", "  ", "\t"}, true},

		// 正常递增
		{"预发布序号递增", "0.0.1-pre.02", []string{"0.0.1-pre.01"}, true},
		{"修订号递增", "0.0.2", []string{"0.0.1"}, true},
		{"次版本递增", "0.1.0", []string{"0.0.9"}, true},
		{"主版本递增", "1.0.0", []string{"0.99.99"}, true},

		// ★ 预发布转正：0.0.1 > 0.0.1-pre.99
		{"预发布转正", "0.0.1", []string{"0.0.1-pre.99"}, true},
		{"预发布转正_基准含多个", "0.0.1", []string{"0.0.1-pre.01", "0.0.1-pre.02"}, true},

		// 取的是最高基准，不是任意一个
		{"基准里有更高版本时仍按最高比", "0.0.2", []string{"0.0.1", "0.0.5"}, false},
		{"高于最高基准即可", "0.0.6", []string{"0.0.5", "0.0.1"}, true},

		// 重复推送 / 已发布后重推 → 跳过
		{"同版本正式版重复", "0.0.1", []string{"0.0.1"}, false},
		{"同序号预发布重复", "0.0.1-pre.01", []string{"0.0.1-pre.01"}, false},

		// ★ 倒退：正式版已发布，再推同号预发布版
		{"正式版已发布_推同号预发布应跳过", "0.0.1-pre.02", []string{"0.0.1"}, false},
		{"高于已发布正式版的预发布可以发", "0.0.2-pre.01", []string{"0.0.1"}, true},

		// 严格更旧
		{"比已发布更旧", "0.0.1", []string{"0.0.2"}, false},
		{"比已发布更旧的预发布", "0.0.1-pre.09", []string{"0.0.1-pre.10"}, false},

		// 无法解析的历史 tag 不阻塞，也不参与比较
		{"忽略无法解析的历史tag", "0.0.1", []string{"release-2024", "0.0.1-beta.1"}, true},
		{"忽略历史tag后仍能正确判否", "0.0.1", []string{"release-2024", "0.0.2"}, false},

		// 常见书写差异
		{"基准带v前缀", "0.0.2", []string{"v0.0.1"}, true},
		{"候选带v前缀", "v0.0.2", []string{"0.0.1"}, true},
		{"基准带CRLF", "0.0.2", []string{"0.0.1\r"}, true},
		{"基准序号未补零", "0.0.1-pre.02", []string{"0.0.1-pre.1"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := decide(tc.candidate, tc.existing)
			if err != nil {
				t.Fatalf("decide 报错: %v", err)
			}
			if d.Publish != tc.want {
				t.Errorf("candidate=%s existing=%v → publish=%v，期望 %v（max=%v hasMax=%v）",
					tc.candidate, tc.existing, d.Publish, tc.want, d.Max, d.HasMax)
			}
		})
	}
}

// 非法候选版本号必须是硬错误，不能静默当成「不发布」——
// 否则 tag 写错时工作流会绿灯通过，问题被藏起来。
func TestDecideRejectsBadCandidate(t *testing.T) {
	bad := []string{
		"",
		"nope",
		"1.2",
		"1.2.3.4",
		"0.0.1-rc.1",
		"0.0.1-dev",
		"0.0.1-pre.0",
		"0.0.1-pre.",
		"0.0.0",
		"v",
	}
	for _, c := range bad {
		t.Run("candidate="+c, func(t *testing.T) {
			if _, err := decide(c, []string{"0.0.1"}); err == nil {
				t.Errorf("候选 %q 应当被拒绝，却通过了", c)
			}
		})
	}
}

// 基准里的最高版本与忽略项要如实统计，方便排查。
func TestDecideReportsMaxAndIgnored(t *testing.T) {
	d, err := decide("0.0.3", []string{"0.0.1", "垃圾tag", "0.0.2", "also-bad"})
	if err != nil {
		t.Fatalf("decide 报错: %v", err)
	}
	if !d.HasMax || d.Max.String() != "0.0.2" {
		t.Errorf("max 应为 0.0.2，实际 %v (hasMax=%v)", d.Max, d.HasMax)
	}
	if d.Considered != 2 {
		t.Errorf("参与比较的应为 2 个，实际 %d", d.Considered)
	}
	if len(d.Ignored) != 2 || d.Ignored[0] != "垃圾tag" || d.Ignored[1] != "also-bad" {
		t.Errorf("忽略项不对: %v", d.Ignored)
	}
	if !d.Publish {
		t.Error("0.0.3 高于 0.0.2，应当发布")
	}
}

// stdout 会被直接追加到 $GITHUB_OUTPUT，必须是干净的 key=value 单行，
// 不能混入人类可读文字或空 key。
func TestRunStdoutIsGithubOutputSafe(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"-candidate", "0.0.2", "-existing", "-"},
		strings.NewReader("0.0.1\n"), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run 报错: %v", err)
	}

	out := stdout.String()
	if !strings.HasSuffix(out, "\n") {
		t.Error("stdout 应以换行结尾")
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	want := map[string]string{
		"publish":   "true",
		"candidate": "0.0.2",
		"max":       "0.0.1",
	}
	seen := map[string]bool{}
	for _, ln := range lines {
		k, v, ok := strings.Cut(ln, "=")
		if !ok {
			t.Errorf("输出行 %q 不是 key=value", ln)
			continue
		}
		if k == "" {
			t.Errorf("输出行 %q 的 key 为空", ln)
		}
		if strings.ContainsAny(ln, "\r") {
			t.Errorf("输出行 %q 含回车", ln)
		}
		if w, expect := want[k]; expect {
			if v != w {
				t.Errorf("%s = %q，期望 %q", k, v, w)
			}
			seen[k] = true
		}
	}
	for k := range want {
		if !seen[k] {
			t.Errorf("stdout 缺少 %q 键", k)
		}
	}

	// 人类可读说明走 stderr
	if !strings.Contains(stderr.String(), "判定:") {
		t.Errorf("stderr 应包含判定说明，实际: %q", stderr.String())
	}
}

// 无基准时 max 输出空值，方便 workflow 里直接引用。
func TestRunEmptyExisting(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"-candidate", "0.0.1-pre.01", "-existing", "-"},
		strings.NewReader(""), &stdout, &stderr); err != nil {
		t.Fatalf("run 报错: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "publish=true\n") {
		t.Errorf("无基准应当发布，stdout=%q", out)
	}
	if !strings.Contains(out, "max=\n") {
		t.Errorf("无基准时 max 应为空，stdout=%q", out)
	}
	if !strings.Contains(stderr.String(), "尚无已发布版本") {
		t.Errorf("stderr 应提示无已发布版本，实际: %q", stderr.String())
	}
}

// 缺 -candidate 必须报错，不能默认放行。
func TestRunRequiresCandidate(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(nil, strings.NewReader(""), &stdout, &stderr); err == nil {
		t.Error("未指定 -candidate 应当报错")
	}
}
