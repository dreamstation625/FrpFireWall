package portrange

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string // 期望的规范文本形式，"" 表示空集合
	}{
		{"空串", "", ""},
		{"只有分隔符", " , , ", ""},
		{"单端口", "80", "80"},
		{"多个单端口", "80,443", "80,443"},
		{"中文逗号", "80，443", "80,443"},
		{"分号", "80;443", "80,443"},
		{"空白与换行", "80 443\n7000\t8000", "80,443,7000,8000"},
		{"区间", "20000-30000", "20000-30000"},
		{"冒号区间", "20000:30000", "20000-30000"},
		{"混合", "80,443,20000-30000", "80,443,20000-30000"},

		// 容错：空项直接忽略。多打一个逗号、从别处粘贴带空行都很常见。
		{"多余逗号", "80,,443,", "80,443"},
		{"多个分隔符混用", "80, 443;  7000\n7100", "80,443,7000,7100"},

		// 归一化：重叠合并，相邻也合并。
		{"重叠合并", "20000-25000,24000-30000", "20000-30000"},
		{"完全包含", "20000-30000,21000-22000", "20000-30000"},
		{"相邻合并", "20000-25000,25001-30000", "20000-30000"},
		{"单端口相邻合并", "80,81", "80-81"},
		{"重复端口去重", "80,80,443,443", "80,443"},
		{"乱序排序", "7000,80,443", "80,443,7000"},

		// 有间隔就不要合并 —— 合并进来等于顺手多封了中间的端口。
		{"有间隔不合并", "80,82", "80,82"},
		{"间隔保持", "7000,8000", "7000,8000"},

		// 边界
		{"最小端口", "1", "1"},
		{"最大端口", "65535", "65535"},
		{"全范围", "1-65535", "1-65535"},
		{"起止写反自动对调", "30000-20000", "20000-30000"},
		{"区间两端相同", "7000-7000", "7000"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Parse(c.in)
			if err != nil {
				t.Fatalf("Parse(%q) 报错: %v", c.in, err)
			}
			if got.String() != c.want {
				t.Fatalf("Parse(%q) = %q，期望 %q", c.in, got.String(), c.want)
			}
		})
	}
}

func TestParseRejectsBadInput(t *testing.T) {
	// 这些必须报错。静默丢掉会让用户以为配了、实际没配 ——
	// 对着一个空端口集合下发"仅 frp 端口"封禁，等于一条规则都没有。
	bad := []string{
		"abc", "-5", "80-", "-", "0", "65536", "70000-80000",
		"80,abc,443", "20000-", "1.5", "80,443,99999",
	}
	for _, in := range bad {
		t.Run(in, func(t *testing.T) {
			if got, err := Parse(in); err == nil {
				t.Fatalf("Parse(%q) 应该报错，却返回了 %q", in, got.String())
			}
		})
	}
}

// TestNormalizeDoesNotTouchInput 确认归一化不会就地改写调用方的切片。
// Set 是切片类型，共享底层数组时"顺手排个序"会静默改掉别人手里的数据。
func TestNormalizeDoesNotTouchInput(t *testing.T) {
	original := Set{{Lo: 30000, Hi: 20000}, {Lo: 80, Hi: 80}}
	snapshot := make(Set, len(original))
	copy(snapshot, original)

	got := original.Normalize()
	if !reflect.DeepEqual(original, snapshot) {
		t.Fatalf("归一化改动了入参：%v，原本是 %v", original, snapshot)
	}
	if want := "80,20000-30000"; got.String() != want {
		t.Fatalf("Normalize() = %q，期望 %q", got.String(), want)
	}
}

// TestNormalizeClampsOutOfRange 确认兜底方向是"丢掉越界部分"而不是
// "整段放过"——越界端口会让整条 iptables 命令被内核拒掉。
func TestNormalizeClampsOutOfRange(t *testing.T) {
	cases := []struct {
		name string
		in   Set
		want string
	}{
		{"下界越界被夹住", Set{{Lo: -5, Hi: 10}}, "1-10"},
		{"上界越界被夹住", Set{{Lo: 60000, Hi: 70000}}, "60000-65535"},
		{"整段越界被丢弃", Set{{Lo: 70000, Hi: 80000}}, ""},
		{"全零被丢弃", Set{{Lo: 0, Hi: 0}}, ""},
		{"合法段不受影响", Set{{Lo: 80, Hi: 80}}, "80"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.in.Normalize().String(); got != c.want {
				t.Fatalf("Normalize(%v) = %q，期望 %q", c.in, got, c.want)
			}
		})
	}
}

func TestMerge(t *testing.T) {
	base := Ports(80, 443)
	got := base.Merge(Span(20000, 30000))
	if want := "80,443,20000-30000"; got.String() != want {
		t.Fatalf("Merge 结果 = %q，期望 %q", got.String(), want)
	}
	// 原来那份不能被改到：guard 里同一份配置会被反复合并。
	if base.String() != "80,443" {
		t.Fatalf("Merge 改动了接收者：%q", base.String())
	}
}

// TestMergeBridgesAcrossSets 覆盖 frp 的真实场景：bindPort 就落在代理端口
// 区间里，合并后应当只剩一段，而不是"一个单端口 + 一段区间"。
func TestMergeBridgesAcrossSets(t *testing.T) {
	got := Ports(7000).Merge(Span(20000, 30000)).Merge(Ports(25000))
	if want := "7000,20000-30000"; got.String() != want {
		t.Fatalf("= %q，期望 %q", got.String(), want)
	}

	bridged := Ports(19999).Merge(Span(20000, 30000))
	if want := "19999-30000"; bridged.String() != want {
		t.Fatalf("相邻应被桥接：= %q，期望 %q", bridged.String(), want)
	}
}

func TestChunks(t *testing.T) {
	set, err := Parse("80-90,100-110,200-210")
	if err != nil {
		t.Fatalf("准备数据失败: %v", err)
	}

	if n := len(set.Chunks(15)); n != 1 {
		t.Fatalf("3 个区间按上限 15 切，应得 1 块，实际 %d 块", n)
	}
	parts := set.Chunks(4)
	if len(parts) != 2 {
		t.Fatalf("3 个区间每块 2 个，应得 2 块，实际 %d 块", len(parts))
	}
	if parts[0].String() != "80-90,100-110" || parts[1].String() != "200-210" {
		t.Fatalf("切块结果不对：%q / %q", parts[0].String(), parts[1].String())
	}

	// 空集合必须返回 nil：返回一个空块会让调用方拼出 `--dports ""`。
	if got := (Set{}).Chunks(15); got != nil {
		t.Fatalf("空集合应返回 nil，实际 %v", got)
	}
	// n 非法时不能死循环，按"一块装下"处理。
	if got := set.Chunks(0); len(got) != 1 {
		t.Fatalf("n=0 应退化成单块，实际 %d 块", len(got))
	}
}

func TestJSONRoundTrip(t *testing.T) {
	type holder struct {
		Ports Set `json:"proxy_ports"`
	}

	// 序列化必须是文本形式：界面上就是一个文本框，原样显示原样提交。
	raw, err := json.Marshal(holder{Ports: Span(20000, 30000).Merge(Ports(80))})
	if err != nil {
		t.Fatalf("Marshal 报错: %v", err)
	}
	if want := `{"proxy_ports":"80,20000-30000"}`; string(raw) != want {
		t.Fatalf("Marshal = %s，期望 %s", raw, want)
	}

	var back holder
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("Unmarshal 报错: %v", err)
	}
	if back.Ports.String() != "80,20000-30000" {
		t.Fatalf("往返后 = %q", back.Ports.String())
	}
}

func TestUnmarshalAcceptsLegacyNumberArray(t *testing.T) {
	// 老客户端与手写的请求体发的是 [80,443]，不能直接报错。
	var h struct {
		Ports Set `json:"proxy_ports"`
	}
	if err := json.Unmarshal([]byte(`{"proxy_ports":[80,443]}`), &h); err != nil {
		t.Fatalf("数字数组应被接受，实际报错: %v", err)
	}
	if h.Ports.String() != "80,443" {
		t.Fatalf("= %q，期望 80,443", h.Ports.String())
	}

	// 坏写法要报错，而不是解出个空集合继续往下走。
	var bad struct {
		Ports Set `json:"proxy_ports"`
	}
	if err := json.Unmarshal([]byte(`{"proxy_ports":"20000~30000"}`), &bad); err == nil {
		t.Fatal("非法端口写法应该报错")
	}
}
