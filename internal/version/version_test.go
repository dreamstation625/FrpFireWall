package version

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in      string
		want    Number
		wantErr bool
	}{
		{in: "0.0.1", want: Number{0, 0, 1, 0}},
		{in: "1.2.3", want: Number{1, 2, 3, 0}},
		{in: "0.0.1-pre.01", want: Number{0, 0, 1, 1}},
		{in: "0.0.1-pre.1", want: Number{0, 0, 1, 1}},   // 容错：不补零
		{in: "0.0.1-pre.99", want: Number{0, 0, 1, 99}},
		{in: "0.0.1-pre.100", want: Number{0, 0, 1, 100}}, // 超过两位
		{in: "v0.0.1", want: Number{0, 0, 1, 0}},          // 容错：git tag 的 v 前缀
		{in: "v0.0.1-pre.02", want: Number{0, 0, 1, 2}},
		{in: "0.0.1+abcdef", want: Number{0, 0, 1, 0}}, // 容错：构建元数据
		{in: " 0.0.1 ", want: Number{0, 0, 1, 0}},      // 容错：首尾空白

		{in: "", wantErr: true},
		{in: "0.1", wantErr: true},
		{in: "0.0.1.2", wantErr: true},
		{in: "a.b.c", wantErr: true},
		{in: "0.0.-1", wantErr: true},
		{in: "0.0.1-dev", wantErr: true},   // 只认 -pre.NN
		{in: "0.0.1-rc.1", wantErr: true},  // 同上
		{in: "0.0.1-pre.00", wantErr: true}, // 序号从 01 起
		{in: "0.0.1-pre.0", wantErr: true},
		{in: "0.0.1-pre.", wantErr: true},
	}

	for _, c := range cases {
		got, err := Parse(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("Parse(%q) 期望报错，实际得到 %v", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("Parse(%q) 意外报错: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("Parse(%q) = %+v，期望 %+v", c.in, got, c.want)
		}
	}
}

func TestNumberString(t *testing.T) {
	cases := []struct {
		in   Number
		want string
	}{
		{Number{0, 0, 1, 0}, "0.0.1"},
		{Number{0, 0, 1, 1}, "0.0.1-pre.01"},
		{Number{0, 0, 1, 9}, "0.0.1-pre.09"},
		{Number{0, 0, 1, 99}, "0.0.1-pre.99"},
		{Number{0, 0, 1, 100}, "0.0.1-pre.100"},
		{Number{1, 20, 3, 4}, "1.20.3-pre.04"},
	}
	for _, c := range cases {
		if got := c.in.String(); got != c.want {
			t.Errorf("%+v.String() = %q，期望 %q", c.in, got, c.want)
		}
	}
}

// 往返一致性：解析后再格式化，应当得到规范形态。
func TestParseStringRoundTrip(t *testing.T) {
	for _, s := range []string{"0.0.1", "0.0.1-pre.01", "0.0.1-pre.99", "1.2.3"} {
		n, err := Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q) 报错: %v", s, err)
		}
		if got := n.String(); got != s {
			t.Errorf("往返不一致: %q → %+v → %q", s, n, got)
		}
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.0.1", "0.0.1", 0},
		{"0.0.2", "0.0.1", 1},
		{"0.0.1", "0.0.2", -1},
		{"0.1.0", "0.0.9", 1},
		{"1.0.0", "0.9.9", 1},

		// 同号：正式版大于预发布版
		{"0.0.1", "0.0.1-pre.01", 1},
		{"0.0.1-pre.01", "0.0.1", -1},
		{"0.0.1", "0.0.1-pre.99", 1},

		// 预发布序号比较
		{"0.0.1-pre.02", "0.0.1-pre.01", 1},
		{"0.0.1-pre.01", "0.0.1-pre.02", -1},
		{"0.0.1-pre.10", "0.0.1-pre.9", 1}, // 按数值而非字典序

		// 主版本优先于预发布状态
		{"0.0.2-pre.01", "0.0.1", 1},
		{"0.0.1", "0.0.2-pre.01", -1},
	}

	for _, c := range cases {
		a, b := MustParse(c.a), MustParse(c.b)
		if got := Compare(a, b); got != c.want {
			t.Errorf("Compare(%s, %s) = %d，期望 %d", c.a, c.b, got, c.want)
		}
		if got := Compare(b, a); got != -c.want {
			t.Errorf("Compare(%s, %s) = %d，期望 %d（反对称性）", c.b, c.a, got, -c.want)
		}
	}
}

func TestSelectUpdate(t *testing.T) {
	cases := []struct {
		name    string
		cur     string
		cands   []string
		want    string
		wantHit bool
	}{
		{
			// ★ 核心需求：正式版不检查到 pre 的更新
			name:    "正式版忽略预发布",
			cur:     "0.0.1",
			cands:   []string{"0.0.2-pre.01", "0.0.1-pre.05"},
			wantHit: false,
		},
		{
			name:    "正式版拿更高的正式版",
			cur:     "0.0.1",
			cands:   []string{"0.0.2-pre.01", "0.0.2", "0.0.1-pre.05"},
			want:    "0.0.2",
			wantHit: true,
		},
		{
			name:    "正式版不提示同号预发布",
			cur:     "0.0.1-pre.01",
			cands:   []string{"0.0.1-pre.01"},
			wantHit: false,
		},
		{
			name:    "预发布版拿更高序号的预发布",
			cur:     "0.0.1-pre.01",
			cands:   []string{"0.0.1-pre.02"},
			want:    "0.0.1-pre.02",
			wantHit: true,
		},
		{
			// 预发布用户一旦有正式版就应当被推过去
			name:    "预发布版优先拿同号正式版",
			cur:     "0.0.1-pre.02",
			cands:   []string{"0.0.1-pre.03", "0.0.1"},
			want:    "0.0.1",
			wantHit: true,
		},
		{
			name:    "预发布版跨号取更高的预发布",
			cur:     "0.0.1-pre.01",
			cands:   []string{"0.0.2-pre.01"},
			want:    "0.0.2-pre.01",
			wantHit: true,
		},
		{
			name:    "已是最新",
			cur:     "0.0.3",
			cands:   []string{"0.0.1", "0.0.2", "0.0.3"},
			wantHit: false,
		},
		{
			name:    "候选为空",
			cur:     "0.0.1",
			cands:   nil,
			wantHit: false,
		},
		{
			// 低于当前版本的正式版不应被采纳
			name:    "降级不提示",
			cur:     "0.1.0",
			cands:   []string{"0.0.9", "0.0.8"},
			wantHit: false,
		},
		{
			name:    "候选乱序也能取到最高",
			cur:     "0.0.1",
			cands:   []string{"0.0.2", "0.0.5", "0.0.3"},
			want:    "0.0.5",
			wantHit: true,
		},
		{
			name:    "零值候选被跳过",
			cur:     "0.0.1",
			cands:   []string{"", "0.0.2"},
			want:    "0.0.2",
			wantHit: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cands := make([]Number, 0, len(c.cands))
			for _, s := range c.cands {
				cands = append(cands, MustParse(s))
			}
			got, idx, hit := SelectUpdate(MustParse(c.cur), cands)
			if hit != c.wantHit {
				t.Fatalf("当前 %s，候选 %v：命中 = %v，期望 %v",
					c.cur, c.cands, hit, c.wantHit)
			}
			if !hit {
				return
			}
			if got.String() != c.want {
				t.Errorf("当前 %s，候选 %v：选中 %s，期望 %s",
					c.cur, c.cands, got.String(), c.want)
			}
			if idx < 0 || idx >= len(cands) || cands[idx] != got {
				t.Errorf("返回下标 %d 与选中版本 %s 不一致", idx, got.String())
			}
		})
	}
}

// Current 必须能解析出构建注入的默认版本号，否则意味着 VERSION 与默认值脱节。
func TestCurrentParses(t *testing.T) {
	n, err := Current()
	if err != nil {
		t.Fatalf("Current() 解析 %q 失败: %v", Version, err)
	}
	if n.IsZero() {
		t.Fatalf("Current() 得到零值版本")
	}
}
