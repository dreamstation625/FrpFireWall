package firewall

import (
	"strings"
	"testing"

	"github.com/dreamstation625/FrpFireWall/internal/portrange"
)

// 「仅 frp 端口」在 iptables 侧落成一个独立子链，规则必须带端口条件。
//
// 这类错误不会报错、不会告警，只会静默少挡一部分流量，所以只能断言生成的规则。
func TestFrpBlockRules(t *testing.T) {
	t.Run("tcp 与 udp 各一条，端口去重后升序", func(t *testing.T) {
		got := frpBlockRules([]string{"198.51.100.9"}, portrange.Ports(7100, 7000, 7000))
		want := []string{
			"-A " + managedBlackFrpChain + " -s 198.51.100.9 -p tcp -m multiport --dports 7000,7100 -j DROP",
			"-A " + managedBlackFrpChain + " -s 198.51.100.9 -p udp -m multiport --dports 7000,7100 -j DROP",
		}
		if len(got) != len(want) {
			t.Fatalf("规则数 %d，期望 %d：%v", len(got), len(want), got)
		}
		for i, w := range want {
			if line := strings.Join(got[i], " "); line != w {
				t.Errorf("第 %d 条不符\n实际: %s\n期望: %s", i+1, line, w)
			}
		}
	})

	// 区间写法是这一版的核心：一个宽区间必须仍然只生成一条规则。
	// 如果哪天有人把它"顺手展开成一个个端口"，这条断言会立刻炸。
	t.Run("区间写成 lo:hi，只占一条规则", func(t *testing.T) {
		got := frpBlockRules([]string{"198.51.100.9"}, portrange.Span(20000, 30000))
		if len(got) != 2 {
			t.Fatalf("一个区间应生成 tcp/udp 各一条，实际 %d 条：%v", len(got), got)
		}
		for i, proto := range []string{"tcp", "udp"} {
			want := "-A " + managedBlackFrpChain + " -s 198.51.100.9 -p " + proto +
				" -m multiport --dports 20000:30000 -j DROP"
			if line := strings.Join(got[i], " "); line != want {
				t.Errorf("实际: %s\n期望: %s", line, want)
			}
		}
	})

	t.Run("连续端口并成一段，不占满 multiport 名额", func(t *testing.T) {
		ports := make([]int, 0, 20)
		for p := 7000; p < 7020; p++ {
			ports = append(ports, p)
		}
		got := frpBlockRules([]string{"198.51.100.9"}, portrange.Ports(ports...))

		// 20 个连续端口归一化成一段 → tcp/udp 各一条，而不是 4 条。
		if len(got) != 2 {
			t.Fatalf("连续端口应并成一段，实际生成 %d 条：%v", len(got), got)
		}
		if line := strings.Join(got[0], " "); !strings.Contains(line, "--dports 7000:7019") {
			t.Errorf("连续端口应写成区间 7000:7019：%s", line)
		}
	})

	t.Run("不连续的端口多于 multiport 上限时拆成多条", func(t *testing.T) {
		ports := make([]int, 0, 20)
		for p := 7000; p < 7040; p += 2 { // 间隔取，避免被合并
			ports = append(ports, p)
		}
		got := frpBlockRules([]string{"198.51.100.9"}, portrange.Ports(ports...))

		// 20 段 → 2 块 × 2 种协议 = 4 条
		if len(got) != 4 {
			t.Fatalf("规则数 %d，期望 4：%v", len(got), got)
		}
		for _, args := range got {
			if n := len(strings.Split(dportsOf(t, args), ",")); n > multiportMax {
				t.Errorf("一条规则带了 %d 个端口段，超过 multiport 上限 %d：%v", n, multiportMax, args)
			}
		}
	})

	t.Run("切块按区间个数算，宽区间不会撑爆一条规则", func(t *testing.T) {
		// 20 段互不相邻的宽区间：总端口数上万，但每块只放 15 段。
		set := portrange.Set{}
		for i := 0; i < 20; i++ {
			base := 1000 + i*1000
			set = set.Merge(portrange.Span(base, base+499))
		}
		got := frpBlockRules([]string{"198.51.100.9"}, set)

		if len(got) != 4 { // 2 块 × 2 协议
			t.Fatalf("规则数 %d，期望 4：%v", len(got), got)
		}
		for _, args := range got {
			if n := len(strings.Split(dportsOf(t, args), ",")); n > multiportMax {
				t.Errorf("一条规则带了 %d 个区间，超过上限 %d：%v", n, multiportMax, args)
			}
		}
	})

	t.Run("没有端口时不生成任何规则", func(t *testing.T) {
		if got := frpBlockRules([]string{"198.51.100.9"}, nil); len(got) != 0 {
			t.Errorf("没有端口却生成了 %d 条规则：%v", len(got), got)
		}
		if got := frpBlockRules(nil, portrange.Ports(7000)); len(got) != 0 {
			t.Errorf("没有地址却生成了 %d 条规则：%v", len(got), got)
		}
	})
}

// dportsOf 取出规则里的 --dports 参数值。
func dportsOf(t *testing.T, args []string) string {
	t.Helper()
	for i, a := range args {
		if a == "--dports" && i+1 < len(args) {
			return args[i+1]
		}
	}
	t.Fatalf("规则里没有 --dports：%v", args)
	return ""
}

// 主链的顺序即优先级：全端口封禁排在仅 frp 端口之前，RETURN 必须留在最后。
func TestBuildIPTablesRulesOrder(t *testing.T) {
	rules := buildIPTablesRules(Desired{
		Blacklist:    []string{"203.0.113.7"},
		BlacklistFrp: []string{"198.51.100.9"},
		ProtectPorts: portrange.Ports(7000),
	}, 32)

	seq := make([]string, 0, len(rules.Guard))
	for _, r := range rules.Guard {
		seq = append(seq, strings.Join(r.Args, " "))
	}
	if len(seq) == 0 {
		t.Fatal("主链规则为空")
	}

	joined := strings.Join(seq, "\n")

	// 必须按 "-j <目标>" 精确取值，不能用 strings.Index 找子串：
	// FRPFIREWALL_BLACK 是 FRPFIREWALL_BLACK_FRP 的前缀，子串匹配会把两条
	// 跳转认成同一条，顺序断言就永远成立、也就永远发现不了顺序写反。
	allIdx, frpIdx := -1, -1
	for i, line := range seq {
		fields := strings.Fields(line)
		for j, f := range fields {
			if f != "-j" || j+1 >= len(fields) {
				continue
			}
			switch fields[j+1] {
			case managedBlackChain:
				allIdx = i
			case managedBlackFrpChain:
				frpIdx = i
			}
		}
	}
	if allIdx < 0 || frpIdx < 0 {
		t.Fatalf("两条跳转都应当存在（all=%d frp=%d）\n%s", allIdx, frpIdx, joined)
	}
	if allIdx > frpIdx {
		t.Errorf("全端口跳转应排在 frp 跳转之前\n%s", joined)
	}

	// RETURN 决定"不匹配的流量回到 INPUT"，排在它后面的规则永远不会被看到。
	if last := seq[len(seq)-1]; !strings.Contains(last, "-j RETURN") {
		t.Errorf("最后一条应当是 RETURN，实际是 %q\n%s", last, joined)
	}
}

// 限速是增强能力，失败可以降级；其余规则失败必须让整次同步失败。
// 两者的区分靠 iptRule.Soft，弄反了后果是：限速失败导致整次同步中断，
// 或者黑名单写失败却被当成可忽略。
func TestBuildIPTablesRulesRateLimitIsSoft(t *testing.T) {
	withRate := buildIPTablesRules(Desired{
		ProtectPorts: portrange.Ports(7000),
		RateLimits:   []RateLimitRule{{Key: "global", PerSec: 20, Ports: portrange.Ports(7000)}},
	}, 32)

	soft, hard := 0, 0
	for _, r := range withRate.Guard {
		if r.Soft {
			soft++
		} else {
			hard++
		}
	}
	if soft != 1 {
		t.Errorf("应当恰好有一条可降级的限速规则，实际 %d 条", soft)
	}
	if hard != 3 { // 跳转全端口 + 跳转 frp + RETURN
		t.Errorf("固定规则应为 3 条，实际 %d 条", hard)
	}

	noRate := buildIPTablesRules(Desired{}, 32)
	for _, r := range noRate.Guard {
		if r.Soft {
			t.Error("未启用限速时不该出现可降级的规则")
		}
	}
}

// frp 端口取自 ProtectPorts，进规则前必须归一化：非法端口会让整条 iptables
// 命令被拒绝，重复端口则是纯粹的噪音。
func TestBuildIPTablesRulesNormalizesPorts(t *testing.T) {
	// 走构造函数：越界值被丢掉、重复被去掉、升序。
	rules := buildIPTablesRules(Desired{ProtectPorts: portrange.Ports(0, -1, 7000, 7000, 70001, 7100)}, 32)
	if got := rules.FrpPorts.String(); got != "7000,7100" {
		t.Errorf("端口归一化结果 %q，期望 7000,7100", got)
	}

	// 直接手写 Set 字面量的调用方不经过构造函数，驱动入口要兜住。
	raw := buildIPTablesRules(Desired{ProtectPorts: portrange.Set{
		{Lo: 7100, Hi: 7100}, {Lo: 7000, Hi: 7000}, {Lo: 7000, Hi: 7000},
	}}, 32)
	if got := raw.FrpPorts.String(); got != "7000,7100" {
		t.Errorf("驱动入口未归一化手写字面量，得到 %q", got)
	}
}

// 限速规则要按区间生成，并且拆块后共用同一张计数表 ——
// 各块各算一份配额会让实际放行量随块数翻倍。
func TestRateLimitArgsUseRanges(t *testing.T) {
	base := RateLimitRule{Key: "r1", PerSec: 20}

	one := rateLimitArgs(withPorts(base, portrange.Ports(7000)))
	if len(one) != 1 {
		t.Fatalf("单端口应生成 1 条，实际 %d 条", len(one))
	}
	if line := strings.Join(one[0], " "); !strings.Contains(line, "--dports 7000 ") {
		t.Errorf("限速规则应带端口条件：%s", line)
	}

	if got := rateLimitArgs(base); len(got) != 1 {
		t.Errorf("未配端口应生成 1 条不限端口的规则，实际 %d 条", len(got))
	} else if line := strings.Join(got[0], " "); strings.Contains(line, "--dports") {
		t.Errorf("未配端口时不该出现 dport 条件：%s", line)
	}

	// 20 段不连续端口 → 拆 2 块，但 --hashlimit-name 必须一致。
	ports := make([]int, 0, 20)
	for p := 7000; p < 7040; p += 2 {
		ports = append(ports, p)
	}
	chunked := rateLimitArgs(withPorts(base, portrange.Ports(ports...)))
	if len(chunked) != 2 {
		t.Fatalf("20 段端口应拆成 2 条，实际 %d 条", len(chunked))
	}
	names := map[string]bool{}
	for _, args := range chunked {
		line := strings.Join(args, " ")
		name := hashlimitName(base.Key)
		if !strings.Contains(line, "--hashlimit-name "+name) {
			t.Errorf("拆块后必须共用同一个 hashlimit 计数表：%v", args)
		}
		names[name] = true
	}
	if len(names) != 1 {
		t.Errorf("拆块后计数表名应当只有一个，实际 %v", names)
	}
}

// 来源条件按「来源 × 端口块」展开成笛卡尔积，不能靠 iptables 自己对重复的 -s
// 做隐式展开 —— 展开出来几条得能提前数清楚。
func TestRateLimitArgsExpandsSources(t *testing.T) {
	r := RateLimitRule{
		Key:     "r2",
		PerSec:  5,
		Sources: []string{"1.2.3.0/24", "10.0.0.1/32"},
		Ports:   portrange.Ports(7000),
	}
	got := rateLimitArgs(r)
	if len(got) != 2 {
		t.Fatalf("2 个来源 × 1 个端口块 = 2 条，实际 %d 条", len(got))
	}
	for i, src := range r.Sources {
		line := strings.Join(got[i], " ")
		if !strings.Contains(line, "-s "+src) {
			t.Errorf("第 %d 条应带来源 %s：%s", i, src, line)
		}
	}

	// 同一来源多个端口块 → 条数相乘，计数表仍是同一个。
	r2 := r
	r2.Ports = portrange.Ports(7000, 7002, 7004, 7006, 7008, 7010, 7012, 7014, 7016,
		7018, 7020, 7022, 7024, 7026, 7028, 7030)
	multi := rateLimitArgs(r2)
	if len(multi) != 4 { // 2 个来源 × 2 个端口块
		t.Fatalf("2 个来源 × 2 个端口块 = 4 条，实际 %d 条", len(multi))
	}
}

// 只有 IPv6 来源的规则落在 IPv4 这一侧时必须整条跳过。
// 退化成"不限来源"等于把一条限定规则放大成全网限速，方向正好反了。
func TestFilterRateRulesDropsWrongFamily(t *testing.T) {
	list := []RateLimitRule{
		{Key: "any", PerSec: 1},
		{Key: "v4", PerSec: 1, Sources: []string{"1.2.3.0/24"}},
		{Key: "v6", PerSec: 1, Sources: []string{"2001:db8::/32"}},
		{Key: "both", PerSec: 1, Sources: []string{"1.2.3.0/24", "2001:db8::/32"}},
	}

	v4 := filterRateRules(list, 32)
	keys := make([]string, 0, len(v4))
	for _, r := range v4 {
		keys = append(keys, r.Key)
	}
	want := []string{"any", "v4", "both"}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Fatalf("IPv4 侧应保留 %v，实际 %v", want, keys)
	}
	for _, r := range v4 {
		if r.Key == "both" && len(r.Sources) != 1 {
			t.Errorf("both 在 IPv4 侧应只剩 IPv4 来源，实际 %v", r.Sources)
		}
	}

	v6 := filterRateRules(list, 128)
	keys = keys[:0]
	for _, r := range v6 {
		keys = append(keys, r.Key)
	}
	want = []string{"any", "v6", "both"}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Fatalf("IPv6 侧应保留 %v，实际 %v", want, keys)
	}
}

// --hashlimit-name 有 15 字符上限，超了 iptables 会拒绝整条命令。
// 而规则名是中文，装不进去，所以只能从 Key 派生 —— 派生结果必须合法、稳定、
// 且不同的 Key 不能撞成同一个名字。
func TestHashlimitNameIsShortAndDistinct(t *testing.T) {
	keys := []string{
		"global", "r1", "r2", "r36", "rzzz",
		"香港限速", "一条名字特别特别长的规则用来把标题撑爆掉再看看会不会出问题",
		"", "!!!",
	}
	seen := map[string]string{}
	for _, k := range keys {
		name := hashlimitName(k)
		if len(name) > hashlimitMaxName {
			t.Errorf("Key %q 派生出的表名 %q 有 %d 字符，超过上限 %d",
				k, name, len(name), hashlimitMaxName)
		}
		for _, r := range name {
			ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '_'
			if !ok {
				t.Errorf("Key %q 派生出的表名 %q 含非法字符 %q", k, name, r)
			}
		}
		if prev, dup := seen[name]; dup {
			t.Errorf("Key %q 与 %q 撞成同一个表名 %q", k, prev, name)
		}
		seen[name] = k
	}
}

// nft 侧一条规则一个动态集合：集合名同样要合法、稳定、不撞。
func TestRateSetNameDistinct(t *testing.T) {
	a := rateSetName("r1")
	b := rateSetName("一条中文规则名")
	c := rateSetName("r2")
	if a == b || b == c || a == c {
		t.Fatalf("集合名撞了：%q %q %q", a, b, c)
	}
	if a != rateSetName("r1") {
		t.Error("同一个 Key 应当派生出同一个集合名")
	}
	if !strings.HasPrefix(a, setRatePrefix) {
		t.Errorf("集合名应带前缀 %q，实际 %q", setRatePrefix, a)
	}
}

// 老版本只建了一个全局集合 frpfirewall_rate，前缀判定要能把它也认出来，
// 否则升级之后它会一直留在内核里。
func TestIsRateSetName(t *testing.T) {
	yes := []string{"frpfirewall_rate", "frpfirewall_rate_global", "frpfirewall_rate_r1"}
	no := []string{"frpfirewall_black", "frpfirewall_black_frp", "rate", ""}
	for _, n := range yes {
		if !isRateSetName(n) {
			t.Errorf("%q 应当被认成限速集合", n)
		}
	}
	for _, n := range no {
		if isRateSetName(n) {
			t.Errorf("%q 不该被认成限速集合", n)
		}
	}
}

// withPorts 给规则补上端口，省得每个用例都写一遍字段名。
func withPorts(r RateLimitRule, p portrange.Set) RateLimitRule {
	r.Ports = p
	return r
}

// 预览必须与实际下发一致，否则预览就成了误导。
func TestIPTablesPreviewMatchesBuild(t *testing.T) {
	d := &iptablesDriver{
		report: &Report{},
		fams:   []ipFamily{{name: "ipv4", bin: "iptables", bits: 32}},
	}
	des := Desired{
		Blacklist:    []string{"203.0.113.7"},
		BlacklistFrp: []string{"198.51.100.9"},
		ProtectPorts: portrange.Ports(7000, 7100),
	}

	got, err := d.Preview(des)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		// 带换行收尾：否则 "-j FRPFIREWALL_BLACK" 会匹配上 "-j FRPFIREWALL_BLACK_FRP"
		// 那一行，跳转没写出来也算通过。
		"-A " + ManagedChain + " -j " + managedBlackChain + "\n",
		"-A " + ManagedChain + " -j " + managedBlackFrpChain + "\n",
		"-A " + managedBlackChain + " -s 203.0.113.7/32 -j DROP",
		"-A " + managedBlackFrpChain + " -s 198.51.100.9/32 -p tcp -m multiport --dports 7000,7100 -j DROP",
		"-A " + managedBlackFrpChain + " -s 198.51.100.9/32 -p udp -m multiport --dports 7000,7100 -j DROP",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("预览缺少 %q\n--- 预览 ---\n%s", want, got)
		}
	}
}

// 预览里的区间写法必须与真实下发一致：iptables 认 lo:hi，不认 lo-hi。
func TestIPTablesPreviewRendersRange(t *testing.T) {
	d := &iptablesDriver{
		report: &Report{},
		fams:   []ipFamily{{name: "ipv4", bin: "iptables", bits: 32}},
	}

	got, err := d.Preview(Desired{
		BlacklistFrp: []string{"198.51.100.9"},
		ProtectPorts: portrange.Span(20000, 30000),
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := "--dports 20000:30000 -j DROP"; !strings.Contains(got, want) {
		t.Errorf("预览缺少 %q\n%s", want, got)
	}
	// 区间写法写成 lo-hi 的话 iptables 会当参数解析错误，整条命令被拒。
	if strings.Contains(got, "--dports 20000-30000") {
		t.Errorf("iptables 不认 lo-hi 的区间写法\n%s", got)
	}
}

// 没配 frp 端口时下不出"仅 frp 端口"的规则。预览要把这件事说出来 ——
// 否则用户看到地址列在黑名单里，会以为已经生效了。
func TestIPTablesPreviewWarnsWhenNoPorts(t *testing.T) {
	d := &iptablesDriver{
		report: &Report{},
		fams:   []ipFamily{{name: "ipv4", bin: "iptables", bits: 32}},
	}

	got, err := d.Preview(Desired{BlacklistFrp: []string{"198.51.100.9"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "无法下发") {
		t.Errorf("预览没有说明这些条目下不去\n%s", got)
	}
	if !strings.Contains(got, "198.51.100.9") {
		t.Errorf("预览没有列出受影响的地址\n%s", got)
	}
	if strings.Contains(got, "-A "+managedBlackFrpChain+" -s") {
		t.Errorf("没有端口却生成了带端口的规则\n%s", got)
	}
}

// 两个后端各认一种区间写法，传反了就是整条命令被拒。
func TestPortRendering(t *testing.T) {
	set := portrange.Ports(80).Merge(portrange.Span(20000, 30000))
	if got := iptPorts(set); got != "80,20000:30000" {
		t.Errorf("iptables 写法 %q，期望 80,20000:30000", got)
	}
	if got := nftPorts(set); got != "80, 20000-30000" {
		t.Errorf("nft 写法 %q，期望 80, 20000-30000", got)
	}
	if got := iptPorts(nil); got != "" {
		t.Errorf("空集合应渲染成空串，实际 %q", got)
	}
}

// 端口数量大时也不该产出成百上千条规则 —— 这是本轮改动要解决的问题本身。
func TestWideRangeDoesNotExplodeRuleCount(t *testing.T) {
	wide := portrange.Span(20000, 30000)
	addrs := []string{"198.51.100.1", "198.51.100.2"}

	got := frpBlockRules(addrs, wide)
	if len(got) != 4 { // 2 个地址 × 2 种协议
		t.Fatalf("宽区间生成了 %d 条规则，期望 4：%v", len(got), got)
	}
	// 顺带确认没有退化成逐个端口列举。
	for _, args := range got {
		if d := dportsOf(t, args); strings.Contains(d, ",") {
			t.Errorf("宽区间不该被展开成端口列表：%s", d)
		}
	}

	// 一万个端口的集合，渲染出来的文本仍然是十来个字符。
	if txt := wide.String(); txt != "20000-30000" {
		t.Errorf("宽区间文本 %q", txt)
	}
}
