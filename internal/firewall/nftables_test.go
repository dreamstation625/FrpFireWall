package firewall

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/dreamstation625/FrpFireWall/internal/portrange"
)

// 这一组用例锁死的是"表达式必须与链的家族匹配"。
//
// 触发过真实故障：系统里只有 `table ip filter` + `chain INPUT` 时，驱动照样把
// `ip6 saddr` 的规则写进这条链，nft 以
//
//	Error: conflicting protocols specified: ip vs. ip6
//
// 拒绝**整份脚本**。因为是预检失败就整体放弃，结果是那条链上一个规则都不下发 ——
// IPv4 封禁也跟着一起失效，而界面上只看到一句"规则语法预检失败"。
//
// 这类错误桩命令永远测不出来（桩不解析语法，只会点头），只能在脚本层面锁死。
func TestRenderScriptFamilyPlacement(t *testing.T) {
	inet := nftTarget{Family: "inet", Table: "filter", Chain: "input"}
	ip4 := nftTarget{Family: "ip", Table: "filter", Chain: "INPUT"}
	ip6 := nftTarget{Family: "ip6", Table: "filter", Chain: "INPUT"}

	des := Desired{Blacklist: []string{"203.0.113.7", "2001:db8::1", "198.51.100.0/24"}}

	cases := []struct {
		name    string
		stacks  []nftStack
		want    []string // 必须出现
		notWant []string // 绝不能出现
	}{
		{
			name: "inet 单链承载双栈",
			stacks: []nftStack{
				{target: inet, bits: 32},
				{target: inet, bits: 128},
			},
			want: []string{
				"insert rule inet filter input ip saddr @frpfirewall_black drop",
				"insert rule inet filter input ip6 saddr @frpfirewall_black6 drop",
			},
		},
		{
			name:   "只有 ip 家族（故障现场）",
			stacks: []nftStack{{target: ip4, bits: 32}},
			want: []string{
				"insert rule ip filter INPUT ip saddr @frpfirewall_black drop",
				"add element ip filter frpfirewall_black { 198.51.100.0/24, 203.0.113.7/32 }",
			},
			notWant: []string{"ip6"},
		},
		{
			name:   "只有 ip6 家族",
			stacks: []nftStack{{target: ip6, bits: 128}},
			want: []string{
				"insert rule ip6 filter INPUT ip6 saddr @frpfirewall_black6 drop",
				"add element ip6 filter frpfirewall_black6 { 2001:db8::1/128 }",
			},
			notWant: []string{"ip saddr"},
		},
		{
			name: "ip 与 ip6 各一条链",
			stacks: []nftStack{
				{target: ip4, bits: 32},
				{target: ip6, bits: 128},
			},
			want: []string{
				"insert rule ip filter INPUT ip saddr @frpfirewall_black drop",
				"insert rule ip6 filter INPUT ip6 saddr @frpfirewall_black6 drop",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := renderScript(tc.stacks, des, nil, false)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("缺少 %q\n--- 实际脚本 ---\n%s", w, got)
				}
			}
			for _, nw := range tc.notWant {
				if strings.Contains(got, nw) {
					t.Errorf("不该出现 %q（链的家族与表达式不匹配，nft 会拒绝整份脚本）\n--- 实际脚本 ---\n%s", nw, got)
				}
			}
		})
	}
}

// 每个落点都要各自清点集合，少一个就等于那个协议栈的封禁没生效。
func TestRenderScriptCoversEveryStack(t *testing.T) {
	inet := nftTarget{Family: "inet", Table: "filter", Chain: "input"}
	stacks := []nftStack{{target: inet, bits: 32}, {target: inet, bits: 128}}

	got := renderScript(stacks, Desired{Blacklist: []string{"203.0.113.7", "2001:db8::1"}}, nil, false)

	for _, want := range []string{
		"flush set inet filter frpfirewall_black",
		"flush set inet filter frpfirewall_black6",
		"add element inet filter frpfirewall_black { 203.0.113.7/32 }",
		"add element inet filter frpfirewall_black6 { 2001:db8::1/128 }",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("缺少 %q\n%s", want, got)
		}
	}
}

// inet 家族下两个协议栈共用一条链，handle 只能删一次。
// 在同一个 nft 事务里删两遍同一个 handle，第二条会因找不到而失败，
// 整份脚本随之回滚 —— 连"删掉旧规则"都做不到。
func TestRenderScriptDeletesHandlesOncePerSharedChain(t *testing.T) {
	inet := nftTarget{Family: "inet", Table: "filter", Chain: "input"}
	stacks := []nftStack{{target: inet, bits: 32}, {target: inet, bits: 128}}
	handles := map[nftTarget][]int{inet: {11, 12}}

	got := renderScript(stacks, Desired{}, handles, false)

	for _, h := range []string{"handle 11", "handle 12"} {
		if n := strings.Count(got, h); n != 1 {
			t.Errorf("%s 出现 %d 次，期望 1 次\n%s", h, n, got)
		}
	}
}

// 各链的 handle 互不干扰：删 ip 链的规则不该去动 ip6 链。
func TestRenderScriptDeletesHandlesPerChain(t *testing.T) {
	ip4 := nftTarget{Family: "ip", Table: "filter", Chain: "INPUT"}
	ip6 := nftTarget{Family: "ip6", Table: "filter", Chain: "INPUT"}
	stacks := []nftStack{{target: ip4, bits: 32}, {target: ip6, bits: 128}}
	handles := map[nftTarget][]int{ip4: {21}, ip6: {31}}

	got := renderScript(stacks, Desired{}, handles, false)

	if !strings.Contains(got, "delete rule ip filter INPUT handle 21") {
		t.Errorf("没有删除 ip 链上的旧规则\n%s", got)
	}
	if !strings.Contains(got, "delete rule ip6 filter INPUT handle 31") {
		t.Errorf("没有删除 ip6 链上的旧规则\n%s", got)
	}
	if strings.Contains(got, "delete rule ip filter INPUT handle 31") {
		t.Errorf("把 handle 张冠李戴到别的链上了\n%s", got)
	}
}

// 限速表达式里的 saddr 是 IPv4 的（动态集合元素类型为 ipv4_addr），
// 落到 IPv6 链上会被 nft 拒绝，所以只有 v4 链才生成。
func TestRenderScriptRateLimitOnlyOnIPv4Stack(t *testing.T) {
	des := Desired{
		ProtectPorts: portrange.Ports(7000),
		RateLimit:    &RateLimitSpec{Enabled: true, PerSec: 20},
	}

	ip6Only := []nftStack{{target: nftTarget{Family: "ip6", Table: "filter", Chain: "INPUT"}, bits: 128}}
	if got := renderScript(ip6Only, des, nil, true); strings.Contains(got, setRate) {
		t.Errorf("IPv6 落点上不该生成限速规则\n%s", got)
	}

	ip4Only := []nftStack{{target: nftTarget{Family: "ip", Table: "filter", Chain: "INPUT"}, bits: 32}}
	if got := renderScript(ip4Only, des, nil, true); !strings.Contains(got, setRate) {
		t.Errorf("IPv4 落点上应当生成限速规则\n%s", got)
	}
}

// 只有一条 ip 链、却要封一个 IPv6 地址时必须报错。
// 静默成功会让用户以为封上了，实际上那条规则根本没下发。
func TestStackForTargetRejectsMissingFamily(t *testing.T) {
	d := &nftablesDriver{
		report: &Report{},
		stacks: []nftStack{{target: nftTarget{Family: "ip", Table: "filter", Chain: "INPUT"}, bits: 32}},
	}

	v6 := netip.MustParsePrefix("2001:db8::1/128")
	if _, err := d.stackForTarget(v6); err == nil {
		t.Error("只有 IPv4 落点时封禁 IPv6 地址应当报错，而不是静默成功")
	}

	v4 := netip.MustParsePrefix("203.0.113.7/32")
	if _, err := d.stackForTarget(v4); err != nil {
		t.Errorf("IPv4 地址不该报错: %v", err)
	}
}

// 预览必须与实际下发的语句一致，否则预览就成了误导。
func TestPreviewContainsSameStatementsAsSync(t *testing.T) {
	ip4 := nftTarget{Family: "ip", Table: "filter", Chain: "INPUT"}
	d := &nftablesDriver{
		report: &Report{},
		stacks: []nftStack{{target: ip4, bits: 32}},
		ready:  true,
	}
	des := Desired{Blacklist: []string{"203.0.113.7", "2001:db8::1"}}

	got, err := d.Preview(des)
	if err != nil {
		t.Fatal(err)
	}
	want := renderScript(d.stacks, des, nil, false)
	if !strings.Contains(got, want) {
		t.Errorf("预览没有包含实际会下发的语句\n--- 预览 ---\n%s\n--- 实际 ---\n%s", got, want)
	}
	// 顺带确认预览里也没有把 v6 规则放进 ip 链
	if strings.Contains(got, "ip6 saddr") {
		t.Errorf("预览里出现了不会被下发的 v6 规则\n%s", got)
	}
}

// 还没探测过系统时，预览按"自建 inet 单链双栈"假设，与 createDefaultChain 一致。
func TestPreviewFallsBackToInetDoubleStack(t *testing.T) {
	d := &nftablesDriver{report: &Report{}}

	got, err := d.Preview(Desired{Blacklist: []string{"203.0.113.7", "2001:db8::1"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"insert rule inet filter input ip saddr @frpfirewall_black drop",
		"insert rule inet filter input ip6 saddr @frpfirewall_black6 drop",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("缺少 %q\n%s", want, got)
		}
	}
}

// 只找到一个协议栈的 INPUT 链要给出明确告警：缺的那一半封禁完全不生效，
// 机器若有那半边连通性就能绕过封禁，而这从界面上看不出来。
func TestHalfStackWarning(t *testing.T) {
	if got := halfStackWarning("IPv6"); !strings.Contains(got, "只有 IPv4") ||
		!strings.Contains(got, "IPv6 封禁无法下发") {
		t.Errorf("IPv6 缺失的告警没说清楚: %s", got)
	}
	if got := halfStackWarning("IPv4"); !strings.Contains(got, "只有 IPv6") ||
		!strings.Contains(got, "IPv4 封禁无法下发") {
		t.Errorf("IPv4 缺失的告警没说清楚: %s", got)
	}
}

// 这一组锁死「仅 frp 端口」这条范围的产物。
//
// 它的失效方式很安静：规则少一条、或者端口漏一个，内核不会报任何错，界面上照样
// 显示"已封禁"，只有真去连那个端口才发现没挡住。桩命令同样测不出来（桩不解析
// 语法，只会点头），所以只能断言脚本文本。
func TestRenderScriptFrpScope(t *testing.T) {
	inet := nftTarget{Family: "inet", Table: "filter", Chain: "input"}
	ip4 := nftTarget{Family: "ip", Table: "filter", Chain: "INPUT"}

	des := Desired{
		Blacklist:    []string{"203.0.113.7"},
		BlacklistFrp: []string{"198.51.100.9", "2001:db8::5"},
		ProtectPorts: portrange.Ports(7100, 7000, 7000), // 故意乱序并重复
	}

	t.Run("inet 双栈：每个协议栈各有 tcp 与 udp", func(t *testing.T) {
		stacks := []nftStack{{target: inet, bits: 32}, {target: inet, bits: 128}}
		got := renderScript(stacks, des, nil, false)

		for _, want := range []string{
			"add element inet filter frpfirewall_black_frp { 198.51.100.9/32 }",
			"add element inet filter frpfirewall_black6_frp { 2001:db8::5/128 }",
			// 端口归一化后升序；TCP 与 UDP 都要有，只封 TCP 会留下 UDP 绕过路径
			"tcp dport { 7000, 7100 } ip saddr @frpfirewall_black_frp drop",
			"udp dport { 7000, 7100 } ip saddr @frpfirewall_black_frp drop",
			"tcp dport { 7000, 7100 } ip6 saddr @frpfirewall_black6_frp drop",
			// 全端口那部分不受影响
			"insert rule inet filter input ip saddr @frpfirewall_black drop",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("缺少 %q\n--- 实际脚本 ---\n%s", want, got)
			}
		}
	})

	// 区间写法是这一版的核心：一万个端口必须仍然是一个集合元素，
	// 而不是一万个元素。哪天有人把它"顺手展开"，这条断言会立刻炸。
	t.Run("区间写进集合字面量，不展开成逐个端口", func(t *testing.T) {
		stacks := []nftStack{{target: inet, bits: 32}}
		got := renderScript(stacks, Desired{
			BlacklistFrp: []string{"198.51.100.9"},
			ProtectPorts: portrange.Span(20000, 30000).Merge(portrange.Ports(880, 8443)),
		}, nil, false)

		want := "tcp dport { 880, 8443, 20000-30000 } ip saddr @frpfirewall_black_frp drop"
		if !strings.Contains(got, want) {
			t.Errorf("缺少 %q\n--- 实际脚本 ---\n%s", want, got)
		}
		// nft 在集合字面量里认 lo-hi，不认 iptables 那套 lo:hi。
		if strings.Contains(got, "20000:30000") {
			t.Errorf("nft 集合里出现了 iptables 风格的区间写法，会被预检拒掉\n%s", got)
		}
		// 一万个端口，脚本文本里不该出现四个以上数字的端口元素。
		if strings.Contains(got, "20001") || strings.Contains(got, "29999") {
			t.Errorf("区间被展开成了逐个端口\n%s", got)
		}
	})

	t.Run("集合始终 flush，避免改范围后残留", func(t *testing.T) {
		stacks := []nftStack{{target: inet, bits: 32}}
		got := renderScript(stacks, Desired{}, nil, false)
		if !strings.Contains(got, "flush set inet filter frpfirewall_black_frp") {
			t.Errorf("frp 集合没有被 flush：地址从该范围移走后元素会残留，那个端口会一直被挡着\n%s", got)
		}
	})

	t.Run("没配 frp 端口时不生成引用集合的规则", func(t *testing.T) {
		stacks := []nftStack{{target: inet, bits: 32}}
		got := renderScript(stacks, Desired{BlacklistFrp: []string{"198.51.100.9"}}, nil, false)

		if strings.Contains(got, "dport") {
			t.Errorf("没有端口却生成了带 dport 的规则\n%s", got)
		}
		if strings.Contains(got, "@"+setBlackFrp+" drop") {
			t.Errorf("没有端口却生成了引用 frp 集合的规则，等于静默不生效\n%s", got)
		}
	})

	t.Run("某协议栈没有该类地址就不为它插规则", func(t *testing.T) {
		stacks := []nftStack{{target: inet, bits: 32}, {target: inet, bits: 128}}
		onlyV4 := Desired{BlacklistFrp: []string{"198.51.100.9"}, ProtectPorts: portrange.Ports(7000)}
		got := renderScript(stacks, onlyV4, nil, false)

		if !strings.Contains(got, "ip saddr @"+setBlackFrp+" drop") {
			t.Errorf("IPv4 落点上缺少 frp 规则\n%s", got)
		}
		if strings.Contains(got, "ip6 saddr @"+setBlack6Frp+" drop") {
			t.Errorf("IPv6 下没有任何该类地址，不该为它生成规则\n%s", got)
		}
	})

	t.Run("ip 家族下不出现 ip6 表达式", func(t *testing.T) {
		stacks := []nftStack{{target: ip4, bits: 32}}
		got := renderScript(stacks, des, nil, false)
		if strings.Contains(got, "ip6 saddr") {
			t.Errorf("ip 家族的链里出现了 ip6 表达式，nft 会拒掉整份脚本\n%s", got)
		}
	})
}

// 链上的实际顺序：全端口封禁在前，仅 frp 端口的在后。
//
// insert 一律插到链首，所以脚本文本里的先后与链上的顺序**相反** —— 脚本末尾那条
// 插入后位置最靠前。要验证真实顺序就得把 insert 序列倒过来读；直接拿脚本顺序
// 断言会得出完全相反的结论。
func TestRenderScriptFrpRulesComeAfterAllPortRules(t *testing.T) {
	inet := nftTarget{Family: "inet", Table: "filter", Chain: "input"}
	stacks := []nftStack{{target: inet, bits: 32}}

	got := renderScript(stacks, Desired{
		Blacklist:    []string{"203.0.113.7"},
		BlacklistFrp: []string{"198.51.100.9"},
		ProtectPorts: portrange.Ports(7000),
	}, nil, false)

	all, frp := -1, -1
	for i, line := range insertOrder(got) {
		if strings.Contains(line, "@"+setBlack+" drop") {
			all = i
		}
		if strings.Contains(line, "@"+setBlackFrp+" drop") {
			frp = i
		}
	}
	if all < 0 || frp < 0 {
		t.Fatalf("两条规则都应当存在\n%s", got)
	}
	if all > frp {
		t.Errorf("链上顺序应为「全端口 → 仅 frp 端口」，实际相反\n%s", got)
	}
}

// insertOrder 抽出脚本里的 insert 语句，并按"插到链首"的语义还原成链上的顺序。
func insertOrder(script string) []string {
	var out []string
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(line, "insert rule ") {
			out = append(out, strings.TrimSpace(line))
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}
