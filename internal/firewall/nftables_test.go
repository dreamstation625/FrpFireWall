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
				"insert rule inet filter input ip saddr @frpfirewall_black counter drop",
				"insert rule inet filter input ip6 saddr @frpfirewall_black6 counter drop",
			},
		},
		{
			name:   "只有 ip 家族（故障现场）",
			stacks: []nftStack{{target: ip4, bits: 32}},
			want: []string{
				"insert rule ip filter INPUT ip saddr @frpfirewall_black counter drop",
				"add element ip filter frpfirewall_black { 198.51.100.0/24, 203.0.113.7/32 }",
			},
			notWant: []string{"ip6"},
		},
		{
			name:   "只有 ip6 家族",
			stacks: []nftStack{{target: ip6, bits: 128}},
			want: []string{
				"insert rule ip6 filter INPUT ip6 saddr @frpfirewall_black6 counter drop",
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
				"insert rule ip filter INPUT ip saddr @frpfirewall_black counter drop",
				"insert rule ip6 filter INPUT ip6 saddr @frpfirewall_black6 counter drop",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := renderScript(tc.stacks, des, nil, nil)
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

	got := renderScript(stacks, Desired{Blacklist: []string{"203.0.113.7", "2001:db8::1"}}, nil, nil)

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

	got := renderScript(stacks, Desired{}, handles, nil)

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

	got := renderScript(stacks, Desired{}, handles, nil)

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
	des := Desired{RateLimits: []RateLimitRule{{Key: "global", PerSec: 20}}}
	rates := planRateRules(des.RateLimits)
	if len(rates) != 1 {
		t.Fatalf("应当规划出 1 条限速规则，实际 %d 条", len(rates))
	}
	set := rates[0].set

	ip6Only := []nftStack{{target: nftTarget{Family: "ip6", Table: "filter", Chain: "INPUT"}, bits: 128}}
	if got := renderScript(ip6Only, des, nil, rates); strings.Contains(got, set) {
		t.Errorf("IPv6 落点上不该生成限速规则\n%s", got)
	}

	ip4Only := []nftStack{{target: nftTarget{Family: "ip", Table: "filter", Chain: "INPUT"}, bits: 32}}
	if got := renderScript(ip4Only, des, nil, rates); !strings.Contains(got, set) {
		t.Errorf("IPv4 落点上应当生成限速规则\n%s", got)
	}
}

// 多条限速规则要各自生成一条规则、各自一个动态集合。
//
// 共用一个集合是不行的：nft 的 limit 是挂在集合上的状态对象，
// 一个集合只有一套速率，共用就等于所有规则只能用同一个速率。
func TestRenderScriptRateRulesAreIsolated(t *testing.T) {
	inet := nftTarget{Family: "inet", Table: "filter", Chain: "input"}
	stacks := []nftStack{{target: inet, bits: 32}}

	des := Desired{RateLimits: []RateLimitRule{
		{Key: "r1", Name: "香港限速", Sources: []string{"203.0.113.0/24"}, Ports: portrange.Span(20000, 30000), PerSec: 5},
		{Key: "r2", Name: "某段限速", Sources: []string{"198.51.100.0/24"}, Ports: portrange.Ports(880, 8443), PerSec: 50, Burst: 100},
		{Key: "global", Name: "全局兜底", Ports: portrange.Ports(7000), PerSec: 20},
	}}
	got := renderScript(stacks, des, nil, planRateRules(des.RateLimits))

	for _, want := range []string{
		`ip saddr { 203.0.113.0/24 } tcp dport { 20000-30000 } ct state new add @frpfirewall_rate_r1 { ip saddr limit rate over 5/second burst 10 packets } counter drop`,
		`ip saddr { 198.51.100.0/24 } tcp dport { 880, 8443 } ct state new add @frpfirewall_rate_r2 { ip saddr limit rate over 50/second burst 100 packets } counter drop`,
		`tcp dport { 7000 } ct state new add @frpfirewall_rate_global { ip saddr limit rate over 20/second burst 40 packets } counter drop`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("缺少 %q\n--- 实际脚本 ---\n%s", want, got)
		}
	}
	// 每条规则一个集合，三个不同的集合名。
	for _, name := range []string{"frpfirewall_rate_r1", "frpfirewall_rate_r2", "frpfirewall_rate_global"} {
		if !strings.Contains(got, "@"+name) {
			t.Errorf("缺少集合 %s", name)
		}
	}
}

// 细分规则必须排在全局兜底之前 —— 内核是"先匹配先生效"，
// 全局排前面的话细分规则永远轮不到，等于配了没用。
//
// insert 一律插到链首，所以脚本里的先后与链上顺序**相反**：
// 要最后生效的反而要最先写进脚本。
func TestRenderScriptRateRuleOrder(t *testing.T) {
	inet := nftTarget{Family: "inet", Table: "filter", Chain: "input"}
	stacks := []nftStack{{target: inet, bits: 32}}
	des := Desired{RateLimits: []RateLimitRule{
		{Key: "r1", PerSec: 5, Ports: portrange.Ports(7001)},
		{Key: "global", PerSec: 20, Ports: portrange.Ports(7002)},
	}}

	got := renderScript(stacks, des, nil, planRateRules(des.RateLimits))

	inserts := strings.Split(got, "\n")
	fine, global := -1, -1
	for i, line := range inserts {
		if strings.Contains(line, "@frpfirewall_rate_r1") {
			fine = i
		}
		if strings.Contains(line, "@frpfirewall_rate_global") {
			global = i
		}
	}
	if fine < 0 || global < 0 {
		t.Fatalf("两条限速规则都该出现\n%s", got)
	}
	// insertOrder 已经把脚本顺序翻成链上的真实顺序，直接比大小即可。
	if fine > global {
		t.Errorf("链上细分规则应排在全局兜底之前，实际 fine=%d global=%d\n%s",
			fine, global, got)
	}
}

// 只有 IPv6 来源的规则在 IPv4 落点上必须整条消失，不能退化成"不限来源"。
func TestPlanRateRulesSkipsWrongFamily(t *testing.T) {
	list := []RateLimitRule{
		{Key: "v6only", PerSec: 5, Sources: []string{"2001:db8::/32"}},
		{Key: "v4only", PerSec: 5, Sources: []string{"203.0.113.0/24"}},
	}
	got := planRateRules(list)
	if len(got) != 1 {
		t.Fatalf("应只剩 IPv4 那条，实际 %d 条", len(got))
	}
	if got[0].rule.Key != "v4only" {
		t.Fatalf("留下的应当是 v4only，实际 %q", got[0].rule.Key)
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
	want := renderScript(d.stacks, des, nil, nil)
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
		"insert rule inet filter input ip saddr @frpfirewall_black counter drop",
		"insert rule inet filter input ip6 saddr @frpfirewall_black6 counter drop",
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

// 这一组锁死「端口限定」这条范围的产物。
//
// 它的失效方式很安静：规则少一条、或者端口漏一个，内核不会报任何错，界面上照样
// 显示"已封禁"，只有真去连那个端口才发现没挡住。桩命令同样测不出来（桩不解析
// 语法，只会点头），所以只能断言脚本文本。
//
// 集合名现在由端口签名派生，所以断言里一律用 portSetName 现算，不把哈希写死：
// 换派生算法不该让一组功能用例跟着变红，那只会让人学会"顺手改断言"。
func TestRenderScriptPortScope(t *testing.T) {
	inet := nftTarget{Family: "inet", Table: "filter", Chain: "input"}
	ip4 := nftTarget{Family: "ip", Table: "filter", Chain: "INPUT"}

	ports := portrange.Ports(7100, 7000, 7000) // 故意乱序并重复
	key := ports.String()                      // "7000,7100"
	set4, set6 := portSetName(32, key), portSetName(128, key)

	des := Desired{
		Blacklist: []string{"203.0.113.7"},
		PortBlacklists: []PortBlacklist{{
			Key: key, Label: "仅 frp 端口",
			Prefixes: []string{"198.51.100.9", "2001:db8::5"}, Ports: ports,
		}},
	}

	t.Run("inet 双栈：每个协议栈各有 tcp 与 udp", func(t *testing.T) {
		stacks := []nftStack{{target: inet, bits: 32}, {target: inet, bits: 128}}
		got := renderScript(stacks, des, nil, nil)

		for _, want := range []string{
			"add element inet filter " + set4 + " { 198.51.100.9/32 }",
			"add element inet filter " + set6 + " { 2001:db8::5/128 }",
			// 端口归一化后升序；TCP 与 UDP 都要有，只封 TCP 会留下 UDP 绕过路径
			"tcp dport { 7000, 7100 } ip saddr @" + set4 + " counter drop",
			"udp dport { 7000, 7100 } ip saddr @" + set4 + " counter drop",
			"tcp dport { 7000, 7100 } ip6 saddr @" + set6 + " counter drop",
			// 全端口那部分不受影响
			"insert rule inet filter input ip saddr @frpfirewall_black counter drop",
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
		wide := portrange.Span(20000, 30000).Merge(portrange.Ports(880, 8443))
		got := renderScript(stacks, Desired{
			PortBlacklists: []PortBlacklist{{
				Key: wide.String(), Label: "仅 frp 端口",
				Prefixes: []string{"198.51.100.9"}, Ports: wide,
			}},
		}, nil, nil)

		want := "tcp dport { 880, 8443, 20000-30000 } ip saddr @" + portSetName(32, wide.String()) + " counter drop"
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

	// 分组还在、只是地址变少了（条目被删或被改走）时，必须先把集合清空再填。
	// 少了这一步，旧地址会一直留在集合里继续被封着 —— 而界面上它已经被删了。
	t.Run("分组存在时集合先 flush 再填", func(t *testing.T) {
		stacks := []nftStack{{target: inet, bits: 32}}
		got := renderScript(stacks, des, nil, nil)
		if !strings.Contains(got, "flush set inet filter "+set4) {
			t.Errorf("端口限定集合没有被 flush：改范围后元素会残留\n%s", got)
		}
		// 全端口集合同样要 flush，哪怕这次是空的。
		if !strings.Contains(got, "flush set inet filter "+setBlack) {
			t.Errorf("全端口集合没有被 flush\n%s", got)
		}
	})

	t.Run("没有端口时不生成引用集合的规则", func(t *testing.T) {
		stacks := []nftStack{{target: inet, bits: 32}}
		got := renderScript(stacks, Desired{PortBlacklists: []PortBlacklist{{
			Key: "", Label: "仅 frp 端口", Prefixes: []string{"198.51.100.9"},
		}}}, nil, nil)

		if strings.Contains(got, "dport") {
			t.Errorf("没有端口却生成了带 dport 的规则\n%s", got)
		}
		if strings.Contains(got, "@"+setPortPrefix) {
			t.Errorf("没有端口却生成了引用端口集合的规则，等于静默不生效\n%s", got)
		}
	})

	// 一组端口一个集合，地址不能串：串了的表现是"某个地址在它没被配到的那组
	// 端口上也被封了"，而两组规则长得一模一样，光看规则本身看不出来。
	t.Run("多个端口分组各用各的集合", func(t *testing.T) {
		stacks := []nftStack{{target: inet, bits: 32}}
		frp := portrange.Ports(7000)
		custom := portrange.Ports(8080)
		got := renderScript(stacks, Desired{PortBlacklists: []PortBlacklist{
			{Key: frp.String(), Label: "仅 frp 端口", Prefixes: []string{"198.51.100.9"}, Ports: frp},
			{Key: custom.String(), Label: "自定义端口 8080", Prefixes: []string{"203.0.113.7"}, Ports: custom},
		}}, nil, nil)

		for _, want := range []string{
			"add element inet filter " + portSetName(32, "7000") + " { 198.51.100.9/32 }",
			"add element inet filter " + portSetName(32, "8080") + " { 203.0.113.7/32 }",
			"tcp dport { 7000 } ip saddr @" + portSetName(32, "7000") + " counter drop",
			"tcp dport { 8080 } ip saddr @" + portSetName(32, "8080") + " counter drop",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("缺少 %q\n--- 实际脚本 ---\n%s", want, got)
			}
		}
		// 两个分组必须落到两个不同的集合名上，否则 A 组的地址会在 B 组的端口上被封。
		if portSetName(32, "7000") == portSetName(32, "8080") {
			t.Error("不同端口集合派生出同一个集合名，地址会串组")
		}
	})

	t.Run("某协议栈没有该类地址就不为它插规则", func(t *testing.T) {
		stacks := []nftStack{{target: inet, bits: 32}, {target: inet, bits: 128}}
		onlyV4 := Desired{PortBlacklists: []PortBlacklist{{
			Key: "7000", Label: "仅 frp 端口",
			Prefixes: []string{"198.51.100.9"}, Ports: portrange.Ports(7000),
		}}}
		got := renderScript(stacks, onlyV4, nil, nil)

		v4, v6 := portSetName(32, "7000"), portSetName(128, "7000")
		if !strings.Contains(got, "ip saddr @"+v4+" counter drop") {
			t.Errorf("IPv4 落点上缺少端口限定规则\n%s", got)
		}
		if strings.Contains(got, "ip6 saddr @"+v6+" counter drop") {
			t.Errorf("IPv6 下没有任何该类地址，不该为它生成规则\n%s", got)
		}
	})

	t.Run("ip 家族下不出现 ip6 表达式", func(t *testing.T) {
		stacks := []nftStack{{target: ip4, bits: 32}}
		got := renderScript(stacks, des, nil, nil)
		if strings.Contains(got, "ip6 saddr") {
			t.Errorf("ip 家族的链里出现了 ip6 表达式，nft 会拒掉整份脚本\n%s", got)
		}
	})
}

// 链上的实际顺序：全端口封禁在前，端口限定的在后。
//
// insert 一律插到链首，所以脚本文本里的先后与链上的顺序**相反** —— 脚本末尾那条
// 插入后位置最靠前。要验证真实顺序就得把 insert 序列倒过来读；直接拿脚本顺序
// 断言会得出完全相反的结论。
func TestRenderScriptPortRulesComeAfterAllPortRules(t *testing.T) {
	inet := nftTarget{Family: "inet", Table: "filter", Chain: "input"}
	stacks := []nftStack{{target: inet, bits: 32}}

	got := renderScript(stacks, Desired{
		Blacklist: []string{"203.0.113.7"},
		PortBlacklists: []PortBlacklist{{
			Key: "7000", Label: "仅 frp 端口",
			Prefixes: []string{"198.51.100.9"}, Ports: portrange.Ports(7000),
		}},
	}, nil, nil)

	all, port := -1, -1
	for i, line := range insertOrder(got) {
		if strings.Contains(line, "@"+setBlack+" counter drop") {
			all = i
		}
		if strings.Contains(line, "@"+portSetName(32, "7000")+" counter drop") {
			port = i
		}
	}
	if all < 0 || port < 0 {
		t.Fatalf("两条规则都应当存在\n%s", got)
	}
	if all > port {
		t.Errorf("链上顺序应为「全端口 → 端口限定」，实际相反\n%s", got)
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
