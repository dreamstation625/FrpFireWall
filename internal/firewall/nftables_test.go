package firewall

import (
	"net/netip"
	"strings"
	"testing"
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
		ProtectPorts: []int{7000},
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
