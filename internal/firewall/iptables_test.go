package firewall

import (
	"strings"
	"testing"
)

// 「仅 frp 端口」在 iptables 侧落成一个独立子链，规则必须带端口条件。
//
// 这类错误不会报错、不会告警，只会静默少挡一部分流量，所以只能断言生成的规则。
func TestFrpBlockRules(t *testing.T) {
	t.Run("tcp 与 udp 各一条，端口去重后升序", func(t *testing.T) {
		got := frpBlockRules([]string{"198.51.100.9"}, []int{7100, 7000, 7000})
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

	t.Run("端口多于 multiport 上限时拆成多条", func(t *testing.T) {
		ports := make([]int, 0, 20)
		for p := 7000; p < 7020; p++ {
			ports = append(ports, p)
		}
		got := frpBlockRules([]string{"198.51.100.9"}, ports)

		// 20 个端口 → 2 块 × 2 种协议 = 4 条
		if len(got) != 4 {
			t.Fatalf("规则数 %d，期望 4：%v", len(got), got)
		}
		for _, args := range got {
			line := strings.Join(args, " ")
			i := strings.Index(line, "--dports ")
			if i < 0 {
				t.Fatalf("规则里没有 --dports: %s", line)
			}
			rest := line[i+len("--dports "):]
			if sp := strings.Index(rest, " "); sp >= 0 {
				rest = rest[:sp]
			}
			if n := len(strings.Split(rest, ",")); n > multiportMax {
				t.Errorf("一条规则带了 %d 个端口，超过 multiport 上限 %d：%s", n, multiportMax, line)
			}
		}
	})

	t.Run("没有端口时不生成任何规则", func(t *testing.T) {
		if got := frpBlockRules([]string{"198.51.100.9"}, nil); len(got) != 0 {
			t.Errorf("没有端口却生成了 %d 条规则：%v", len(got), got)
		}
		if got := frpBlockRules(nil, []int{7000}); len(got) != 0 {
			t.Errorf("没有地址却生成了 %d 条规则：%v", len(got), got)
		}
	})
}

// 主链的顺序即优先级：全端口封禁排在仅 frp 端口之前，RETURN 必须留在最后。
func TestBuildIPTablesRulesOrder(t *testing.T) {
	rules := buildIPTablesRules(Desired{
		Blacklist:    []string{"203.0.113.7"},
		BlacklistFrp: []string{"198.51.100.9"},
		ProtectPorts: []int{7000},
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
		ProtectPorts: []int{7000},
		RateLimit:    &RateLimitSpec{Enabled: true, PerSec: 20},
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
	rules := buildIPTablesRules(Desired{ProtectPorts: []int{0, -1, 7000, 7000, 70001, 7100}}, 32)
	if got := portList(rules.FrpPorts); got != "7000,7100" {
		t.Errorf("端口归一化结果 %q，期望 7000,7100", got)
	}
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
		ProtectPorts: []int{7000, 7100},
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
