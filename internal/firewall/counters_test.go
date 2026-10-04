package firewall

import "testing"

// 这两个解析函数只能靠"真实格式的输出样本"来验 —— 本机（Windows）跑不了
// iptables / nft，端到端那条路走不通。所以样本必须照着真实输出写，
// 尤其是列的位置：iptables 那份是靠列号定位 source 的。

// iptables -L <链> -n -v -x 的真实输出形态。
const sampleIPTablesBlack = `Chain FRPFIREWALL_BLACK (1 references)
    pkts      bytes target     prot opt in     out     source               destination
      12      720 DROP       all  --  *      *       203.0.113.7          0.0.0.0/0
       0        0 DROP       all  --  *      *       198.51.100.9         0.0.0.0/0
`

// 端口限定链：选项里带 multiport dports，Key 必须带上端口才不会和上面撞。
const sampleIPTablesPort = `Chain FRPFIREWALL_BLACK_FRP (1 references)
    pkts      bytes target     prot opt in     out     source               destination
       5      300 DROP       tcp  --  *      *       203.0.113.7          0.0.0.0/0            multiport dports 7000
       0        0 DROP       tcp  --  *      *       198.51.100.9         0.0.0.0/0            multiport dports 8080
`

func TestParseIPTablesCountersByAddr(t *testing.T) {
	got := parseIPTablesCounters(sampleIPTablesBlack, "ipv4", CounterKindAddr)
	if len(got) != 2 {
		t.Fatalf("应当解析出 2 条，实际 %d 条：%+v", len(got), got)
	}
	if got[0].Key != "203.0.113.7" || got[0].Packets != 12 || got[0].Bytes != 720 {
		t.Fatalf("第一条 = %+v，期望 203.0.113.7 / 12 / 720", got[0])
	}
	if got[0].Kind != CounterKindAddr || got[0].Family != "ipv4" {
		t.Fatalf("种类与协议栈没带上：%+v", got[0])
	}
	// 0 包的条目也要在：界面上"封了但没人来撞"本身就是有用信息。
	if got[1].Key != "198.51.100.9" || got[1].Packets != 0 {
		t.Fatalf("第二条 = %+v，期望 198.51.100.9 / 0", got[1])
	}
}

func TestParseIPTablesCountersPortKeyDiffers(t *testing.T) {
	got := parseIPTablesCounters(sampleIPTablesPort, "ipv4", CounterKindPort)
	if len(got) != 2 {
		t.Fatalf("应当解析出 2 条，实际 %d 条：%+v", len(got), got)
	}
	// 同一个地址在两条链里各有一条规则。Key 不带端口的话，这两条会撞成
	// 一个 —— 界面上就只能看到其中一条的计数，另一条永远显示不出来。
	if got[0].Key != "203.0.113.7|7000" {
		t.Fatalf("端口限定条目的 Key 应当带端口，实际 %q", got[0].Key)
	}
	if got[1].Key != "198.51.100.9|8080" {
		t.Fatalf("第二条 Key = %q，期望 198.51.100.9|8080", got[1].Key)
	}
	if got[0].Packets != 5 || got[0].Bytes != 300 {
		t.Fatalf("计数解析错了：%+v", got[0])
	}
}

// 链里的非条目规则不能算进来：不限来源的兜底规则、以及将来可能加的 RETURN。
func TestParseIPTablesCountersSkipsNonEntryRules(t *testing.T) {
	raw := `Chain FRPFIREWALL_BLACK (1 references)
    pkts      bytes target     prot opt in     out     source               destination
     999   999999 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0
     888   888888 RETURN     all  --  *      *       203.0.113.7          0.0.0.0/0
       7      420 DROP       all  --  *      *       203.0.113.7          0.0.0.0/0
`
	got := parseIPTablesCounters(raw, "ipv4", CounterKindAddr)
	if len(got) != 1 {
		t.Fatalf("只该剩 1 条条目级规则，实际 %d 条：%+v", len(got), got)
	}
	if got[0].Packets != 7 {
		t.Fatalf("留下来的应当是那条 7 包的规则，实际 %+v", got[0])
	}
}

// nft -a list chain 的真实输出形态。
const sampleNFTChain = `table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
		ip saddr @frpfirewall_black counter packets 12 bytes 720 drop comment "frpfirewall:black" # handle 12
		ip6 saddr @frpfirewall_black6 counter packets 0 bytes 0 drop comment "frpfirewall:black6" # handle 13
		tcp dport { 7000 } ip saddr @frpfirewall_black_p_67a46022 counter packets 3 bytes 180 drop comment "frpfirewall:black-port:67a46022" # handle 14
		ct state new add @frpfirewall_rate_g { ip saddr limit rate over 20/second burst 40 packets } counter packets 9 bytes 540 drop comment "frpfirewall:rate:g" # handle 15
		accept
	}
}
`

func TestParseNFTCounters(t *testing.T) {
	got := parseNFTCounters(sampleNFTChain)
	if len(got) != 4 {
		t.Fatalf("应当解析出 4 条受管规则，实际 %d 条：%+v", len(got), got)
	}

	byKey := make(map[string]RuleCounter, len(got))
	for _, c := range got {
		byKey[c.Key] = c
	}

	// 最后那条 accept 没有 comment，不该出现 —— 它是系统自己的规则。
	if _, ok := byKey[""]; ok {
		t.Fatal("没有 comment 的规则不该被收进来")
	}

	black, ok := byKey[commentBlack]
	if !ok || black.Kind != CounterKindGroup || black.Packets != 12 {
		t.Fatalf("全端口那条 = %+v，期望 group / 12 包", black)
	}
	// inet 链里 v4 与 v6 是两条规则，协议栈要分得开。
	if black.Family != "ipv4" {
		t.Fatalf("协议栈认错了：%+v", black)
	}
	if v6, ok := byKey[commentBlack6]; !ok || v6.Family != "ipv6" {
		t.Fatalf("v6 那条协议栈应当是 ipv6：%+v", v6)
	}
	if p, ok := byKey[commentPortPrefix+"67a46022"]; !ok || p.Kind != CounterKindPort || p.Packets != 3 {
		t.Fatalf("端口限定那条 = %+v，期望 port / 3 包", p)
	}
	if r, ok := byKey[commentRate+":g"]; !ok || r.Kind != CounterKindRate || r.Packets != 9 {
		t.Fatalf("限速那条 = %+v，期望 rate / 9 包", r)
	}
}

// 没有 counter 表达式的规则数不出数，跳过而不是报 0。
//
// 报 0 会让人误判成"规则在生效、但一个包都没拦到"，而真相是"这条规则根本
// 没在数数" —— 老版本程序插进去的残留规则就是这种。
func TestParseNFTCountersSkipsRulesWithoutCounter(t *testing.T) {
	raw := `table inet filter {
	chain input {
		ip saddr @frpfirewall_black drop comment "frpfirewall:black" # handle 12
		ip saddr @frpfirewall_black counter packets 4 bytes 240 drop comment "frpfirewall:black" # handle 13
	}
}
`
	got := parseNFTCounters(raw)
	if len(got) != 1 {
		t.Fatalf("只该收带 counter 的那条，实际 %d 条：%+v", len(got), got)
	}
	if got[0].Packets != 4 {
		t.Fatalf("留下来的应当是 4 包那条，实际 %+v", got[0])
	}
}
