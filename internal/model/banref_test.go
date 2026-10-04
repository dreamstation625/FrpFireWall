package model

import "testing"

// 来源引用的格式在 ban 层与 api 层之间是一份**协议**，两边的解体必须一致。
//
// 这里把"哪种引用长什么样"钉死，因为踩过的坑正是它的形态不统一：名单条目引用
// 带的是自增主键（十进制），细分规则引用带的是内容签名（十六进制哈希）。
// 后者解析不出十进制 ID，于是"先解析、再看类型"的调用方在第一步就返回了，
// 那句"这条地址是被某规则拦的、解禁后还会被拦"的提示从来没出现过。
func TestBanSourceRefFormat(t *testing.T) {
	if got := BanSourceRef(BanRefACL, 12); got != "acl:12" {
		t.Errorf("名单条目引用应为 acl:12，实际 %q", got)
	}
	// 0 号没有意义（自增主键从 1 开始），返回空串表示"没有来源"，
	// 而不是拼出一个 acl:0 让调用方去查一条不存在的条目。
	if got := BanSourceRef(BanRefACL, 0); got != "" {
		t.Errorf("ID 为 0 时应返回空串，实际 %q", got)
	}
	if got := BanSourceRef("", 12); got != "" {
		t.Errorf("类型为空时应返回空串，实际 %q", got)
	}

	// 规则引用不走 BanSourceRef —— 它的标识是内容签名，由 RateRule.BanRef 拼。
	rule := RateRule{Name: "整段拉黑", Enabled: true, CIDRs: "203.0.113.0/24", Block: true}
	ref := rule.BanRef()
	if BanSourceRefKind(ref) != BanRefRule {
		t.Errorf("规则引用应有 %s 前缀，实际 %q", BanRefRule, ref)
	}
	// 停用的规则不产生封禁，也就没有引用。
	off := RateRule{Name: "停用的", Enabled: false, CIDRs: "203.0.113.0/24"}
	if off.BanRef() != "" {
		t.Errorf("停用的规则不该有来源引用，实际 %q", off.BanRef())
	}
}

// BanSourceRefKind 只认类型，不碰标识 —— 这正是它能正确处理规则引用的原因。
func TestBanSourceRefKind(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"acl:12", BanRefACL},
		{"rule:466972c4", BanRefRule},
		{"rule:deadbeef", BanRefRule},
		// 十六进制签名**有可能**整串都是数字。这类引用在 ParseBanSourceRef
		// 那里看起来像合法的数字 ID，但语义上完全不是 —— 所以类型判断必须
		// 只信 BanSourceRefKind。
		{"rule:12345678", BanRefRule},
		{"  acl:7  ", BanRefACL},

		// 没有引用的情形：频次自动封禁、全局地域名单、人工封禁都是空串。
		{"", ""},
		{"   ", ""},
		{"acl", ""},
		{":12", ""},
	}
	for _, c := range cases {
		if got := BanSourceRefKind(c.in); got != c.want {
			t.Errorf("BanSourceRefKind(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
}

// ParseBanSourceRef 的契约要写清楚：它**只**用来取名单条目的主键。
//
// 对规则引用返回 ok=false 不是 bug，是设计 —— 让"取不到 ID"这件事显式暴露出来，
// 而不是塞一个 0 给调用方去 GetACL(0)。调用方想判类型请用 BanSourceRefKind。
func TestParseBanSourceRef(t *testing.T) {
	kind, id, ok := ParseBanSourceRef("acl:12")
	if !ok || kind != BanRefACL || id != 12 {
		t.Errorf("acl:12 应解析为 (acl, 12, true)，实际 (%q, %d, %v)", kind, id, ok)
	}

	for _, ref := range []string{
		"rule:deadbeef", // 规则引用：标识不是十进制
		"acl:0",         // 0 号不存在
		"acl:",
		"acl",
		"",
		"  ",
	} {
		if kind, id, ok := ParseBanSourceRef(ref); ok {
			t.Errorf("%q 不该解析成功，实际 (%q, %d, true)", ref, kind, id)
		}
	}
}

// 内容签名必须只跟着"影响判定的字段"走：改个名字不该让谁解封，
// 而条件一改、规则一停用，旧签名就应当消失 —— 那是"依据不成立了"。
func TestRateRuleBanRefTracksConditionsNotName(t *testing.T) {
	base := RateRule{Name: "A", Enabled: true, CIDRs: "203.0.113.0/24", Block: true}
	ref := base.BanRef()

	renamed := base
	renamed.Name = "B"
	if renamed.BanRef() != ref {
		t.Error("改名字不该改变来源引用，否则改个名就会把一批地址解封")
	}

	reordered := base
	reordered.Remark = "换了个备注"
	if reordered.BanRef() != ref {
		t.Error("备注与判定无关，不该改变来源引用")
	}

	// 条件改动 → 引用改变 → 旧引用消失 → 由它封的地址随之解禁。
	for _, mutate := range []func(r *RateRule){
		func(r *RateRule) { r.CIDRs = "198.51.100.0/24" },
		func(r *RateRule) { r.Cities = "深圳" },
		func(r *RateRule) { r.Block = false },
	} {
		changed := base
		mutate(&changed)
		if changed.BanRef() == ref {
			t.Errorf("条件改动后来源引用应当变化：%+v", changed)
		}
	}

	// 停用 → 空引用，天然落进"旧签名消失"那一类，不需要单独判一次。
	disabled := base
	disabled.Enabled = false
	if disabled.BanRef() != "" {
		t.Error("停用的规则应返回空引用")
	}
}

// RateRuleBanRefs 是保存时做前后对比用的集合，停用的不计。
func TestRateRuleBanRefs(t *testing.T) {
	rows := []RateRule{
		{Name: "在用", Enabled: true, CIDRs: "203.0.113.0/24", Block: true},
		{Name: "停用", Enabled: false, CIDRs: "198.51.100.0/24", Block: true},
	}
	refs := RateRuleBanRefs(rows)
	if len(refs) != 1 {
		t.Fatalf("应当只剩 1 条启用的规则，实际 %d 条：%v", len(refs), refs)
	}
	if !refs[rows[0].BanRef()] {
		t.Errorf("集合里应当有启用规则的引用，实际 %v", refs)
	}
	if refs[""] {
		t.Error("空引用不该进集合 —— 它会把\"所有没有来源的封禁\"当成一条规则")
	}
}
