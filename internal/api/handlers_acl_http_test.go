package api

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/model"
)

// 取一条名单条目当前在**库里**的样子。
//
// 刻意不用接口返回的那份：接口返回的是请求体拼出来的对象，它正确不代表真的写进去了。
// 这次改动里最先踩到的就是这个 —— UpdateACL 的更新列漏了 ports，接口老老实实
// 把新端口回给了前端，库里却一个字节都没变，界面刷新一下又变回旧值。
func aclRow(t *testing.T, h *harness, id uint) (scope, ports, remark string) {
	t.Helper()
	e, err := h.srv.store.GetACL(id)
	if err != nil {
		t.Fatalf("读条目 %d 失败：%v", id, err)
	}
	return e.Scope, e.Ports, e.Remark
}

func entryID(t *testing.T, h *harness, r resp) uint {
	t.Helper()
	d := h.data(r)
	// JSON 数字会解成 float64
	f, ok := d["id"].(float64)
	if !ok || f <= 0 {
		t.Fatalf("接口没返回有效 id：%v", d["id"])
	}
	return uint(f)
}

// TestACLCustomPortsEndToEnd 走完"自定义端口"这条链：新增 → 落库 → 修改 → 再落库。
//
// 范围只影响内核规则怎么写（全端口丢 / 只在某些端口上丢），不影响插件层
// "是否命中"的判定 —— 插件只作用于 frp 连接、拿不到端口。所以自定义端口这一档
// 完全靠"库里那一列"决定内核封哪些端口，那一列丢了整档就是空的。
func TestACLCustomPortsEndToEnd(t *testing.T) {
	h := newHarness(t)

	// 新增：乱序 + 区间 + 重复，接口负责归一化后再入库
	code, r := h.call(http.MethodPost, "/api/v1/acl/black", map[string]any{
		"target": "203.0.113.5",
		"scope":  "custom",
		"ports":  "9000-9100, 8080 ,8080",
		"remark": "机房备用机",
	})
	if code != http.StatusOK {
		t.Fatalf("POST 应 200，得到 %d %s", code, r.Error)
	}
	id := entryID(t, h, r)
	if scope, ports, remark := aclRow(t, h, id); scope != "custom" || ports != "8080,9000-9100" || remark != "机房备用机" {
		t.Fatalf("入库结果 = (%q, %q, %q)，期望 (custom, 8080,9000-9100, 机房备用机)", scope, ports, remark)
	}

	// 修改端口：只传 ports，scope 不动
	code, r = h.call(http.MethodPut, "/api/v1/acl/black/"+strconv.Itoa(int(id)), map[string]any{"ports": "8081"})
	if code != http.StatusOK {
		t.Fatalf("PUT 应 200，得到 %d %s", code, r.Error)
	}
	if _, ports, _ := aclRow(t, h, id); ports != "8081" {
		t.Errorf("改完端口后库里 = %q，期望 8081（接口的值和库里的值必须一致）", ports)
	}

	// 换成非自定义范围：端口必须被清掉。
	// 库里残留一份不参与生效的端口是"配置里写着、实际不生效"那类最难排查的问题。
	code, r = h.call(http.MethodPut, "/api/v1/acl/black/"+strconv.Itoa(int(id)), map[string]any{"scope": "frp"})
	if code != http.StatusOK {
		t.Fatalf("PUT 应 200，得到 %d %s", code, r.Error)
	}
	if scope, ports, _ := aclRow(t, h, id); scope != "frp" || ports != "" {
		t.Errorf("切到 frp 范围后 = (%q, %q)，期望 (frp, 空)", scope, ports)
	}

	// 只改备注的请求不带 scope / ports，不能把范围偷偷放宽成"封全部端口"
	code, r = h.call(http.MethodPut, "/api/v1/acl/black/"+strconv.Itoa(int(id)), map[string]any{"remark": "改个备注"})
	if code != http.StatusOK {
		t.Fatalf("PUT 应 200，得到 %d %s", code, r.Error)
	}
	if scope, _, remark := aclRow(t, h, id); scope != "frp" || remark != "改个备注" {
		t.Errorf("只改备注后 = (%q, %q)，范围不该被改动", scope, remark)
	}

	// 重新添加同一个地址走的是 upsert 分支：端口是这次改动的本体，必须跟着更新
	code, r = h.call(http.MethodPost, "/api/v1/acl/black", map[string]any{
		"target": "203.0.113.5",
		"scope":  "custom",
		"ports":  "7000-7100",
	})
	if code != http.StatusOK {
		t.Fatalf("重复 POST 应 200，得到 %d %s", code, r.Error)
	}
	if scope, ports, _ := aclRow(t, h, id); scope != "custom" || ports != "7000-7100" {
		t.Errorf("重复添加后 = (%q, %q)，期望 (custom, 7000-7100)", scope, ports)
	}
}

// TestACLCustomPortsRejectsBadInput 自定义范围写不出端口时必须当场报错。
//
// 放过去的后果是"名单上它在、内核对不上"：范围是自定义却没有端口，内核一条
// 规则都生成不出来，而列表里它显示成一条正常生效中的条目。
func TestACLCustomPortsRejectsBadInput(t *testing.T) {
	h := newHarness(t)

	cases := []struct {
		name string
		body map[string]any
	}{
		{"缺端口", map[string]any{"target": "203.0.113.6", "scope": "custom"}},
		{"端口为空串", map[string]any{"target": "203.0.113.6", "scope": "custom", "ports": ""}},
		{"端口非法", map[string]any{"target": "203.0.113.6", "scope": "custom", "ports": "8080~9000"}},
		{"端口越界", map[string]any{"target": "203.0.113.6", "scope": "custom", "ports": "70000"}},
		// 范围写法只属于导入文件那一列，接口参数收到的是裸范围名
		{"把导入写法当接口参数", map[string]any{"target": "203.0.113.6", "scope": "custom:8080"}},
		{"未知范围", map[string]any{"target": "203.0.113.6", "scope": "some"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, r := h.call(http.MethodPost, "/api/v1/acl/black", c.body)
			if code != http.StatusBadRequest {
				t.Fatalf("应 400，得到 %d %s", code, r.Error)
			}
		})
	}

	// 白名单条目本身不产生任何封禁动作，范围恒为 all：手工塞进来的端口
	// 不能在库里留下一句读不懂也没用途的话。
	code, r := h.call(http.MethodPost, "/api/v1/acl/white", map[string]any{
		"target": "203.0.113.7",
		"scope":  "custom",
		"ports":  "8080",
	})
	if code != http.StatusOK {
		t.Fatalf("白名单条目应正常新增，得到 %d %s", code, r.Error)
	}
	if scope, ports, _ := aclRow(t, h, entryID(t, h, r)); scope != "all" || ports != "" {
		t.Errorf("白名单条目 = (%q, %q)，期望 (all, 空)", scope, ports)
	}
}

// 地区条目的完整链路：新增 → 落库 → 导出带类型前缀 → 导入还原 → 删除。
//
// 这条链上最容易断的是导出：地区条目的目标不是地址，导出时不带类型前缀的话
// 导入端会报"非法的 IP 地址" —— 等于地区条目根本没法留档、没法换机器搬。
func TestACLGeoEntryEndToEnd(t *testing.T) {
	h := newHarness(t)

	code, r := h.call(http.MethodPost, "/api/v1/acl/black", map[string]any{
		"target":      "cn, hk",
		"target_type": "geo_country",
		// 地区条目没有"范围"可言，传进来的范围与端口必须被忽略
		"scope":  "custom",
		"ports":  "8080",
		"remark": "境外扫描源",
	})
	if code != http.StatusOK {
		t.Fatalf("POST 应 200，得到 %d %s", code, r.Error)
	}
	id := entryID(t, h, r)

	row, err := h.srv.store.GetACL(id)
	if err != nil {
		t.Fatalf("读条目失败：%v", err)
	}
	if row.Target != "CN,HK" || row.TargetType != model.TargetGeoCountry {
		t.Fatalf("入库目标 = (%q, %q)，期望 (CN,HK, geo_country)", row.Target, row.TargetType)
	}
	if row.Scope != model.ScopeAll || row.Ports != "" {
		t.Fatalf("地区条目的范围必须是 all/空，实际 (%q, %q) —— "+
			"库里留一句「标着 custom、实际全端口」的谎话，界面上完全看不出来",
			row.Scope, row.Ports)
	}
	// 地区条目的 Target 是地名，拿它查属地没有意义
	if row.Country != "" || row.Province != "" {
		t.Fatalf("地区条目不该回填属地，实际 (%q, %q)", row.Country, row.Province)
	}

	// 导出：必须是 country:CN;HK 这种带前缀的写法（多值用分号，逗号是列分隔符）
	code, body := h.raw(http.MethodGet, "/api/v1/acl/black/export", nil)
	if code != http.StatusOK {
		t.Fatalf("导出应 200，得到 %d", code)
	}
	if !strings.Contains(body, "country:CN;HK") {
		t.Fatalf("导出内容里没有带前缀的地区行：\n%s", body)
	}
	if strings.Contains(body, "country:CN,HK") {
		t.Fatalf("多值用了逗号 —— 那是列分隔符，会把备注列切走：\n%s", body)
	}

	// 把导出的那一行原样导入回来，必须能还原成同一个条目
	line := ""
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, "country:") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("导出内容里找不到地区行：\n%s", body)
	}
	code, r = h.call(http.MethodPost, "/api/v1/acl/black/import", map[string]any{
		"content":  line,
		"dry_run":  true,
		"scope":    "custom:8080", // 地区行必须忽略它
		"dry_run2": nil,
	})
	if code != http.StatusOK {
		t.Fatalf("导入校验应 200，得到 %d %s", code, r.Error)
	}
	if n, _ := h.data(r)["added"].(float64); n != 1 {
		t.Fatalf("导出的那一行应当能被导入，实际 added=%v（invalid=%v）",
			h.data(r)["added"], h.data(r)["invalid"])
	}

	// 删除：即便没有任何封禁由它产生，也要把 released_bans 这个字段给出
	// （前端直接读它报数），值为 0 而不是缺字段。
	code, r = h.call(http.MethodDelete, "/api/v1/acl/black/"+strconv.Itoa(int(id)), nil)
	if code != http.StatusOK {
		t.Fatalf("DELETE 应 200，得到 %d %s", code, r.Error)
	}
	if _, ok := h.data(r)["released_bans"]; !ok {
		t.Fatalf("删除响应里应当带 released_bans 字段：%v", h.data(r))
	}
	if _, err := h.srv.store.GetACL(id); err == nil {
		t.Fatal("条目应当已被删除")
	}
}

// 地区值写错时的报错要指向真正的原因。
func TestACLGeoEntryRejectsBadInput(t *testing.T) {
	h := newHarness(t)

	cases := []struct {
		name string
		body map[string]any
		want string
	}{
		{"国家码三位", map[string]any{"target": "CHN", "target_type": "geo_country"}, "两位字母"},
		{"省份无法识别", map[string]any{"target": "深证", "target_type": "geo_province"}, "无法识别"},
		{"城市为空", map[string]any{"target": "  ", "target_type": "geo_city"}, "城市不能为空"},
		// 不给类型时按地址解析，"CN" 不是地址
		{"不给类型按地址", map[string]any{"target": "CN"}, "IP 地址"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, r := h.call(http.MethodPost, "/api/v1/acl/black", c.body)
			if code != http.StatusBadRequest {
				t.Fatalf("应 400，得到 %d %s", code, r.Error)
			}
			if !strings.Contains(r.Error, c.want) {
				t.Fatalf("报错里没有 %q：%s", c.want, r.Error)
			}
		})
	}
}

// 国家码只校验格式，**不校验真实性** —— 这条边界要钉住，免得哪天有人
// "顺手补一个存在性校验"。
//
// 能拿来做白名单的只有 geoip 包那份国家表，而它是刻意只收常见来源地的
// （未收录的国家按 ISO 码展示，不影响功能）。拿它当白名单会把哈萨克斯坦
// 之外的一大票真实国家一起拒掉 —— 那比"写错了不报错"严重得多。
func TestACLGeoCountryOnlyChecksFormat(t *testing.T) {
	h := newHarness(t)

	// CU 是老名单里没收录的真实国家；ZZ 是根本不存在的码。
	// 两者都按两位字母放行 —— 这是有意的取舍，不是漏了校验。
	for _, country := range []string{"KZ", "CU", "ZZ"} {
		st, r := h.call(http.MethodPost, "/api/v1/acl/black", map[string]any{
			"target":      country,
			"target_type": "geo_country",
		})
		if st != http.StatusOK {
			t.Errorf("国家码 %q 只该看格式，不该被拒：%d %s", country, st, r.Error)
		}
	}
}

// 手动解封一个"被某条名单条目封掉"的地址时，那条条目必须一并删掉。
//
// 不删的后果很具体：解封当场生效，但它下一次连接又命中同一条条目、立刻再被封
// 一次 —— 用户看到的是"解封没起作用"，而他的真实意图是"让这个地址进来"。
func TestUnbanClearsBackingACLEntry(t *testing.T) {
	h := newHarness(t)

	code, r := h.call(http.MethodPost, "/api/v1/acl/black", map[string]any{
		"target": "203.0.113.7",
		"remark": "扫描源",
	})
	if code != http.StatusOK {
		t.Fatalf("POST 应 200，得到 %d %s", code, r.Error)
	}
	aclID := entryID(t, h, r)

	// 造一条"由这条条目产生"的封禁。Target 写成 /32 是刻意的：真实的封禁记录
	// 来自 banPrefix，按封禁粒度可能带掩码，而条目里存的是裸 IP —— 两者字面不同、
	// 指的却是同一件事，比对时必须归一化。
	rec := &model.BanRecord{
		Target: "203.0.113.7/32", TargetType: "cidr4",
		Scope: model.ScopeAll, Reason: "命中黑名单", Source: model.SourceGeoIP,
		SourceRef: model.BanSourceRef(model.BanRefACL, aclID),
		Status:    model.BanActive, BannedAt: time.Now(),
	}
	if err := h.srv.store.CreateBan(rec); err != nil {
		t.Fatalf("造封禁记录失败：%v", err)
	}

	code, r = h.call(http.MethodDelete, "/api/v1/bans/"+strconv.Itoa(int(rec.ID)), nil)
	if code != http.StatusOK {
		t.Fatalf("解封应 200，得到 %d %s", code, r.Error)
	}
	if n, _ := h.data(r)["source_entry_removed"].(float64); n != 1 {
		t.Fatalf("应当报告清理了 1 条名单条目，实际 %v", h.data(r)["source_entry_removed"])
	}
	if _, err := h.srv.store.GetACL(aclID); err == nil {
		t.Fatal("背后的名单条目应当已被删除，否则解封之后它还会被同一条拦回来")
	}

	// 清理痕迹要留事件：静默删掉一条黑名单条目是"事后完全查不出发生过什么"的操作
	ev, err := h.srv.store.ListEventsPage("", "", nil, 1, 50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range ev.Items {
		if strings.Contains(e.Detail, "一并移除") {
			found = true
		}
	}
	if !found {
		t.Fatalf("应当留下「一并移除条目」的事件记录，实际 %d 条事件都没提到", len(ev.Items))
	}
}

// 条目是网段时，**只解封、不动条目**。
//
// 条目 1.2.3.0/24 背后是 256 个地址，删掉它等于顺手把另外 255 个也放进来，
// 那超出了用户点这一次解封的授权范围。
func TestUnbanKeepsCIDREntry(t *testing.T) {
	h := newHarness(t)

	code, r := h.call(http.MethodPost, "/api/v1/acl/black", map[string]any{"target": "203.0.113.0/24"})
	if code != http.StatusOK {
		t.Fatalf("POST 应 200，得到 %d %s", code, r.Error)
	}
	aclID := entryID(t, h, r)

	// 封禁记录的 Target 是该网段里的一个具体地址 → 与条目不等
	rec := &model.BanRecord{
		Target: "203.0.113.7/32", TargetType: "cidr4",
		Scope: model.ScopeAll, Reason: "命中黑名单", Source: model.SourceGeoIP,
		SourceRef: model.BanSourceRef(model.BanRefACL, aclID),
		Status:    model.BanActive, BannedAt: time.Now(),
	}
	if err := h.srv.store.CreateBan(rec); err != nil {
		t.Fatal(err)
	}

	code, r = h.call(http.MethodDelete, "/api/v1/bans/"+strconv.Itoa(int(rec.ID)), nil)
	if code != http.StatusOK {
		t.Fatalf("解封应 200，得到 %d %s", code, r.Error)
	}
	if n, _ := h.data(r)["source_entry_removed"].(float64); n != 0 {
		t.Fatalf("网段条目不该被删，实际报告清理了 %v 条", h.data(r)["source_entry_removed"])
	}
	if _, err := h.srv.store.GetACL(aclID); err != nil {
		t.Fatalf("网段条目必须留着，实际读不到了：%v", err)
	}
}

// 解封一个"由细分规则拦下"的地址时，不动规则，但必须留一句提示。
//
// 规则是条件型的（"来自某地区的一律拦"），没法从中"移除一个地址" ——
// 强行动作只会把整条规则改坏。但什么也不说同样不行：用户会发现解禁之后
// 又被拦回来，只能自己猜原因。
func TestUnbanFromRuleLeavesRuleAlone(t *testing.T) {
	h := newHarness(t)

	// PUT /policy 要求带上完整的全局策略（窗口、阈值这些不能缺），
	// 用模板而不是自己拼一个半截请求体 —— 半截的会被"统计窗口需在 1~86400"
	// 这类校验挡下来，测不到规则那部分。
	body := h.policyBody()
	body["rules"] = []map[string]any{{
		"name": "整段拉黑", "enabled": true,
		"cidrs": "203.0.113.0/24", "block": true,
	}}
	code, r := h.call(http.MethodPut, "/api/v1/policy", body)
	if code != http.StatusOK {
		t.Fatalf("保存规则应 200，得到 %d %s", code, r.Error)
	}

	rules, err := h.srv.store.RateRules()
	if err != nil || len(rules) != 1 {
		t.Fatalf("应当存下 1 条规则，实际 %d 条（err=%v）", len(rules), err)
	}
	if !rules[0].Block || rules[0].Cities != "" {
		t.Fatalf("规则的 block 没落库：%+v", rules[0])
	}
	ref := rules[0].BanRef()
	if !strings.HasPrefix(ref, model.BanRefRule+":") {
		t.Fatalf("规则来源引用形态不对：%q", ref)
	}

	rec := &model.BanRecord{
		Target: "203.0.113.7/32", TargetType: "cidr4",
		Scope: model.ScopeAll, Reason: "命中规则", Source: model.SourceRule,
		SourceRef: ref, Status: model.BanActive, BannedAt: time.Now(),
	}
	if err := h.srv.store.CreateBan(rec); err != nil {
		t.Fatal(err)
	}

	code, r = h.call(http.MethodDelete, "/api/v1/bans/"+strconv.Itoa(int(rec.ID)), nil)
	if code != http.StatusOK {
		t.Fatalf("解封应 200，得到 %d %s", code, r.Error)
	}
	if n, _ := h.data(r)["source_entry_removed"].(float64); n != 0 {
		t.Fatalf("不该报告清理了条目，实际 %v", h.data(r)["source_entry_removed"])
	}

	// 规则原样留着
	if left, err := h.srv.store.RateRules(); err != nil || len(left) != 1 || !left[0].Block {
		t.Fatalf("规则不该被动过：%d 条（err=%v）", len(left), err)
	}

	// 但事件里必须说清楚"是规则拦的、规则还开着"
	ev, err := h.srv.store.ListEventsPage("", "", nil, 1, 50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range ev.Items {
		if strings.Contains(e.Detail, "细分规则拦截") {
			found = true
		}
	}
	if !found {
		t.Fatalf("应当留一句「该地址由细分规则拦截」的提示，实际没有（事件 %d 条）", len(ev.Items))
	}
}

// 地区条目的地址列要显示中文名，但这只是**展示层**的转换：
// 库里、匹配时、导出文件里都必须仍是国家码（归一化与命中判定都基于它）。
func TestACLListShowsGeoNameInChinese(t *testing.T) {
	h := newHarness(t)

	code, r := h.call(http.MethodPost, "/api/v1/acl/black", map[string]any{
		"target":      "hk, jp, sg",
		"target_type": "geo_country",
	})
	if code != http.StatusOK {
		t.Fatalf("建地区条目应 200，得到 %d %s", code, r.Error)
	}
	// 再建一条地址条目：它不该带展示名，前端回落显示原值
	code, r = h.call(http.MethodPost, "/api/v1/acl/black", map[string]any{
		"target": "203.0.113.7",
	})
	if code != http.StatusOK {
		t.Fatalf("建地址条目应 200，得到 %d %s", code, r.Error)
	}

	code, r = h.call(http.MethodGet, "/api/v1/acl/black?page=1&size=20", nil)
	if code != http.StatusOK {
		t.Fatalf("列表应 200，得到 %d %s", code, r.Error)
	}
	items, _ := h.data(r)["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("应当有 2 条，实际 %d", len(items))
	}

	var geo, addr map[string]any
	for _, it := range items {
		row, _ := it.(map[string]any)
		if row["target_type"] == model.TargetGeoCountry {
			geo = row
		} else {
			addr = row
		}
	}
	if geo == nil || addr == nil {
		t.Fatalf("没找到两条不同类型的条目：%+v", items)
	}

	if got := geo["target_label"]; got != "中国香港、日本、新加坡" {
		t.Fatalf("地区条目的展示名 = %v，期望「中国香港、日本、新加坡」", got)
	}
	if got := geo["target"]; got != "HK,JP,SG" {
		t.Fatalf("匹配值被改写了 = %v —— 归一化、命中判定、导出导入都基于它，"+
			"必须保持国家码 HK,JP,SG", got)
	}
	if got := addr["target_label"]; got != "" {
		t.Fatalf("地址条目不该有展示名，实际 %v", got)
	}

	// 导出文件也不能因为展示层改中文 —— 导出的行还要能原样导入回来
	code, body := h.raw(http.MethodGet, "/api/v1/acl/black/export", nil)
	if code != http.StatusOK {
		t.Fatalf("导出应 200，得到 %d", code)
	}
	if !strings.Contains(body, "country:HK;JP;SG") {
		t.Fatalf("导出内容里应当是国家码：\n%s", body)
	}
	if strings.Contains(body, "中国香港") {
		t.Fatalf("导出内容里出现了中文名 —— 前缀解析只认国家码，导入会整个失败：\n%s", body)
	}
}

// 列表显示中文名之后，搜索也必须能吃中文名。否则用户照着界面上的字搜一条都搜不到 ——
// 展示与搜索对不上，比不显示中文名更让人困惑。
//
// 顺带钉住一个更隐蔽的点：多个搜索词必须**各自带括号**再或起来。写成
// `kind = ? AND A OR B` 的话（AND 优先级高于 OR），B 命中会把 kind 条件整个绕过去 ——
// 在黑名单页搜出白名单的条目。下面用"白名单放地区条目、黑名单放无关地址条目"来验它。
func TestACLSearchMatchesChineseGeoName(t *testing.T) {
	h := newHarness(t)

	if code, r := h.call(http.MethodPost, "/api/v1/acl/white", map[string]any{
		"target":      "hk",
		"target_type": "geo_country",
	}); code != http.StatusOK {
		t.Fatalf("建白名单地区条目应 200，得到 %d %s", code, r.Error)
	}
	if code, r := h.call(http.MethodPost, "/api/v1/acl/black", map[string]any{
		"target": "203.0.113.9",
	}); code != http.StatusOK {
		t.Fatalf("建黑名单地址条目应 200，得到 %d %s", code, r.Error)
	}

	// 白名单：按界面上的中文名搜得到，展示名也是中文
	code, r := h.call(http.MethodGet, "/api/v1/acl/white?keyword="+url.QueryEscape("香港"), nil)
	if code != http.StatusOK {
		t.Fatalf("列表应 200，得到 %d %s", code, r.Error)
	}
	d := h.data(r)
	if d["total"] != float64(1) {
		t.Fatalf("按中文名「香港」搜白名单应命中 1 条，实际 total=%v", d["total"])
	}
	if items, _ := d["items"].([]any); len(items) == 1 {
		if got := items[0].(map[string]any)["target_label"]; got != "中国香港" {
			t.Fatalf("展示名 = %v，期望「中国香港」", got)
		}
	}

	// 黑名单：同一个词不能把白名单的条目捞出来
	code, r = h.call(http.MethodGet, "/api/v1/acl/black?keyword="+url.QueryEscape("香港"), nil)
	if code != http.StatusOK {
		t.Fatalf("列表应 200，得到 %d %s", code, r.Error)
	}
	if got := h.data(r)["total"]; got != float64(0) {
		t.Fatalf("按「香港」搜黑名单应 0 条，实际 total=%v —— "+
			"多词 OR 没加括号，kind 条件被绕过去了，白名单的条目被搜出来了", got)
	}

	// 按国家码本身搜同样要能命中（老习惯不该因为加了中文名而退化）
	code, r = h.call(http.MethodGet, "/api/v1/acl/white?keyword=HK", nil)
	if code != http.StatusOK {
		t.Fatalf("列表应 200，得到 %d %s", code, r.Error)
	}
	if got := h.data(r)["total"]; got != float64(1) {
		t.Fatalf("按国家码 HK 搜应命中 1 条，实际 total=%v", got)
	}
}

// aclPath 拼一个条目详情地址。
func aclPath(kind string, id uint) string {
	return "/api/v1/acl/" + kind + "/" + strconv.FormatUint(uint64(id), 10)
}

// 创建一条带有效期的条目，返回 id。
func createACLWithExpiry(t *testing.T, h *harness, kind, target string, sec int64) uint {
	t.Helper()
	code, r := h.call(http.MethodPost, "/api/v1/acl/"+kind, map[string]any{
		"target":         target,
		"expires_in_sec": sec,
	})
	if code != http.StatusOK {
		t.Fatalf("创建条目应 200，得到 %d %s", code, r.Error)
	}
	return entryID(t, h, r)
}

// 编辑条目时"没提有效期"必须等于"不改动有效期"。
//
// 这个字段上前后踩过两次坑，所以契约值得钉死：
//
//  1. 最早 update 用普通 int64，"没传"绑定出来就是 0、而 0 表示永久 ——
//     于是"进来改个备注"这个最普通的操作，会把一条「1 小时」的条目悄悄改成
//     永久生效，而请求里根本没提有效期。
//  2. 改成"前端回填精确剩余秒数硬扛"之后，结果是对的，但界面上多出的一档
//     与预设档撞名（3597 秒被说成"剩余 60 分钟"，和「1 小时」字面一样），
//     反而更让人看不懂该选哪个。
//
// 现在改成显式区分：字段缺席 = 不动，传 0 = 改成永久，正数 = 从现在起 N 秒。
func TestUpdateACLKeepsExpiryWhenOmitted(t *testing.T) {
	h := newHarness(t)
	id := createACLWithExpiry(t, h, "black", "203.0.113.9", 3600)

	before, err := h.srv.store.GetACL(id)
	if err != nil {
		t.Fatal(err)
	}
	if before.ExpiresAt == nil {
		t.Fatal("条目应当有到期时刻")
	}

	code, r := h.call(http.MethodPut, aclPath("black", id), map[string]any{
		"remark": "改过的备注",
	})
	if code != http.StatusOK {
		t.Fatalf("PUT 应 200，得到 %d %s", code, r.Error)
	}

	after, err := h.srv.store.GetACL(id)
	if err != nil {
		t.Fatal(err)
	}
	if after.ExpiresAt == nil {
		t.Fatal("只改备注就把到期时刻清掉了 —— 这正是「有效期选 1 小时、保存后变永久」那个 bug")
	}
	if after.ExpiresAt.Unix() != before.ExpiresAt.Unix() {
		t.Fatalf("请求里没提有效期，它却被改了：%v → %v", before.ExpiresAt, after.ExpiresAt)
	}
	if after.Remark != "改过的备注" {
		t.Fatalf("备注没更新：%q", after.Remark)
	}
}

// 显式传值时的两种语义：0 = 改成永久，正数 = 从现在起重新计时。
func TestUpdateACLExpiryExplicitValues(t *testing.T) {
	h := newHarness(t)
	id := createACLWithExpiry(t, h, "black", "203.0.113.10", 3600)

	// 传 0 → 永久
	code, r := h.call(http.MethodPut, aclPath("black", id), map[string]any{
		"expires_in_sec": 0,
	})
	if code != http.StatusOK {
		t.Fatalf("PUT 应 200，得到 %d %s", code, r.Error)
	}
	row, err := h.srv.store.GetACL(id)
	if err != nil {
		t.Fatal(err)
	}
	if row.ExpiresAt != nil {
		t.Fatalf("显式传 0 应改成永久，实际仍有到期时刻 %v", row.ExpiresAt)
	}

	// 传正数 → 从现在起重新计时（而不是在原到期时刻上叠加）
	code, r = h.call(http.MethodPut, aclPath("black", id), map[string]any{
		"expires_in_sec": 86400,
	})
	if code != http.StatusOK {
		t.Fatalf("PUT 应 200，得到 %d %s", code, r.Error)
	}
	row, err = h.srv.store.GetACL(id)
	if err != nil {
		t.Fatal(err)
	}
	if row.ExpiresAt == nil {
		t.Fatal("显式传正数却没有设置到期时刻")
	}
	want := time.Now().Add(86400 * time.Second).Unix()
	if d := row.ExpiresAt.Unix() - want; d > 10 || d < -10 {
		t.Fatalf("到期时刻应约等于 now+86400s，偏差 %d 秒（%v）", d, row.ExpiresAt)
	}
}

// 启用/禁用开关的接口契约：
//
//   - enabled 用指针收：没传 = 不改动。开关请求只发 enabled，备注、有效期
//     一个字节都不能动（Remark 因此也改成了指针 —— 开关请求不带备注，
//     值类型绑定出来是空串，会把原备注清掉）。
//   - 从启用切到停用必须报告 released_bans：停用要和删除一个待遇，由这条
//     条目封掉的地址一起放开（本用例没有由它产生的封禁，值应为 0 且字段必须在）。
func TestUpdateACLToggleEnabled(t *testing.T) {
	h := newHarness(t)

	code, r := h.call(http.MethodPost, "/api/v1/acl/black", map[string]any{
		"target": "203.0.113.11",
		"remark": "扫描源",
	})
	if code != http.StatusOK {
		t.Fatalf("POST 应 200，得到 %d %s", code, r.Error)
	}
	id := entryID(t, h, r)

	// 停用：只发 enabled，不带备注
	code, r = h.call(http.MethodPut, aclPath("black", id), map[string]any{"enabled": false})
	if code != http.StatusOK {
		t.Fatalf("PUT 应 200，得到 %d %s", code, r.Error)
	}
	if _, ok := h.data(r)["released_bans"]; !ok {
		t.Fatalf("停用响应里应当带 released_bans 字段：%v", h.data(r))
	}
	row, err := h.srv.store.GetACL(id)
	if err != nil {
		t.Fatal(err)
	}
	if row.Enabled {
		t.Fatal("enabled=false 应当落库")
	}
	if row.Remark != "扫描源" {
		t.Fatalf("开关请求不该动备注，实际 %q —— Remark 没用指针的话这里会被清成空串", row.Remark)
	}

	// 再只改备注：enabled 不传 = 保持停用
	code, r = h.call(http.MethodPut, aclPath("black", id), map[string]any{"remark": "新备注"})
	if code != http.StatusOK {
		t.Fatalf("PUT 应 200，得到 %d %s", code, r.Error)
	}
	if row, err = h.srv.store.GetACL(id); err != nil {
		t.Fatal(err)
	}
	if row.Enabled || row.Remark != "新备注" {
		t.Fatalf("只改备注后 = (enabled=%v, remark=%q)，期望 (false, 新备注)", row.Enabled, row.Remark)
	}

	// 重新启用
	code, r = h.call(http.MethodPut, aclPath("black", id), map[string]any{"enabled": true})
	if code != http.StatusOK {
		t.Fatalf("PUT 应 200，得到 %d %s", code, r.Error)
	}
	if row, err = h.srv.store.GetACL(id); err != nil {
		t.Fatal(err)
	}
	if !row.Enabled {
		t.Fatal("enabled=true 应当落库")
	}
}
