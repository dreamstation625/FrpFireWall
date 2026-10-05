package api

import (
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"

	"github.com/dreamstation625/FrpFireWall/internal/geoip"
	"github.com/dreamstation625/FrpFireWall/internal/guard"
	"github.com/dreamstation625/FrpFireWall/internal/model"
	"github.com/dreamstation625/FrpFireWall/internal/portrange"
	"github.com/dreamstation625/FrpFireWall/internal/store"
)

// ---- 黑白名单 ----

func validKind(kind string) bool {
	return kind == model.KindWhite || kind == model.KindBlack
}

// aclView 是名单条目在接口上的形态：库里的字段原样带出，另补一个展示用的中文名。
//
// 地区条目的 Target 是**匹配值**（国家码 "HK,JP"、省份 "广东"），匹配、归一化与
// 导出导入全都基于它，所以它必须保持原样 —— 列表里直接看到 "HK,JP,SG,TW,US"
// 不好认，于是在响应里另给一个 target_label 只管展示。地址条目的 TargetLabel
// 留空，前端回落去显示 Target。
type aclView struct {
	model.ACLEntry
	TargetLabel string `json:"target_label"`
}

func aclViewOf(e model.ACLEntry) aclView {
	v := aclView{ACLEntry: e}
	if model.IsGeoTargetType(e.TargetType) {
		v.TargetLabel = geoip.DisplayList(e.TargetType, e.Target)
	}
	return v
}

// aclSearchTerms 把一个搜索词展开成 SQL 要匹配的若干词。
//
// 列表里地区条目显示的是中文名（"中国香港"），库里存的却是国家码（"HK"）。
// 只按库里那串 LIKE 的话，用户照着界面上的字去搜一条都搜不到 —— 展示与搜索对不上，
// 比不显示中文名更让人困惑。所以把中文名反查回国家码一起匹配。
//
// 反查依据 geoip 那份**封闭**的常见来源地国家表：查得到就加，查不到就只按原词匹配
// （未收录的国家本来也只能按码搜）。省份与城市库里存的就是中文，无需展开。
func aclSearchTerms(keyword string) []string {
	kw := strings.TrimSpace(keyword)
	if kw == "" {
		return nil
	}
	terms := []string{kw}
	// seen 里预置大写原词：搜 "hk" 时不必再补一条 "HK"，LIKE 对 ASCII 本就不区分大小写。
	seen := map[string]bool{strings.ToUpper(kw): true}
	for _, c := range geoip.Countries() {
		if !strings.Contains(c.Name, kw) || seen[c.Code] {
			continue
		}
		seen[c.Code] = true
		terms = append(terms, c.Code)
	}
	return terms
}

func (s *Server) handleListACL(c *gin.Context) {
	kind := c.Param("kind")
	if !validKind(kind) {
		badRequest(c, "kind 只能是 white 或 black")
		return
	}
	page, size := pageParams(c)

	res, err := s.store.ListACL(kind, aclSearchTerms(c.Query("keyword")), page, size)
	if err != nil {
		serverErr(c, err)
		return
	}
	items := make([]aclView, 0, len(res.Items))
	for _, e := range res.Items {
		items = append(items, aclViewOf(e))
	}
	ok(c, store.Page[aclView]{Items: items, Total: res.Total, Page: res.Page, Size: res.Size})
}

func (s *Server) handleCreateACL(c *gin.Context) {
	kind := c.Param("kind")
	if !validKind(kind) {
		badRequest(c, "kind 只能是 white 或 black")
		return
	}

	var req struct {
		Target string `json:"target"`
		// TargetType 留空时按 IP/CIDR 推断（老客户端不传这个字段）。
		// 要建地区条目就必须显式给 geo_country / geo_province / geo_city ——
		// 不从内容去猜：两位字母既可能是国家码也可能是个手滑的地址片段，
		// 猜错的后果是"配了一条永远不命中或莫名其妙命中的条目"。
		TargetType string `json:"target_type"`
		Remark     string `json:"remark"`
		// ExpiresIn 用指针是为了区分"没传"和"传了 0"：两者在创建时都是永久，
		// 但在编辑时含义完全不同（不改动 vs 改成永久），见 handleUpdateACL。
		// 这里一并收指针，是为了让两个接口的字段类型一致 —— 同一个字段在
		// 创建和编辑上语义不同，迟早有人照着一边写另一边。
		ExpiresIn *int64 `json:"expires_in_sec"` // <=0 表示永久
		Scope     string `json:"scope"`          // all | frp | custom，留空按 all
		Ports     string `json:"ports"`          // 仅 scope=custom 时有意义
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请求格式不正确")
		return
	}

	if req.ExpiresIn != nil && (*req.ExpiresIn < 0 || *req.ExpiresIn > model.MaxDurationSeconds) {
		badRequest(c, "有效期超出范围，永久请填写 0")
		return
	}

	target, targetType, err := normalizeACLTarget(req.Target, req.TargetType)
	if err != nil {
		badRequest(c, err.Error())
		return
	}

	scope, ports, err := aclScopePorts(kind, targetType, req.Scope, req.Ports)
	if err != nil {
		badRequest(c, err.Error())
		return
	}

	entry := &model.ACLEntry{
		Kind:       kind,
		Target:     target,
		TargetType: targetType,
		Scope:      scope,
		Ports:      ports,
		Remark:     req.Remark,
		Source:     model.SourceManual,
		// 创建路径必须显式写 true：模型列带 default:true，GORM 会把零值 false
		// 省略掉、落库成 true。这里写 true 与库的默认一致，纯属把约定钉在明面上。
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// 创建时"没传"与"传 0"都是永久，不必区分。
	if req.ExpiresIn != nil && *req.ExpiresIn > 0 {
		t := time.Now().Add(model.SafeSeconds(*req.ExpiresIn))
		entry.ExpiresAt = &t
	}

	// 顺带把属地填上，列表里直接能看到来源。
	// 只对 IP 条目做：地区条目的 Target 是地名本身，拿去查属地没有意义。
	if !model.IsGeoTargetType(targetType) {
		if info := s.geo.LookupString(target); info != nil {
			entry.Country = info.Country
			entry.Province = info.Province
		}
	}

	if err := s.store.UpsertACL(entry); err != nil {
		serverErr(c, err)
		return
	}

	s.refreshGuard()

	_ = s.store.AddEvent(&model.Event{
		Category: model.EvtConfig,
		IP:       c.ClientIP(),
		Detail:   fmt.Sprintf("新增%s条目 %s", kindLabel(kind), target),
		Actor:    s.currentUser(c),
	})

	ok(c, entry)
}

func (s *Server) handleUpdateACL(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		badRequest(c, "ID 不正确")
		return
	}

	var req struct {
		// Remark 用指针：开关请求（只发 enabled）不带备注，不能把它清空。
		Remark *string `json:"remark"`
		// ExpiresIn 用指针的理由同下面的 Scope：区分"没传"与"传了 0"。
		//
		// 这个字段踩过的坑比 Scope 还隐蔽：老写法用普通 int64，绑定时"没传"
		// 就是 0、而 0 表示永久，于是"进来改个备注"这个最普通的操作，会把一条
		// 「1 小时」的条目悄悄改成永久生效 —— 请求里根本没提有效期。
		// nil = 保持原值，0 = 改成永久，正数 = 从现在起 N 秒。
		ExpiresIn *int64 `json:"expires_in_sec"`
		// Enabled 用指针区分"没传"与"传 false"：nil = 不改动。
		// 由启用切到停用时会联动解禁由这条条目产生的封禁（见下方）。
		Enabled *bool `json:"enabled"`
		// Scope 用指针是为了区分"没传"和"传了空串"。
		//
		// 用普通 string 会有个很隐蔽的坑：只改备注的请求不带 scope 字段，
		// 绑定出来就是 ""，归一化后变成 all，等于把一条 frp 范围的条目
		// 偷偷放宽成"封全部端口"——连 SSH 一起挡。改个备注不该有这种副作用。
		// 所以 nil 表示保持原值，非 nil 才覆盖。
		Scope *string `json:"scope"`
		// Ports 同理：nil 表示保持原值。切换范围时也要能把它改掉（或清空）。
		Ports *string `json:"ports"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请求格式不正确")
		return
	}

	if req.ExpiresIn != nil && (*req.ExpiresIn < 0 || *req.ExpiresIn > model.MaxDurationSeconds) {
		badRequest(c, "有效期超出范围，永久请填写 0")
		return
	}

	entry, err := s.store.GetACL(uint(id))
	if err != nil {
		fail(c, http.StatusNotFound, "条目不存在")
		return
	}

	// 地区条目的范围与端口恒为 all / 空，直接摆正不报错：这个字段对地区条目
	// 本来就没有第二种含义（见 aclScopePorts），而库里的老行、前端漏传、
	// 手工调接口都可能带进来一个与落地方式不符的值。
	if model.IsGeoTargetType(entry.TargetType) {
		entry.Scope, entry.Ports = model.ScopeAll, ""
	} else {
		if req.Scope != nil {
			scope, err := normalizeScope(entry.Kind, *req.Scope)
			if err != nil {
				badRequest(c, err.Error())
				return
			}
			entry.Scope = scope
		}
		// 顺手把库里的老行补正：AutoMigrate 加列前写入的行 scope 可能为空串
		// （NOT NULL 列的 default 不会回头填已有行）。这类行读出来就到 guard 层
		// 才被兜底成 all，留一个空值在库里迟早有人读错，碰上了就改掉。
		if !model.ValidScope(entry.Scope) {
			entry.Scope = model.ScopeAll
		}

		// 端口：没传就沿用库里那份，传了就以传的为准。注意不能只看 req.Ports ——
		// 从 custom 换成 all / frp 的请求通常不带 ports，而这时候**必须**把端口清掉，
		// 否则库里会残留一份不参与生效的端口，界面上看不出来、内核对不上。
		switch {
		case req.Ports != nil:
			ports, err := normalizeScopePorts(entry.Scope, *req.Ports)
			if err != nil {
				badRequest(c, err.Error())
				return
			}
			entry.Ports = ports
		case req.Scope != nil:
			ports, err := normalizeScopePorts(entry.Scope, entry.Ports)
			if err != nil {
				badRequest(c, err.Error())
				return
			}
			entry.Ports = ports
		}
	}

	if req.Remark != nil {
		entry.Remark = *req.Remark
	}
	wasEnabled := entry.Enabled
	if req.Enabled != nil {
		entry.Enabled = *req.Enabled
	}
	switch {
	case req.ExpiresIn == nil:
		// 没传就不动 —— 这是"只改备注"的形状，条目该怎么到期还怎么到期。
	case *req.ExpiresIn > 0:
		t := time.Now().Add(model.SafeSeconds(*req.ExpiresIn))
		entry.ExpiresAt = &t
	default:
		// 显式传 0 才是"改成永久"。
		entry.ExpiresAt = nil
	}

	if err := s.store.UpdateACL(entry); err != nil {
		serverErr(c, err)
		return
	}
	s.refreshGuard()

	// 停用要和删除一个待遇：由这条条目封掉的地址一起放开。不停的话，界面上
	// 那条条目已经"停用"了，被它封的地址却还进不来 —— 与"停用 = 不再生效"
	// 的直觉矛盾，而且用户在名单页看不到任何还封着的依据。
	// 启用方向不用做事：之前被解禁的地址，下次命中会重新封。
	released := 0
	if wasEnabled && !entry.Enabled {
		released = s.releaseBansOfACL(c, entry.ID, "名单条目已停用")
	}

	// 开关本身留痕：解禁那半边 ReleaseBansByRef 会记事件，这里补上动作本身。
	if wasEnabled != entry.Enabled {
		action := "启用"
		if !entry.Enabled {
			action = "停用"
		}
		_ = s.store.AddEvent(&model.Event{
			Category: model.EvtConfig,
			IP:       c.ClientIP(),
			Detail:   fmt.Sprintf("%s%s条目 %s", action, kindLabel(entry.Kind), entry.Target),
			Actor:    s.currentUser(c),
		})
	}

	ok(c, gin.H{"entry": aclViewOf(*entry), "released_bans": released})
}

func (s *Server) handleDeleteACL(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		badRequest(c, "ID 不正确")
		return
	}
	entry, err := s.store.GetACL(uint(id))
	if err != nil {
		fail(c, http.StatusNotFound, "条目不存在")
		return
	}
	if err := s.store.DeleteACL(uint(id)); err != nil {
		serverErr(c, err)
		return
	}
	s.refreshGuard()

	// 联动解禁：被这条条目封掉的地址要一起放开。
	//
	// 少这一步的后果很隐蔽 —— 界面上那条名单已经没了，被它挡在外面的地址却
	// 还挂在封禁列表里，用户既不知道它们为什么进不来，也不知道该点哪几条。
	released := s.releaseBansOfACL(c, entry.ID, "名单条目已删除")

	_ = s.store.AddEvent(&model.Event{
		Category: model.EvtConfig,
		IP:       c.ClientIP(),
		Detail:   fmt.Sprintf("删除%s条目 %s", kindLabel(entry.Kind), entry.Target),
		Actor:    s.currentUser(c),
	})
	ok(c, gin.H{"message": "已删除", "released_bans": released})
}

// releaseBansOfACL 解除由某条名单条目触发的活跃封禁，返回解除的条数。
//
// 失败只记日志、不打断调用方：删条目本身已经成功，因为"解封没做干净"就把
// 整个请求报成失败，会让用户以为条目没删掉而反复重试。
func (s *Server) releaseBansOfACL(c *gin.Context, id uint, why string) int {
	n, err := s.guard.ReleaseBansByRef(
		model.BanSourceRef(model.BanRefACL, id), s.currentUser(c), why)
	if err != nil {
		s.log.Warn("名单条目联动解禁失败", "err", err, "acl_id", id)
		return 0
	}
	return n
}

func (s *Server) handleBatchACL(c *gin.Context) {
	kind := c.Param("kind")
	if !validKind(kind) {
		badRequest(c, "kind 只能是 white 或 black")
		return
	}

	var req struct {
		Action  string   `json:"action"` // add | delete
		IDs     []uint   `json:"ids"`
		Targets []string `json:"targets"`
		// TargetType 是 add 时本批统一的目标类型。留空按 IP/CIDR 逐条推断；
		// 给地区类型时，Targets 里每一条就是一个地区值（"CN" / "广东" / "深圳"）。
		TargetType string `json:"target_type"`
		Scope      string `json:"scope"` // add 时本批统一用的范围，留空按 all
		Ports      string `json:"ports"` // 仅 scope=custom 时有意义
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请求格式不正确")
		return
	}

	switch req.Action {
	case "delete":
		if err := s.store.DeleteACLBatch(req.IDs); err != nil {
			serverErr(c, err)
			return
		}
		// 逐条联动解禁：批量删的每一条都可能封过一批地址，漏掉一条就等于
		// 留了一批"界面上已经没有依据、却还进不来"的地址。
		released := 0
		for _, id := range req.IDs {
			released += s.releaseBansOfACL(c, id, "名单条目已删除")
		}
		s.refreshGuard()
		ok(c, gin.H{"message": "已处理", "released_bans": released})
		return

	case "add":
		scope, ports, err := aclScopePorts(kind, req.TargetType, req.Scope, req.Ports)
		if err != nil {
			badRequest(c, err.Error())
			return
		}
		isGeo := model.IsGeoTargetType(req.TargetType)

		added := 0
		for _, t := range req.Targets {
			target, targetType, err := normalizeACLTarget(t, req.TargetType)
			if err != nil {
				continue
			}
			e := &model.ACLEntry{
				Kind:       kind,
				Target:     target,
				TargetType: targetType,
				Scope:      scope,
				Ports:      ports,
				Source:     model.SourceManual,
				Enabled:    true,
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
			}
			if !isGeo {
				if info := s.geo.LookupString(target); info != nil {
					e.Country = info.Country
					e.Province = info.Province
				}
			}
			if err := s.store.UpsertACL(e); err == nil {
				added++
			}
		}
		ok(c, gin.H{"added": added})
		s.refreshGuard()
		return

	default:
		badRequest(c, "action 只能是 add 或 delete")
		return
	}
}

// handleImportACL 批量导入。每行一个条目，支持以下写法：
//
//	1.2.3.4
//	1.2.3.0/24
//	1.2.3.4 机房备用机
//	1.2.3.4,机房备用机
//	1.2.3.4,frp
//	1.2.3.4,custom:8080;9000-9100
//	1.2.3.4,custom:8080,机房备用机
//	1.2.3.4,frp,机房备用机
//	# 以 # 开头的行为注释
//
// 第二列只有恰好是合法范围写法时才被当作范围，否则整体按备注处理 ——
// 老版本导出的两列文件（地址,备注）因此不需要改一个字节就能重新导入。
// 范围只对黑名单生效，白名单即使写了也会被忽略（恒为 all）。
//
// 自定义端口的端口列表写在范围列里（custom:8080;9000-9100），用分号分隔：
// 逗号是列分隔符，端口列表再用逗号分项会把一列切成两列。
func (s *Server) handleImportACL(c *gin.Context) {
	kind := c.Param("kind")
	if !validKind(kind) {
		badRequest(c, "kind 只能是 white 或 black")
		return
	}

	var req struct {
		Content string `json:"content"`
		DryRun  bool   `json:"dry_run"`
		Scope   string `json:"scope"` // 本批默认范围，行内可覆盖，留空按 all
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请求格式不正确")
		return
	}

	// 默认范围与行内写法共用一套语法，所以它也能带端口（custom:8080;9000-9100）。
	defScope, defPorts := model.ScopeAll, ""
	if v := strings.TrimSpace(req.Scope); v != "" {
		sc, pt, ok := parseScopeField(v)
		if !ok {
			badRequest(c, "默认范围只能是 all / frp，或 custom:端口（例如 custom:8080;9000-9100）")
			return
		}
		defScope, defPorts = sc, pt
	}
	if kind == model.KindWhite {
		defScope, defPorts = model.ScopeAll, ""
	}

	added, skipped := 0, 0
	invalid := make([]string, 0, 8)
	seen := make(map[string]struct{})

	for _, raw := range strings.Split(req.Content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		targetPart, lineScope, linePorts, remark, err := parseImportLine(line, defScope, defPorts)
		if err != nil {
			invalid = append(invalid, line)
			skipped++
			continue
		}
		// 目标列可能带地区前缀（country:CN / province:广东 / city:深圳），
		// 那是导出时写上去的。不带前缀的地区条目导入回来会被当成地址解析、
		// 报"非法的 IP 地址"—— 导出再导入是用户最常走的一条路（留档、换机器），
		// 断了等于地区条目没法备份。
		target, targetType, err := normalizeImportTarget(targetPart)
		if err != nil {
			invalid = append(invalid, line)
			skipped++
			continue
		}
		// 地区条目没有"范围"可言，一律 all + 空端口（见 aclScopePorts）。
		// 行内写了 custom:... 也忽略 —— 那个范围在它身上落不了地。
		if model.IsGeoTargetType(targetType) {
			lineScope, linePorts = model.ScopeAll, ""
		}
		if _, dup := seen[target]; dup {
			skipped++
			continue
		}
		seen[target] = struct{}{}

		if req.DryRun {
			added++
			continue
		}

		e := &model.ACLEntry{
			Kind:       kind,
			Target:     target,
			TargetType: targetType,
			Scope:      lineScope,
			Ports:      linePorts,
			Remark:     remark,
			Source:     model.SourceManual,
			Enabled:    true,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}
		if !model.IsGeoTargetType(targetType) {
			if info := s.geo.LookupString(target); info != nil {
				e.Country = info.Country
				e.Province = info.Province
			}
		}
		if err := s.store.UpsertACL(e); err != nil {
			skipped++
			continue
		}
		added++
	}

	if !req.DryRun && added > 0 {
		s.refreshGuard()
		_ = s.store.AddEvent(&model.Event{
			Category: model.EvtConfig,
			IP:       c.ClientIP(),
			Detail:   fmt.Sprintf("批量导入%s %d 条", kindLabel(kind), added),
			Actor:    s.currentUser(c),
		})
	}

	ok(c, gin.H{
		"added":   added,
		"skipped": skipped,
		"invalid": invalid,
		"dry_run": req.DryRun,
	})
}

func (s *Server) handleExportACL(c *gin.Context) {
	kind := c.Param("kind")
	if !validKind(kind) {
		badRequest(c, "kind 只能是 white 或 black")
		return
	}
	rows, err := s.store.AllACL(kind)
	if err != nil {
		serverErr(c, err)
		return
	}

	var b strings.Builder
	b.WriteString("# frpfirewall " + kindLabel(kind) + " 导出\n")
	b.WriteString("# 生成时间 " + time.Now().Format(time.RFC3339) + "\n")

	if kind == model.KindBlack {
		// 黑名单导出恒带范围一列，即使全是 all：导出文件常被当作"当前配置"
		// 留档或拿去别的机器导入，省掉这一列会让"全端口封禁"这个事实只在
		// 界面上存在、文件里丢失。
		//
		// 自定义端口的端口列表就写在范围列里（custom:8080;9000-9100）。
		// 端口与范围本来就是同一个概念的两面，拆成两列反而要多解释一句
		// "端口那列什么范围下才有意义"，而且逗号既是列分隔符又是端口分隔符，
		// 拆列之后备注列一定会被端口串里的逗号切开。
		b.WriteString("# 格式：地址,范围[,备注]\n")
		b.WriteString("# 范围：all = 封禁该地址到本机的全部端口；frp = 只封 frp 服务端口\n")
		b.WriteString("#       custom:端口 = 只封列出的端口，多个用分号分隔，如 custom:8080;9000-9100\n")
		b.WriteString("# 地区条目写成 country:CN / province:广东 / city:深圳，多个值用分号分隔\n\n")
		for _, r := range rows {
			scope := r.Scope
			if !model.ValidScope(scope) {
				scope = model.ScopeAll
			}
			b.WriteString(renderTargetField(r) + "," + renderScopeField(scope, r.Ports))
			if r.Remark != "" {
				b.WriteString("," + r.Remark)
			}
			b.WriteString("\n")
		}
	} else {
		// 白名单导出不带范围：范围描述的是"封住多少访问"，对豁免列表没有意义。
		b.WriteString("# 格式：地址[,备注]\n")
		b.WriteString("# 地区条目写成 country:CN / province:广东 / city:深圳\n\n")
		for _, r := range rows {
			if r.Remark != "" {
				b.WriteString(renderTargetField(r) + "," + r.Remark + "\n")
			} else {
				b.WriteString(renderTargetField(r) + "\n")
			}
		}
	}

	c.Header("Content-Disposition",
		fmt.Sprintf(`attachment; filename="frpfirewall-%s-%s.txt"`, kind, time.Now().Format("20060102")))
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(b.String()))
}

// ---- 封禁 ----

// handleListBans 走数据库分页，含历史记录。
func (s *Server) handleListBans(c *gin.Context) {
	page, size := pageParams(c)
	res, err := s.store.ListBans(c.Query("status"), c.Query("keyword"), page, size)
	if err != nil {
		serverErr(c, err)
		return
	}
	ok(c, res)
}

// handleActiveBans 直接读内存，返回实时封禁状态（含剩余秒数）。
// handleActiveBans 返回当前生效中的封禁，支持分页。
//
// 分页在内存里切片，不去数据库按同样条件再查一遍：这批条目本来就在 guard 的
// 内存表里（判定用的就是它），从库里查会多出一个窗口 —— 库里已解封、内存还没
// 刷新时，两份列表的条数对不上，用户看到的总数与他刚解封的操作矛盾。
func (s *Server) handleActiveBans(c *gin.Context) {
	bans := s.guard.Bans()
	total := len(bans)

	page, size := pageParams(c)
	start := (page - 1) * size
	if start > total {
		start = total
	}
	end := min(start+size, total)

	items := bans[start:end]
	if items == nil {
		// 空列表必须是 []，不能是 null —— 前端直接读它的 length。
		items = []guard.BanView{}
	}
	ok(c, gin.H{"items": items, "total": total, "page": page, "size": size})
}

func (s *Server) handleCreateBan(c *gin.Context) {
	var req struct {
		Target    string `json:"target"`
		Reason    string `json:"reason"`
		DurationS int64  `json:"duration_sec"` // <=0 表示永久
		Scope     string `json:"scope"`        // all | frp | custom，留空按 all
		Ports     string `json:"ports"`        // 仅 scope=custom 时有意义
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请求格式不正确")
		return
	}

	if req.DurationS < 0 || req.DurationS > model.MaxDurationSeconds {
		badRequest(c, "封禁时长超出范围，永久封禁请填写 0")
		return
	}
	// 这里统一走 normalizeScope：大小写归一、留空补 all 都在同一个地方做，
	// 免得 BanManual 和名单接口对同一个字符串给出两种判断。
	scope, err := normalizeScope(model.KindBlack, req.Scope)
	if err != nil {
		badRequest(c, err.Error())
		return
	}

	var ports portrange.Set
	if model.ScopeNeedsPorts(scope) {
		ports, err = model.ParseCustomPorts(req.Ports)
		if err != nil {
			badRequest(c, err.Error())
			return
		}
	}

	rec, err := s.guard.BanManual(req.Target, req.Reason, s.currentUser(c),
		model.SafeSeconds(req.DurationS), scope, ports)
	if err != nil {
		badRequest(c, err.Error())
		return
	}
	ok(c, rec)
}

func (s *Server) handleDeleteBan(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		badRequest(c, "ID 不正确")
		return
	}
	// 先把记录取出来：解封之后内存里那份就没了，来源引用也就查不到了。
	rec, err := s.store.GetBan(uint(id))
	if err != nil {
		fail(c, http.StatusNotFound, "封禁记录不存在")
		return
	}

	user := s.currentUser(c)
	if err := s.guard.UnbanByRecordID(uint(id), user); err != nil {
		badRequest(c, err.Error())
		return
	}

	// 计数形式，和批量解封那个接口同一个口径（单条只可能是 0 或 1）。
	// 一个接口给布尔、另一个给数字的话，前端得为同一个字段写两种判断。
	cleared := 0
	if s.clearBanSourceEntry(c, rec.SourceRef, rec.Target, user) {
		cleared = 1
	}
	ok(c, gin.H{"message": "已解封", "source_entry_removed": cleared})
}

// clearBanSourceEntry 手动解封之后，把"把它挡在外面"的那条名单条目一并清掉。
//
// 为什么需要：某个地址因为命中一条黑名单条目被封，用户点解封 —— 解封当场生效，
// 但它下一次连接又会命中同一条条目、立刻再被封一次。用户看到的是"解封没起作用"，
// 而他的真实意图显然是"让这个地址进来"，所以顺手清掉那条条目才符合预期。
//
// 两道边界：
//   - **条目的 Target 必须精确等于被封的地址。** 条目是个网段（1.2.3.0/24）时，
//     删掉它等于顺手放行另外 255 个地址，那超出了用户点这一次解封的授权范围；
//     这种情况只解封、不动条目。
//   - **只管名单条目**。规则（rule:*）是条件型的（"来自某地区的一律拦"），
//     没法从中"移除一个地址"，强行动作只会把整条规则改坏，所以只记一笔事件，
//     让用户自己决定要不要调整规则。
//
// 返回是否真的删掉了条目。
func (s *Server) clearBanSourceEntry(c *gin.Context, ref, target, user string) bool {
	// 先按类型分岔，再去解析 ID。
	//
	// 顺序反过来的话，"规则引用"这一支永远不会被执行到：规则引用里的标识是
	// 十六进制内容签名，ParseBanSourceRef 解析不出十进制 ID、直接返回 ok=false，
	// 于是整段在这里就退出了 —— 用户解封一个"被规则一直拦着"的地址，什么提示
	// 都看不到，只会发现解禁之后又被拦回来。
	switch model.BanSourceRefKind(ref) {
	case model.BanRefRule:
		_ = s.store.AddEvent(&model.Event{
			Category: model.EvtUnban,
			IP:       target,
			Detail:   "该地址由细分规则拦截：解封后若规则仍启用，下次连接会再次命中，请按需调整规则",
			Actor:    user,
		})
		return false
	case model.BanRefACL:
		// 继续往下走，需要 entry id
	default:
		// 没有来源引用（频次自动封禁、全局地域名单、人工封禁）或者类型不认识。
		return false
	}

	// 到这一步类型已经确定是名单条目，只差把主键取出来。
	// 解析失败只可能是引用被写坏了，跳过联动处理、别去碰任何条目。
	if _, id, ok := model.ParseBanSourceRef(ref); ok {
		if s.releaseBanByACLID(c, id, target, user) {
			return true
		}
	}
	return false
}

// releaseBanByACLID 是"解封时清理背后那条名单条目"的实际动作。
//
// 单独拆出来只为让 clearBanSourceEntry 的分岔逻辑一眼看得完：那里全是
// "哪些情况不该动"的判断，真正的删除动作混在同一段里，很容易把某个
// 早退条件连同删除一起漏掉。
func (s *Server) releaseBanByACLID(c *gin.Context, id uint, target, user string) bool {
	entry, err := s.store.GetACL(id)
	if err != nil {
		// 条目可能已经被删了（比如刚在名单页删掉），这不是错误。
		return false
	}
	if !sameTarget(entry.Target, target) {
		return false
	}
	if err := s.store.DeleteACL(id); err != nil {
		s.log.Warn("解封时清理名单条目失败", "err", err, "acl_id", id)
		return false
	}
	s.refreshGuard()

	_ = s.store.AddEvent(&model.Event{
		Category: model.EvtConfig,
		IP:       c.ClientIP(),
		Detail: fmt.Sprintf("解封 %s 时一并移除%s条目 %s（它是该地址被拦的原因，留着会再次拦下它）",
			target, kindLabel(entry.Kind), entry.Target),
		Actor: user,
	})
	return true
}

// sameTarget 判断两个目标是不是同一个地址/网段。
//
// 不能直接比字符串：封禁记录里的 Target 来自 banPrefix，按封禁粒度可能写成
// "1.2.3.0/24" 甚至带 /32；而名单条目里存的是裸 IP。两者字面不同、指的却是
// 同一件事，直接比字符串会让"同一个地址"被误判成不同，于是该清的条目清不掉。
func sameTarget(a, b string) bool {
	na, ok1 := canonicalTarget(a)
	nb, ok2 := canonicalTarget(b)
	return ok1 && ok2 && na == nb
}

// canonicalTarget 把目标统一成前缀形态（裸 IP 补成 /32 或 /128）。
func canonicalTarget(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked().String(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()).String(), true
	}
	return "", false
}

func (s *Server) handleBatchDeleteBan(c *gin.Context) {
	var req struct {
		IDs []uint `json:"ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请求格式不正确")
		return
	}

	user := s.currentUser(c)
	success, failed, cleared := 0, 0, 0
	errs := make([]string, 0, 4)

	for _, id := range req.IDs {
		// 逐条先把记录取出来：解封之后内存里那份就没了，来源引用也就查不到了。
		rec, err := s.store.GetBan(id)
		if err != nil {
			failed++
			if len(errs) < 4 {
				errs = append(errs, fmt.Sprintf("#%d: 封禁记录不存在", id))
			}
			continue
		}
		if err := s.guard.UnbanByRecordID(id, user); err != nil {
			failed++
			if len(errs) < 4 {
				errs = append(errs, fmt.Sprintf("#%d: %s", id, err.Error()))
			}
			continue
		}
		if s.clearBanSourceEntry(c, rec.SourceRef, rec.Target, user) {
			cleared++
		}
		success++
	}
	ok(c, gin.H{"success": success, "failed": failed, "errors": errs, "source_entry_removed": cleared})
}

// handleLookupIP 排障用：查一个 IP 当前处于什么状态。
func (s *Server) handleLookupIP(c *gin.Context) {
	var req struct {
		Target string `json:"target"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请求格式不正确")
		return
	}
	ok(c, s.guard.Lookup(req.Target))
}

// ---- 策略 ----

func (s *Server) handleGetPolicy(c *gin.Context) {
	p, err := s.store.GetPolicy()
	if err != nil {
		serverErr(c, err)
		return
	}
	ok(c, p)
}

func (s *Server) handleUpdatePolicy(c *gin.Context) {
	var req policyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请求格式不正确")
		return
	}
	p := req.Policy

	// 校验关键字段，避免把系统配置成"谁都连不上"或"谁都拦不住"
	if p.WindowSeconds < 1 || p.WindowSeconds > 86400 {
		badRequest(c, "统计窗口需在 1 ~ 86400 秒之间")
		return
	}
	if p.Threshold < 1 || p.Threshold > 100000 {
		badRequest(c, "触发阈值需在 1 ~ 100000 之间")
		return
	}
	if p.EscalateWindowHours > 24*30 {
		badRequest(c, "升级窗口最多 720 小时")
		return
	}
	if p.EscalateWindowHours < 1 {
		p.EscalateWindowHours = 24
	}
	switch p.BanGranularity {
	case "ip", "cidr24":
	default:
		badRequest(c, "封禁粒度只能是 ip 或 cidr24")
		return
	}
	switch p.FailMode {
	case "open", "close":
	default:
		badRequest(c, "fail_mode 只能是 open 或 close")
		return
	}
	switch p.GeoIPMode {
	case "blacklist", "whitelist":
	default:
		badRequest(c, "地域模式只能是 blacklist 或 whitelist")
		return
	}

	steps, stepsErr := model.ParseDurationSteps(p.BanDurations)
	if stepsErr != nil {
		badRequest(c, stepsErr.Error())
		return
	}
	if len(steps) == 0 {
		badRequest(c, "阶梯封禁时长不能为空")
		return
	}
	for _, v := range steps {
		if v < 0 {
			badRequest(c, "阶梯时长不能为负数")
			return
		}
	}
	if p.RateLimitEnabled {
		if p.RateLimitPerSec < 1 || p.RateLimitPerSec > 1000000 || p.RateLimitBurst > 2000000 {
			badRequest(c, "速率限制必须大于 0")
			return
		}
		if p.RateLimitBurst < 1 {
			p.RateLimitBurst = p.RateLimitPerSec * 2
		}
	}

	// 国家码规范化
	p.GeoIPBlockCountries = model.PackageCountries(p.CountryList())

	// 细分规则：带了就一起校验、一起落盘，没带就完全不碰。
	//
	// 校验放在落盘之前，是为了让"某条规则写错了"变成一次明确的 400，
	// 而不是先存一半再报错。
	var rules []model.RateRule
	if req.Rules != nil {
		var err error
		if rules, err = normalizeRateRules(*req.Rules); err != nil {
			badRequest(c, err.Error())
			return
		}
	}

	if req.Rules != nil {
		// 先记下旧规则的「封禁依据」签名，保存之后拿它和新集合作差。
		//
		// 差集里的就是"依据已经消失"的那些规则 —— 被删掉的、被停用的、条件
		// 被改动过的，三种情况一并覆盖；由它们封掉的地址要跟着解封，否则界面上
		// 那条规则已经改了甚至没了，被它挡在外面的地址却还进不来。
		//
		// 对比用**内容签名**而不是规则 ID：rate_rules 是整体替换的，ID 每次
		// 保存都会变（见 model.RateRule.BanRef），拿 ID 比会得出满屏的假差集。
		oldRows, err := s.store.RateRules()
		if err != nil {
			serverErr(c, err)
			return
		}
		oldRefs := model.RateRuleBanRefs(oldRows)

		if err := s.store.SavePolicyWithRules(&p, rules); err != nil {
			serverErr(c, err)
			return
		}

		newRefs := model.RateRuleBanRefs(rules)
		for ref := range oldRefs {
			if newRefs[ref] {
				continue
			}
			// 解禁失败不打断保存：规则本身已经落盘了，因为联动解禁出错就报
			// "保存失败"，会让用户以为规则没存进去而反复重试。
			if _, err := s.guard.ReleaseBansByRef(ref, s.currentUser(c),
				"细分规则已删除、停用或改动"); err != nil {
				s.log.Warn("规则改动联动解禁失败", "err", err, "ref", ref)
			}
		}
	} else if err := s.store.SavePolicy(&p); err != nil {
		serverErr(c, err)
		return
	}

	if err := s.guard.Refresh(); err != nil {
		serverErr(c, err)
		return
	}
	s.guard.Apply()

	detail := fmt.Sprintf("更新策略：窗口 %ds / 阈值 %d 次 / 阶梯 %v", p.WindowSeconds, p.Threshold, steps)
	if req.Rules != nil {
		detail += fmt.Sprintf(" / 细分规则 %d 条", len(rules))
	}
	_ = s.store.AddEvent(&model.Event{
		Category: model.EvtConfig,
		IP:       c.ClientIP(),
		Detail:   detail,
		Actor:    s.currentUser(c),
	})

	saved, _ := s.store.GetPolicy()
	ok(c, saved)
}

// ---- GeoIP ----

func (s *Server) handleGeoLookup(c *gin.Context) {
	var req struct {
		IP string `json:"ip"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请求格式不正确")
		return
	}

	info := s.geo.LookupString(req.IP)
	state := s.guard.Lookup(strings.TrimSpace(req.IP))

	ok(c, gin.H{"geoip": info, "state": state})
}

func (s *Server) handleGeoLookupBatch(c *gin.Context) {
	var req struct {
		IPs []string `json:"ips"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请求格式不正确")
		return
	}
	if len(req.IPs) > 200 {
		badRequest(c, "单次最多查询 200 个 IP")
		return
	}

	out := make([]*geoip.Info, 0, len(req.IPs))
	for _, ip := range req.IPs {
		out = append(out, s.geo.LookupString(ip))
	}
	ok(c, out)
}

func (s *Server) handleGeoStatus(c *gin.Context) {
	ok(c, s.geo.Status())
}

func (s *Server) handleGeoUpload(c *gin.Context) {
	name := c.PostForm("name")
	if name == "" {
		name = c.Query("name")
	}
	if name == "" {
		badRequest(c, "缺少 name 字段（"+geoip.FileCountry+" / "+geoip.FileCity+" / "+geoip.FileRegion+"）")
		return
	}

	fh, err := c.FormFile("file")
	if err != nil {
		badRequest(c, "缺少 file 字段: "+err.Error())
		return
	}
	if fh.Size > 200<<20 {
		badRequest(c, "文件过大，上限 200MB")
		return
	}

	f, err := fh.Open()
	if err != nil {
		serverErr(c, err)
		return
	}
	defer f.Close()

	if err := s.geo.SaveUpload(name, f); err != nil {
		badRequest(c, err.Error())
		return
	}

	_ = s.store.AddEvent(&model.Event{
		Category: model.EvtGeoIP,
		IP:       c.ClientIP(),
		Detail:   "上传属地数据库 " + name,
		Actor:    s.currentUser(c),
	})

	ok(c, gin.H{"message": "已更新", "status": s.geo.Status()})
}

func (s *Server) handleGeoCountries(c *gin.Context) {
	ok(c, gin.H{
		"countries": geoip.Countries(),
		"available": s.geo.CountryBlockAvailable(),
		"status":    s.geo.Status(),
	})
}

// ---- 辅助 ----

// normalizeTargetString 规范化并校验 IP/CIDR 输入。
func normalizeTargetString(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("地址不能为空")
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return "", fmt.Errorf("非法的 CIDR：%s", s)
		}
		return p.Masked().String(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", fmt.Errorf("非法的 IP 地址：%s", s)
	}
	return a.String(), nil
}

// normalizeACLTarget 归一化名单条目的目标，返回入库文本与目标类型。
//
// 两条路径：targetType 是地区类型时按地区口径处理（国家码 / 省份 / 城市），
// 否则一律按 IP/CIDR 处理 —— 老客户端不传 targetType，走的也是这条路，
// 所以这里不能要求它必填。
//
// 返回的 target 就是入库形态：IP 条目是规范化后的地址，地区条目是归一化后
// 的逗号分隔地名（例如 "CN,US" / "广东,福建" / "深圳"）。
func normalizeACLTarget(raw, targetType string) (target, tt string, err error) {
	targetType = strings.TrimSpace(targetType)

	if model.IsGeoTargetType(targetType) {
		list, err := model.NormalizeGeoTarget(targetType, raw)
		if err != nil {
			return "", "", err
		}
		return list, targetType, nil
	}

	// 传了具体的 IP 类型但内容不是地址时，也让 normalizeTargetString 去报错 ——
	// 它给出的原因（"非法的 CIDR" / "非法的 IP 地址"）比"类型不匹配"更好懂。
	t, err := normalizeTargetString(raw)
	if err != nil {
		return "", "", err
	}
	return t, model.TargetTypeOf(t), nil
}

// aclScopePorts 决定一个条目的范围与端口。
//
// 地区条目恒为 all + 空端口：它命中之后的落地方式是"把这个具体 IP 全端口
// 封掉"，内核里根本没有"地区"这个对象，也就不存在一条可以被限定到某几个
// 端口的规则。强制写成 all/空，是为了别在库里留下一句"标着 frp、实际全端口"
// 的谎话 —— 那种不一致在界面上完全看不出来，只有去数内核规则才会发现对不上。
func aclScopePorts(kind, targetType, reqScope, reqPorts string) (scope, ports string, err error) {
	if model.IsGeoTargetType(targetType) {
		return model.ScopeAll, "", nil
	}
	scope, err = normalizeScope(kind, reqScope)
	if err != nil {
		return "", "", err
	}
	ports, err = normalizeScopePorts(scope, reqPorts)
	if err != nil {
		return "", "", err
	}
	return scope, ports, nil
}

// normalizeScope 校验并归一化封禁范围。
//
// 范围只对黑名单有意义：白名单描述的是"豁免谁"，条目本身不产生任何封禁动作，
// 所以白名单恒返回 all，传进来的值直接忽略（前端也不该传）。这样即使有人
// 手工调接口给白名单塞了个 frp，也不会在库里留下一句读不懂也没用途的话。
func normalizeScope(kind, scope string) (string, error) {
	if kind == model.KindWhite {
		return model.ScopeAll, nil
	}
	scope = strings.ToLower(strings.TrimSpace(scope))
	if scope == "" {
		// 留空按全端口。这是"存量行为不变"的保证点：升级上来的老客户端
		// 不带 scope 字段，语义必须和以前完全一致。
		return model.ScopeAll, nil
	}
	if !model.ValidScope(scope) {
		return "", fmt.Errorf(
			"封禁范围只能是 all（封禁全部端口）、frp（只封 frp 服务端口）或 custom（自定义端口）")
	}
	return scope, nil
}

// normalizeScopePorts 校验并归一化条目的端口字段，返回入库用的规范文本。
//
// 非自定义范围一律返回空串：把这些端口留在库里会对不上内核规则，而界面上
// 完全看不出来（列表里它还显示着那条范围）。要留就留在前端表单里。
func normalizeScopePorts(scope, ports string) (string, error) {
	if !model.ScopeNeedsPorts(scope) {
		return "", nil
	}
	ps, err := model.ParseCustomPorts(ports)
	if err != nil {
		return "", err
	}
	return ps.String(), nil
}

// scopeFieldPrefix 是"自定义端口"在范围列里的写法前缀，后面跟端口列表。
const scopeFieldPrefix = "custom"

// parseScopeField 解析范围列，支持 all / frp / custom:端口。
//
// 自定义端口的端口列表写在同一个字段里（custom:8080;9000-9100），而不是新开一列：
// 逗号既是列分隔符、又是端口列表的分隔符，新开一列之后备注列一定会被端口串
// 切开 —— 这种错在读文件时看不出来，只有导入之后发现备注少了一半才知道。
//
// 只写 "custom" 不带端口时返回 false（整体按备注处理）：范围是自定义却没有端口，
// 内核一条规则都生成不出来，而导入结果里它会显示成一条生效中的条目。
//
// 返回的端口是**入库口径**（逗号分隔），不是文件口径（分号）—— 只有
// renderScopeField 在往文件里写的那一刻才换成分号。导入的两条路径（默认范围、
// 行内覆盖）拿到的必须是同一种文本，否则同一个导入动作会因为"范围写在哪里"
// 而落库成两种格式；而且这里的返回值会一路写进 model.ACLEntry.Ports，
// 换个分隔符就等于库里凭空出现第二种方言。
func parseScopeField(s string) (scope, ports string, ok bool) {
	v := strings.ToLower(strings.TrimSpace(s))
	switch v {
	case model.ScopeAll, model.ScopeFrp:
		return v, "", true
	}
	if !strings.HasPrefix(v, scopeFieldPrefix) {
		return "", "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(v, scopeFieldPrefix))
	if !strings.HasPrefix(rest, ":") {
		return "", "", false
	}
	ps, err := portrange.Parse(strings.TrimPrefix(rest, ":"))
	if err != nil || len(ps) == 0 {
		return "", "", false
	}
	return model.ScopeCustom, ps.String(), true
}

// renderScopeField 把范围与端口渲染成导出文件里那一列。
//
// 这里用分号分隔端口，而不是入库口径的逗号：逗号是列分隔符，端口串里再出现
// 逗号就会把后面的备注列切走。所以"文件里用分号、库里用逗号"这层转换是必须的，
// 而且只允许发生在导出/导入这两端。
//
// 库里被手工改坏的行（范围是自定义但没有可用端口）退化成 all 导出，
// 与 guard 的兜底方向一致：宁可让导入方看到"全端口"这个更严的范围，
// 也不要导出一句它解析不了、只能当备注的话。
func renderScopeField(scope, ports string) string {
	if !model.ScopeNeedsPorts(scope) {
		return scope
	}
	ps, err := portrange.Parse(ports)
	if err != nil || len(ps) == 0 {
		return model.ScopeAll
	}
	return scopeFieldPrefix + ":" + ps.StringSep(";")
}

// geoFieldPrefix 返回地区类型在导出文件里的前缀写法。
//
// 另给一个函数、而不是直接写 map：前缀与类型的对应关系只在这一处，导出（写）
// 与导入（读）都从这里拿，两边不会各写一套而慢慢走岔。
func geoFieldPrefix(targetType string) string {
	switch targetType {
	case model.TargetGeoCountry:
		return "country"
	case model.TargetGeoProvince:
		return "province"
	case model.TargetGeoCity:
		return "city"
	}
	return ""
}

// geoTargetTypeOfPrefix 是 geoFieldPrefix 的逆运算。
//
// 同时认 "country" 与 "geo_country" 两种写法：前者是给用户看/手写的短形态，
// 后者直接就是内部的类型常量（接口调用方会见到它）。多认一种写法的代价只是
// 多一个 case，而少认一种的表现是"文件明明照着类型名写的却导入不了"。
func geoTargetTypeOfPrefix(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "country", model.TargetGeoCountry:
		return model.TargetGeoCountry
	case "province", model.TargetGeoProvince:
		return model.TargetGeoProvince
	case "city", model.TargetGeoCity:
		return model.TargetGeoCity
	}
	return ""
}

// renderTargetField 把条目的目标渲染成导出文件里那一列。
//
// IP / CIDR 条目原样输出；地区条目带上类型前缀（country:CN / province:广东 /
// city:深圳）。**前缀不是装饰**：导出文件是拿来重新导入的（留档、换机器），
// 不带前缀的"CN"、"深圳"在导入端只能被当成地址解析、报"非法的 IP 地址" ——
// 那等于地区条目根本没法备份。
//
// 多值用分号分隔，理由与范围列里的端口列表完全一样：逗号是列分隔符。
func renderTargetField(r model.ACLEntry) string {
	prefix := geoFieldPrefix(r.TargetType)
	if prefix == "" {
		return r.Target
	}
	values := splitGeoTarget(r.Target)
	if len(values) == 0 {
		// 库里被手工改坏的地区条目（类型标着地区、值却是空的）。返回带前缀的
		// 空串比返回裸空列好：至少导入方能看到"这条本来是地区条目"，而不是
		// 平白多出一行解析不了的空地址。
		return prefix + ":"
	}
	return prefix + ":" + strings.Join(values, ";")
}

// splitGeoTarget 把入库形态（逗号分隔）的地区值切成列表。
//
// 逗号、分号、中文标点都认：入库形态只可能是逗号（NormalizeGeoTarget 的产物），
// 但这行的输入也可能来自界面表单或手工改过的库，多认几个分隔符不会误伤 ——
// 地名里不可能出现这些字符。
func splitGeoTarget(s string) []string {
	out := make([]string, 0, 4)
	f := func(r rune) bool {
		switch r {
		case ',', '，', ';', '；':
			return true
		}
		return false
	}
	for _, v := range strings.FieldsFunc(s, f) {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// cutGeoPrefix 把 "country:CN" 拆成前缀与值。
//
// 找不到冒号返回 ok=false。冒号在 IPv6 里到处都是（2001:db8::1），所以这里
// **只负责拆**，是不是真的地区前缀由调用方拿 geoTargetTypeOfPrefix 判断 ——
// 拆出来的前缀不是已知地区类型时按地址走。
func cutGeoPrefix(s string) (prefix, rest string, ok bool) {
	i := strings.Index(s, ":")
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
}

// normalizeImportTarget 解析导入文件里的一列目标，返回入库文本与目标类型。
//
// 与 normalizeACLTarget 的差别只在"类型信息从哪来"：接口调用方有独立的
// target_type 字段，而导入文件的类型只能写在目标里（country:CN）。老文件里
// 全是裸地址、没有任何前缀，所以**无前缀一律按地址处理** —— 老导出的文件
// 必须不改一个字节就能导入（与 parseImportLine 对第二列的宽容同一个理由）。
//
// 带前缀但值非法时**不回落成按地址解析**：那样只会让人看到"非法的 IP 地址"，
// 而真正的问题是省份/国家码写错了，报错得指向真正的原因。
//
// 已知边界：切列时空格也是分隔符（见 cutLine），所以 "city:New York" 会在
// 空格处被切开。国内城市名没有空格，这是"国内城市为主"口径下可接受的代价。
func normalizeImportTarget(s string) (target, tt string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", fmt.Errorf("目标不能为空")
	}
	prefix, rest, ok := cutGeoPrefix(s)
	if !ok {
		t, err := normalizeTargetString(s)
		if err != nil {
			return "", "", err
		}
		return t, model.TargetTypeOf(t), nil
	}
	tt = geoTargetTypeOfPrefix(prefix)
	if tt == "" {
		// 形如 xxx:yyy 但不是已知地区前缀 —— 多半是 IPv6。交给地址解析判断，
		// 它给的报错（"非法的 CIDR" / "非法的 IP 地址"）比"未知的地区类型"
		// 更贴近真实情况。
		t, err := normalizeTargetString(s)
		if err != nil {
			return "", "", err
		}
		return t, model.TargetTypeOf(t), nil
	}
	list, err := model.NormalizeGeoTarget(tt, rest)
	if err != nil {
		return "", "", err
	}
	return list, tt, nil
}

// parseImportLine 解析批量导入的一行，返回地址、封禁范围、端口、备注。
//
// 支持下面几种写法（分隔符可以是 逗号 / 中文逗号 / Tab / 空格）：
//
//	1.2.3.4                      → 范围取默认，无备注
//	1.2.3.4,frp                  → 只封 frp 端口
//	1.2.3.4,custom:8080;9000-9100 → 只封这几个端口
//	1.2.3.4,备注                  → 范围取默认
//	1.2.3.4,custom:8080,备注      → 只封 8080，带备注
//
// 关键点是第二段**只有恰好是合法范围写法时才当作范围**，否则整段按备注处理。
// 这样老版本导出的两列文件（地址,备注）不用改一个字节就能重新导入 —— 导出
// 文件常被留档、拿去别的机器用，格式一旦不兼容就是实打实的数据损失。
// 代价是备注恰好写成 "all" / "frp" 时会被误认成范围，这是刻意接受的取舍。
//
// 行内范围一旦生效，端口就跟着行内那份走：默认范围带的端口不会残留下来
// （默认是 custom:8080、这一行写 frp 时，端口必须是空的）。
//
// 返回值里的端口恒为入库口径（逗号），**不是**文件口径（分号）——这个函数对外
// 只能有一个口径，否则同一个导入动作会因为"范围写在哪一列"而落库成两种写法。
func parseImportLine(line, defScope, defPorts string) (target, scope, ports, remark string, err error) {
	// 默认范围与端口先过一遍归一化，不能原样相信调用方传来的文本：
	// 它可能来自界面表单（文件口径的分号），也可能来自库里被手工改坏的行。
	scope, ports = defScope, defPorts
	switch {
	case !model.ValidScope(scope):
		// 非法范围回落 all，绝不回落 frp：漏封比多封难发现得多
		scope, ports = model.ScopeAll, ""
	case !model.ScopeNeedsPorts(scope):
		// 非自定义范围上一律不带端口，与 normalizeScopePorts 同口径
		ports = ""
	default:
		ps, perr := model.ParseCustomPorts(ports)
		if perr != nil {
			// 自定义却没有可用端口 → 回落 all：这样的条目在内核里一条规则
			// 都生成不出来，留着只会显示成"生效中"
			scope, ports = model.ScopeAll, ""
		} else {
			ports = ps.String()
		}
	}

	head, rest := cutLine(line)
	if head == "" {
		return "", "", "", "", fmt.Errorf("地址为空")
	}
	target = head
	if rest == "" {
		return target, scope, ports, "", nil
	}

	// 第二段单独切一次：是范围就吃掉它，剩下的当备注；不是范围就整段当备注。
	second, tail := cutLine(rest)
	if sc, pt, ok := parseScopeField(second); ok {
		scope, ports = sc, pt
		remark = tail
	} else {
		// 备注里带逗号/空格是常态，这里必须原样保留（不能按分隔符切开再拼回去）
		remark = rest
	}
	return target, scope, ports, remark, nil
}

// cutLine 按第一个分隔符把一行切两段，前后各自 TrimSpace。
//
// 必须按 rune 推进而不是按字节：中文逗号是全角字符，UTF-8 占 3 字节，
// 用 s[i+1:] 只会跳掉一个续字节，剩下两字节脏数据混进备注里 ——
// 而中文逗号恰恰是最常用的分隔符。
func cutLine(s string) (head, rest string) {
	for i, r := range s {
		if r == ',' || r == '，' || r == '\t' || r == ' ' {
			return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+utf8.RuneLen(r):])
		}
	}
	return strings.TrimSpace(s), ""
}

func kindLabel(kind string) string {
	if kind == model.KindWhite {
		return "白名单"
	}
	return "黑名单"
}

// refreshGuard 名单变更后重载并把新状态同步到防火墙。
func (s *Server) refreshGuard() {
	if err := s.guard.Refresh(); err != nil {
		s.log.Warn("重载名单失败", "err", err)
		return
	}
	s.guard.Apply()
}
