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
	"github.com/dreamstation625/FrpFireWall/internal/model"
)

// ---- 黑白名单 ----

func validKind(kind string) bool {
	return kind == model.KindWhite || kind == model.KindBlack
}

func (s *Server) handleListACL(c *gin.Context) {
	kind := c.Param("kind")
	if !validKind(kind) {
		badRequest(c, "kind 只能是 white 或 black")
		return
	}
	page, size := pageParams(c)

	res, err := s.store.ListACL(kind, c.Query("keyword"), page, size)
	if err != nil {
		serverErr(c, err)
		return
	}
	ok(c, res)
}

func (s *Server) handleCreateACL(c *gin.Context) {
	kind := c.Param("kind")
	if !validKind(kind) {
		badRequest(c, "kind 只能是 white 或 black")
		return
	}

	var req struct {
		Target    string `json:"target"`
		Remark    string `json:"remark"`
		ExpiresIn int64  `json:"expires_in_sec"` // <=0 表示永久
		Scope     string `json:"scope"`          // all | frp，留空按 all
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请求格式不正确")
		return
	}

	target, err := normalizeTargetString(req.Target)
	if err != nil {
		badRequest(c, err.Error())
		return
	}

	scope, err := normalizeScope(kind, req.Scope)
	if err != nil {
		badRequest(c, err.Error())
		return
	}

	entry := &model.ACLEntry{
		Kind:       kind,
		Target:     target,
		TargetType: model.TargetTypeOf(target),
		Scope:      scope,
		Remark:     req.Remark,
		Source:     model.SourceManual,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if req.ExpiresIn > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresIn) * time.Second)
		entry.ExpiresAt = &t
	}

	// 顺带把属地填上，列表里直接能看到来源
	if info := s.geo.LookupString(target); info != nil {
		entry.Country = info.Country
		entry.Province = info.Province
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
		Remark    string `json:"remark"`
		ExpiresIn int64  `json:"expires_in_sec"`
		// Scope 用指针是为了区分"没传"和"传了空串"。
		//
		// 用普通 string 会有个很隐蔽的坑：只改备注的请求不带 scope 字段，
		// 绑定出来就是 ""，归一化后变成 all，等于把一条 frp 范围的条目
		// 偷偷放宽成"封全部端口"——连 SSH 一起挡。改个备注不该有这种副作用。
		// 所以 nil 表示保持原值，非 nil 才覆盖。
		Scope *string `json:"scope"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请求格式不正确")
		return
	}

	entry, err := s.store.GetACL(uint(id))
	if err != nil {
		fail(c, http.StatusNotFound, "条目不存在")
		return
	}

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

	entry.Remark = req.Remark
	if req.ExpiresIn > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresIn) * time.Second)
		entry.ExpiresAt = &t
	} else {
		entry.ExpiresAt = nil
	}

	if err := s.store.UpdateACL(entry); err != nil {
		serverErr(c, err)
		return
	}
	s.refreshGuard()
	ok(c, entry)
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

	_ = s.store.AddEvent(&model.Event{
		Category: model.EvtConfig,
		IP:       c.ClientIP(),
		Detail:   fmt.Sprintf("删除%s条目 %s", kindLabel(entry.Kind), entry.Target),
		Actor:    s.currentUser(c),
	})
	ok(c, gin.H{"message": "已删除"})
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
		Scope   string   `json:"scope"` // add 时本批统一用的范围，留空按 all
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请求格式不正确")
		return
	}

	scope, err := normalizeScope(kind, req.Scope)
	if err != nil {
		badRequest(c, err.Error())
		return
	}

	switch req.Action {
	case "delete":
		if err := s.store.DeleteACLBatch(req.IDs); err != nil {
			serverErr(c, err)
			return
		}
	case "add":
		added := 0
		for _, t := range req.Targets {
			target, err := normalizeTargetString(t)
			if err != nil {
				continue
			}
			e := &model.ACLEntry{
				Kind:       kind,
				Target:     target,
				TargetType: model.TargetTypeOf(target),
				Scope:      scope,
				Source:     model.SourceManual,
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
			}
			if info := s.geo.LookupString(target); info != nil {
				e.Country = info.Country
				e.Province = info.Province
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

	s.refreshGuard()
	ok(c, gin.H{"message": "已处理"})
}

// handleImportACL 批量导入。每行一个条目，支持以下写法：
//
//	1.2.3.4
//	1.2.3.0/24
//	1.2.3.4 机房备用机
//	1.2.3.4,机房备用机
//	1.2.3.4,frp
//	1.2.3.4,frp,机房备用机
//	# 以 # 开头的行为注释
//
// 第二列只有恰好是 all / frp 时才被当作封禁范围，否则整体按备注处理 ——
// 老版本导出的两列文件（地址,备注）因此不需要改一个字节就能重新导入。
// 范围只对黑名单生效，白名单即使写了也会被忽略（恒为 all）。
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

	defScope, err := normalizeScope(kind, req.Scope)
	if err != nil {
		badRequest(c, err.Error())
		return
	}

	added, skipped := 0, 0
	invalid := make([]string, 0, 8)
	seen := make(map[string]struct{})

	for _, raw := range strings.Split(req.Content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		targetPart, lineScope, remark, err := parseImportLine(line, defScope)
		if err != nil {
			invalid = append(invalid, line)
			skipped++
			continue
		}
		target, err := normalizeTargetString(targetPart)
		if err != nil {
			invalid = append(invalid, line)
			skipped++
			continue
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
			TargetType: model.TargetTypeOf(target),
			Scope:      lineScope,
			Remark:     remark,
			Source:     model.SourceManual,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}
		if info := s.geo.LookupString(target); info != nil {
			e.Country = info.Country
			e.Province = info.Province
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
		b.WriteString("# 格式：地址,范围,备注\n")
		b.WriteString("# 范围：all = 封禁该地址到本机的全部端口；frp = 只封 frp 服务端口\n\n")
		for _, r := range rows {
			scope := r.Scope
			if !model.ValidScope(scope) {
				scope = model.ScopeAll
			}
			b.WriteString(r.Target + "," + scope)
			if r.Remark != "" {
				b.WriteString("," + r.Remark)
			}
			b.WriteString("\n")
		}
	} else {
		// 白名单导出不带范围：范围描述的是"封住多少访问"，对豁免列表没有意义。
		b.WriteString("# 格式：地址[,备注]\n\n")
		for _, r := range rows {
			if r.Remark != "" {
				b.WriteString(r.Target + "," + r.Remark + "\n")
			} else {
				b.WriteString(r.Target + "\n")
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
func (s *Server) handleActiveBans(c *gin.Context) {
	ok(c, gin.H{
		"items": s.guard.Bans(),
		"total": len(s.guard.Bans()),
	})
}

func (s *Server) handleCreateBan(c *gin.Context) {
	var req struct {
		Target    string `json:"target"`
		Reason    string `json:"reason"`
		DurationS int64  `json:"duration_sec"` // <=0 表示永久
		Scope     string `json:"scope"`        // all | frp，留空按 all
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请求格式不正确")
		return
	}

	// 这里统一走 normalizeScope：大小写归一、留空补 all 都在同一个地方做，
	// 免得 BanManual 和名单接口对同一个字符串给出两种判断。
	scope, err := normalizeScope(model.KindBlack, req.Scope)
	if err != nil {
		badRequest(c, err.Error())
		return
	}

	rec, err := s.guard.BanManual(req.Target, req.Reason, s.currentUser(c),
		time.Duration(req.DurationS)*time.Second, scope)
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
	if err := s.guard.UnbanByRecordID(uint(id), s.currentUser(c)); err != nil {
		badRequest(c, err.Error())
		return
	}
	ok(c, gin.H{"message": "已解封"})
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
	success, failed := 0, 0
	errs := make([]string, 0, 4)

	for _, id := range req.IDs {
		if err := s.guard.UnbanByRecordID(id, user); err != nil {
			failed++
			if len(errs) < 4 {
				errs = append(errs, fmt.Sprintf("#%d: %s", id, err.Error()))
			}
			continue
		}
		success++
	}
	ok(c, gin.H{"success": success, "failed": failed, "errors": errs})
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
	var req model.Policy
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请求格式不正确")
		return
	}

	// 校验关键字段，避免把系统配置成"谁都连不上"或"谁都拦不住"
	if req.WindowSeconds < 1 || req.WindowSeconds > 86400 {
		badRequest(c, "统计窗口需在 1 ~ 86400 秒之间")
		return
	}
	if req.Threshold < 1 || req.Threshold > 100000 {
		badRequest(c, "触发阈值需在 1 ~ 100000 之间")
		return
	}
	if req.EscalateWindowHours < 1 {
		req.EscalateWindowHours = 24
	}
	switch req.BanGranularity {
	case "ip", "cidr24":
	default:
		badRequest(c, "封禁粒度只能是 ip 或 cidr24")
		return
	}
	switch req.FailMode {
	case "open", "close":
	default:
		badRequest(c, "fail_mode 只能是 open 或 close")
		return
	}
	switch req.GeoIPMode {
	case "blacklist", "whitelist":
	default:
		badRequest(c, "地域模式只能是 blacklist 或 whitelist")
		return
	}

	steps := req.DurationSteps()
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
	if req.RateLimitEnabled {
		if req.RateLimitPerSec < 1 {
			badRequest(c, "速率限制必须大于 0")
			return
		}
		if req.RateLimitBurst < 1 {
			req.RateLimitBurst = req.RateLimitPerSec * 2
		}
	}

	// 国家码规范化
	req.GeoIPBlockCountries = model.PackageCountries(req.CountryList())

	if err := s.store.SavePolicy(&req); err != nil {
		serverErr(c, err)
		return
	}

	if err := s.guard.Refresh(); err != nil {
		serverErr(c, err)
		return
	}
	s.guard.Apply()

	_ = s.store.AddEvent(&model.Event{
		Category: model.EvtConfig,
		IP:       c.ClientIP(),
		Detail:   fmt.Sprintf("更新策略：窗口 %ds / 阈值 %d 次 / 阶梯 %v", req.WindowSeconds, req.Threshold, steps),
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
		badRequest(c, "缺少 name 字段（" + geoip.FileCountry + " / " + geoip.FileCity + " / " + geoip.FileRegion + "）")
		return
	}

	fh, err := c.FormFile("file")
	if err != nil {
		badRequest(c, "缺少 file 字段: " + err.Error())
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
		return "", fmt.Errorf("封禁范围只能是 all（封禁全部端口）或 frp（只封 frp 服务端口）")
	}
	return scope, nil
}

// parseImportLine 解析批量导入的一行，返回地址、封禁范围、备注。
//
// 支持下面四种写法（分隔符可以是 逗号 / 中文逗号 / Tab / 空格）：
//
//	1.2.3.4                 → 范围取默认，无备注
//	1.2.3.4,frp             → 只封 frp 端口
//	1.2.3.4,备注             → 范围取默认
//	1.2.3.4,frp,备注         → 只封 frp 端口，带备注
//
// 关键点是第二段**只有恰好是合法范围值时才当作范围**，否则整段按备注处理。
// 这样老版本导出的两列文件（地址,备注）不用改一个字节就能重新导入 —— 导出
// 文件常被留档、拿去别的机器用，格式一旦不兼容就是实打实的数据损失。
// 代价是备注恰好写成 "all" / "frp" 时会被误认成范围，这是刻意接受的取舍。
func parseImportLine(line, defScope string) (target, scope, remark string, err error) {
	scope = defScope
	if !model.ValidScope(scope) {
		scope = model.ScopeAll
	}

	head, rest := cutLine(line)
	if head == "" {
		return "", "", "", fmt.Errorf("地址为空")
	}
	target = head
	if rest == "" {
		return target, scope, "", nil
	}

	// 第二段单独切一次：是范围就吃掉它，剩下的当备注；不是范围就整段当备注。
	second, tail := cutLine(rest)
	if v := strings.ToLower(second); model.ValidScope(v) {
		scope = v
		remark = tail
	} else {
		// 备注里带逗号/空格是常态，这里必须原样保留（不能按分隔符切开再拼回去）
		remark = rest
	}
	return target, scope, remark, nil
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
