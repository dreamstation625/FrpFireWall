package api

import (
	"context"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/dreamstation625/FrpFireWall/internal/firewall"
	"github.com/dreamstation625/FrpFireWall/internal/frpsplugin"
	"github.com/dreamstation625/FrpFireWall/internal/geoip"
	"github.com/dreamstation625/FrpFireWall/internal/model"
	"github.com/dreamstation625/FrpFireWall/internal/version"
)

// ---- 系统信息 ----

func (s *Server) handleSystemInfo(c *gin.Context) {
	host, _ := os.Hostname()

	cap := firewall.Capability{}
	if drv := s.driver(); drv != nil {
		cap = drv.Capability()
	}

	// 更新检查只回放已有缓存，不在这里发起网络请求，
	// 避免每次刷新面板都去打 GitHub。
	upd := gin.H{"enabled": s.cfg.Update.Enabled, "checked": false}
	if s.cfg.Update.Enabled {
		if res, checked := s.updater.Peek(); checked {
			upd["checked"] = true
			upd["result"] = res
		}
	}

	ok(c, gin.H{
		"version":        version.Version,
		"commit":         version.Commit,
		"build_time":     version.BuildTime,
		"version_full":   version.String(),
		"is_prerelease":  isPrerelease(),
		"hostname":       host,
		"os":             runtime.GOOS,
		"arch":           runtime.GOARCH,
		"started_at":     s.startedAt,
		"uptime_sec":     int64(time.Since(s.startedAt).Seconds()),
		"panel_listen":   s.cfg.Server.Listen,
		"tls_enabled":    s.cfg.Server.TLS.Enabled,
		"plugin_listen":  s.cfg.Frps.PluginListen,
		"plugin_path":    s.cfg.Frps.PluginPath,
		"data_dir":       s.cfg.DataDir,
		"bind_port":      s.cfg.Frps.BindPort,
		"proxy_ports":    s.cfg.Frps.ProxyPorts,
		"trusted_proxy":  s.cfg.Frps.TrustedProxies,
		"guard":          s.guard.Stats(),
		"capability":     cap,
		"detect":         s.reportSnapshot(),
		"geoip":          s.geo.Status(),
		"config_snippet": frpsplugin.Snippet(s.cfg.Frps.PluginListen, s.cfg.Frps.PluginPath),
		"update":         upd,
	})
}

// isPrerelease 判断当前运行的是否为预发布版。
func isPrerelease() bool {
	n, err := version.Current()
	return err == nil && n.IsPre()
}

func (s *Server) handleSystemDetect(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()

	rep := firewall.Detect(ctx)

	profile, err := s.store.GetFirewallProfile()
	if err == nil {
		profile.Detected = rep.Recommended
		profile.DetectedAt = time.Now()
		_ = s.store.SaveFirewallProfile(profile)
	}

	ok(c, rep)
}

// handleSwitchMode 切换防火墙后端。
//
// 顺序很重要：先把新后端的链建好、规则灌进去，再让引擎切过去。
// 反过来做会出现"旧后端已清理、新后端还没生效"的保护真空窗口。
func (s *Server) handleSwitchMode(c *gin.Context) {
	var req struct {
		Backend string `json:"backend"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请求格式不正确")
		return
	}
	switch req.Backend {
	case string(firewall.BackendAuto), string(firewall.BackendIPTables), string(firewall.BackendNFTables):
	default:
		badRequest(c, "backend 只能是 auto / iptables / nftables")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	report := firewall.Detect(ctx)
	newDrv, err := firewall.New(ctx, req.Backend, report)
	if err != nil {
		badRequest(c, "该后端不可用: "+err.Error())
		return
	}

	if err := newDrv.EnsureBase(); err != nil {
		serverErr(c, err)
		return
	}

	// 新后端已就绪，切过去并全量重灌规则
	s.guard.SetDriver(newDrv)
	s.SetDriver(newDrv, report)

	if err := s.guard.Reconcile(); err != nil {
		serverErr(c, err)
		return
	}

	profile, err := s.store.GetFirewallProfile()
	if err == nil {
		profile.Preferred = req.Backend
		profile.Detected = newDrv.Name()
		profile.DetectedAt = time.Now()
		_ = s.store.SaveFirewallProfile(profile)
	}

	_ = s.store.AddRuleChange(&model.RuleChange{
		Backend: newDrv.Name(),
		Action:  "switch_mode",
		Payload: `{"requested":"` + req.Backend + `","effective":"` + newDrv.Name() + `"}`,
		Result:  "success",
	})
	_ = s.store.AddEvent(&model.Event{
		Category: model.EvtConfig,
		IP:       c.ClientIP(),
		Detail:   "切换防火墙后端为 " + newDrv.Name(),
		Actor:    s.currentUser(c),
	})

	ok(c, gin.H{
		"backend":     newDrv.Name(),
		"capability":  newDrv.Capability(),
		"requested":   req.Backend,
		"detect":      report,
		"note":        "旧后端的受管规则不会自动清理，避免误删；如需清理可执行 scripts/frpfirewall-panic.sh",
	})
}

// ---- 防火墙规则展示 ----

func (s *Server) handleManagedRules(c *gin.Context) {
	drv := s.driver()
	if drv == nil {
		badRequest(c, "当前没有可用的防火墙后端")
		return
	}
	rules, err := drv.DumpManaged()
	if err != nil {
		serverErr(c, err)
		return
	}
	ok(c, rules)
}

func (s *Server) handleSystemRules(c *gin.Context) {
	drv := s.driver()
	if drv == nil {
		badRequest(c, "当前没有可用的防火墙后端")
		return
	}
	raw, err := drv.DumpSystem()
	if err != nil {
		serverErr(c, err)
		return
	}
	ok(c, gin.H{"backend": drv.Name(), "raw": raw})
}

// handlePreview 生成将要下发的规则，前端"预览变更"用。
func (s *Server) handlePreview(c *gin.Context) {
	drv := s.driver()
	if drv == nil {
		badRequest(c, "当前没有可用的防火墙后端")
		return
	}
	text, err := s.guard.Preview()
	if err != nil {
		serverErr(c, err)
		return
	}
	ok(c, gin.H{"backend": drv.Name(), "preview": text})
}

func (s *Server) handleReconcile(c *gin.Context) {
	if err := s.guard.Reconcile(); err != nil {
		serverErr(c, err)
		return
	}
	_ = s.store.AddEvent(&model.Event{
		Category: model.EvtRuleChange,
		IP:       c.ClientIP(),
		Detail:   "手动触发规则同步",
		Actor:    s.currentUser(c),
	})
	ok(c, gin.H{"message": "规则已同步", "stats": s.guard.Stats()})
}

func (s *Server) handleSnapshot(c *gin.Context) {
	drv := s.driver()
	if drv == nil {
		badRequest(c, "当前没有可用的防火墙后端")
		return
	}
	snap, err := drv.Snapshot()
	if err != nil {
		serverErr(c, err)
		return
	}
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.String(http.StatusOK, snap)
}

// ---- 事件 ----

func (s *Server) handleListEvents(c *gin.Context) {
	category := c.Query("category")
	keyword := c.Query("keyword")

	var since *time.Time
	if h := c.Query("hours"); h != "" {
		if n, err := strconv.Atoi(h); err == nil && n > 0 {
			t := time.Now().Add(-time.Duration(n) * time.Hour)
			since = &t
		}
	}

	limit := 50
	if l := c.Query("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}

	// 游标就是上一页最后一条的 id
	var beforeID uint
	if cur := c.Query("cursor"); cur != "" {
		if n, err := strconv.ParseUint(cur, 10, 64); err == nil {
			beforeID = uint(n)
		}
	}

	res, err := s.store.ListEventsCursor(category, keyword, since, beforeID, limit)
	if err != nil {
		serverErr(c, err)
		return
	}
	ok(c, res)
}

func (s *Server) handleEventStats(c *gin.Context) {
	hours := 24
	if h := c.Query("hours"); h != "" {
		if n, err := strconv.Atoi(h); err == nil && n > 0 && n <= 24*30 {
			hours = n
		}
	}
	stats, err := s.store.EventStats(time.Now().Add(-time.Duration(hours) * time.Hour))
	if err != nil {
		serverErr(c, err)
		return
	}

	// 国家码转成中文名，前端直接展示
	for i := range stats.TopCountries {
		stats.TopCountries[i].Name = geoip.CountryName(stats.TopCountries[i].Name)
	}

	ok(c, stats)
}

func (s *Server) handleListRuleChanges(c *gin.Context) {
	page, size := pageParams(c)
	res, err := s.store.ListRuleChanges(page, size)
	if err != nil {
		serverErr(c, err)
		return
	}
	ok(c, res)
}

// ---- frps 集成 ----

func (s *Server) handleFrpsSnippet(c *gin.Context) {
	ok(c, gin.H{
		"snippet":  frpsplugin.Snippet(s.cfg.Frps.PluginListen, s.cfg.Frps.PluginPath),
		"addr":     s.cfg.Frps.PluginListen,
		"path":     s.cfg.Frps.PluginPath,
		"ops":      []string{"Login", "NewUserConn"},
		"bind_port": s.cfg.Frps.BindPort,
		"warnings": []string{
			"ops 绝对不要加 \"Ping\"：心跳是每客户端 30s 一次，挂上来会让插件 QPS 乘以客户端数，可能拖垮 frps。",
			"修改 frps.toml 后需要 systemctl restart frps，重启期间所有隧道会断开，建议避开业务高峰。",
			"插件服务只监听回环地址，frps 必须与本程序在同一台机器上。",
		},
	})
}

// handleFrpsHealth 直接向插件服务发一次真实请求，验证链路连通。
func (s *Server) handleFrpsHealth(c *gin.Context) {
	url := "http://" + s.cfg.Frps.PluginListen + "/healthz"

	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		serverErr(c, err)
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		ok(c, gin.H{"ok": false, "error": "插件服务不可达: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	ok(c, gin.H{"ok": resp.StatusCode == http.StatusOK, "status": resp.StatusCode, "url": url})
}

// handleFrpsConfig 返回 frps 侧建议的进阶配置。
func (s *Server) handleFrpsConfig(c *gin.Context) {
	ok(c, gin.H{
		"plugin_snippet": frpsplugin.Snippet(s.cfg.Frps.PluginListen, s.cfg.Frps.PluginPath),
		"hardening": "# 以下为可选加固项，按需追加到 frps.toml\n" +
			"# 只接受启用 TLS 的客户端，减少协议层攻击面\n" +
			"transport.tls.force = true\n\n" +
			"# 让心跳与工作连接也参与插件校验（注意：会增加插件调用量）\n" +
			"# auth.additionalScopes = [\"HeartBeats\", \"NewWorkConns\"]\n\n" +
			"# 限制单个客户端的代理数量\n" +
			"maxPortsPerClient = 10\n",
	})
}

// ---- 辅助 ----

func pageParams(c *gin.Context) (page, size int) {
	page, size = 1, 20
	if p := c.Query("page"); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			page = n
		}
	}
	if s := c.Query("size"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 500 {
			size = n
		}
	}
	return page, size
}
