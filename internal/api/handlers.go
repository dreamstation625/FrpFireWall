package api

import (
	"context"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/dreamstation625/FrpFireWall/internal/config"
	"github.com/dreamstation625/FrpFireWall/internal/firewall"
	"github.com/dreamstation625/FrpFireWall/internal/frpsplugin"
	"github.com/dreamstation625/FrpFireWall/internal/geoip"
	"github.com/dreamstation625/FrpFireWall/internal/model"
	"github.com/dreamstation625/FrpFireWall/internal/portrange"
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

	bindPort, proxyPorts, protectPorts := s.guard.FrpsPorts()

	ok(c, gin.H{
		"version":       version.Version,
		"commit":        version.Commit,
		"build_time":    version.BuildTime,
		"version_full":  version.String(),
		"is_prerelease": isPrerelease(),
		"hostname":      host,
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"started_at":    s.startedAt,
		"uptime_sec":    int64(time.Since(s.startedAt).Seconds()),
		"panel_listen":  s.cfg.Server.Listen,
		"tls_enabled":   s.cfg.Server.TLS.Enabled,
		"plugin_listen": s.cfg.Frps.PluginListen,
		"plugin_path":   s.cfg.Frps.PluginPath,
		"data_dir":      s.cfg.DataDir,
		"bind_port":     bindPort,
		// 代理端口与受保护端口取的是**运行期**值（guard 里那份），不是 s.cfg 里
		// 启动时的快照：这一项可以在 frp 接入页热改，面板必须显示真正生效的东西。
		"proxy_ports":    proxyPorts,
		"protect_ports":  protectPorts,
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
		"backend":    newDrv.Name(),
		"capability": newDrv.Capability(),
		"requested":  req.Backend,
		"detect":     report,
		"note":       "旧后端的受管规则不会自动清理，避免误删；如需清理可执行 scripts/frpfirewall-panic.sh",
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

// handleCounters 返回内核丢包统计：当前读数 + 相对上一批的增幅 + 趋势。
//
// 读不到计数时**不报错**，返回带 unsupported 说明的空结果 —— 界面要能显示
// "这个后端数不出数"，而不是弹一个红框。
func (s *Server) handleCounters(c *gin.Context) {
	hours := 24
	if h := c.Query("hours"); h != "" {
		if n, err := strconv.Atoi(h); err == nil && n > 0 && n <= 24*30 {
			hours = n
		}
	}
	snap, err := s.guard.CountersSnapshot(hours)
	if err != nil {
		serverErr(c, err)
		return
	}
	ok(c, snap)
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

	page, size := pageParams(c)
	res, err := s.store.ListEventsPage(category, keyword, since, page, size)
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

// handleProxyNames 给细分规则的「代理」一栏提供候选值。
//
// 列表只是**方便的默认值**，不是全集：它来自事件表，没被访问过的隧道、
// 以及被事件保留期清掉的旧隧道都不在里面。界面因此必须允许手填（allow-create），
// 这里也不做任何校验 —— 填错的表现是永远不命中，与城市那一栏是同一个取舍。
func (s *Server) handleProxyNames(c *gin.Context) {
	limit := 100
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	names, err := s.store.ListProxyNames(limit)
	if err != nil {
		serverErr(c, err)
		return
	}
	ok(c, gin.H{"items": names})
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
		// TOML 与 JSON 两份等价配置一起下发，由前端切换展示。
		// frp 从 v0.52.0 起两种格式都支持，用哪份取决于用户现有配置文件的后缀。
		"snippet":      frpsplugin.Snippet(s.cfg.Frps.PluginListen, s.cfg.Frps.PluginPath),
		"snippet_json": frpsplugin.SnippetJSON(s.cfg.Frps.PluginListen, s.cfg.Frps.PluginPath),
		"addr":         s.cfg.Frps.PluginListen,
		"path":         s.cfg.Frps.PluginPath,
		// ops 取自 frpsplugin，不在这里另写一份：界面告诉用户订阅了哪几个 op，
		// 与实际生成到配置里的必须一致。
		"ops":       frpsplugin.Ops(),
		"bind_port": s.cfg.Frps.BindPort,
		"warnings": []string{
			"ops 绝对不要加 \"Ping\"：心跳是每客户端 30s 一次，挂上来会让插件 QPS 乘以客户端数，可能拖垮 frps。",
			"修改配置后需要 systemctl restart frps，重启期间所有隧道会断开，建议避开业务高峰。",
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
//
// 文本由 frpsplugin 生成而不是在这里拼：那几份配置要能拿真实的 frps 校验
// （frps verify -c），放在包里才好一起测。
func (s *Server) handleFrpsConfig(c *gin.Context) {
	ok(c, gin.H{
		"plugin_snippet":      frpsplugin.Snippet(s.cfg.Frps.PluginListen, s.cfg.Frps.PluginPath),
		"plugin_snippet_json": frpsplugin.SnippetJSON(s.cfg.Frps.PluginListen, s.cfg.Frps.PluginPath),
		"hardening":           frpsplugin.HardeningTOML(),
		"hardening_json":      frpsplugin.HardeningJSON(),
	})
}

// protectPortsPayload 是"受保护端口"这一栏的数据形状。
//
// 三个字段一起给，是因为界面右上角必须把这三件事同时讲清楚：
// 受保护端口 = bind_port ∪ 代理端口。只回一个拼好的结果，用户改完端口
// 会想问"7000 是从哪来的、为什么删不掉"。
//
// bind_port 只是读出来展示，不接受修改：它是 frps 自己的 bindPort，
// 改这里不会让 frps 换端口，只会让防火墙规则和实际监听的端口错位。
func protectPortsPayload(bindPort int, proxyPorts, protect portrange.Set) gin.H {
	return gin.H{
		"bind_port":   bindPort,
		"proxy_ports": proxyPorts,
		"ports":       protect,
	}
}

// handleGetFrpsProtectPorts 返回当前生效的受保护端口。
func (s *Server) handleGetFrpsProtectPorts(c *gin.Context) {
	bindPort, proxyPorts, protect := s.guard.FrpsPorts()
	ok(c, protectPortsPayload(bindPort, proxyPorts, protect))
}

// handleUpdateFrpsProtectPorts 保存代理端口，并立即生效。
//
// 与 PUT /config 的区别只在"生效时机"：代理端口只影响内核规则里那个端口集合
// （全局限速的兜底规则、"仅 frp 端口"的黑名单），重算一次规则就够了，不需要
// 重启进程。所以这里走热更，而 PUT /config 仍然老老实实说"需要重启"。
//
// 先落库再改内存：落库失败的话不该已经动过内核规则。
func (s *Server) handleUpdateFrpsProtectPorts(c *gin.Context) {
	var req struct {
		ProxyPorts portrange.Set `json:"proxy_ports"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		// 带上底层原因：这里唯一有自由文本写法的就是端口，只说"格式不正确"
		// 用户猜不出自己是多打了一个逗号还是端口越界了。
		badRequest(c, "端口格式不正确："+err.Error())
		return
	}
	if len(req.ProxyPorts) == 0 {
		// 空值在 FromSettings 里被当成"没配过"、回落成默认的 80,443，
		// 于是保存完看着生效了、重启之后又变回默认 —— 这种"改了等于没改"
		// 比当场报错难查得多，所以在入口拦住。
		badRequest(c, "代理端口不能为空：留空会被当作未配置，重启后回落成默认的 80,443。确实不想再保护任何代理端口时，请改用「全部端口」范围，或把这条封禁删掉")
		return
	}

	cfg, err := s.storedConfig()
	if err != nil {
		serverErr(c, err)
		return
	}
	cfg.Frps.ProxyPorts = req.ProxyPorts
	// 走一遍完整校验：这里只校验了代理端口，但规则与 PUT /config 完全一致，
	// 免得以后加了端口相关约束只生效在其中一个入口上。
	if err := cfg.Validate(); err != nil {
		badRequest(c, err.Error())
		return
	}
	portsText := cfg.Frps.ProxyPorts.String()
	if err := s.store.SetSetting(config.KeyProxyPorts, portsText); err != nil {
		serverErr(c, err)
		return
	}

	s.guard.SetFrpsProxyPorts(cfg.Frps.ProxyPorts)

	_ = s.store.AddEvent(&model.Event{
		Category: model.EvtConfig,
		IP:       c.ClientIP(),
		Detail:   "修改 frp 代理端口：" + portsText,
		Actor:    s.currentUser(c),
	})

	bindPort, proxyPorts, protect := s.guard.FrpsPorts()
	res := protectPortsPayload(bindPort, proxyPorts, protect)
	res["message"] = "受保护端口已更新并立即生效"
	ok(c, res)
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
