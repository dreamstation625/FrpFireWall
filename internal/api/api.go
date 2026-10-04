package api

import (
	"context"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/dreamstation625/FrpFireWall/internal/config"
	"github.com/dreamstation625/FrpFireWall/internal/firewall"
	"github.com/dreamstation625/FrpFireWall/internal/geoip"
	"github.com/dreamstation625/FrpFireWall/internal/guard"
	"github.com/dreamstation625/FrpFireWall/internal/store"
	"github.com/dreamstation625/FrpFireWall/internal/update"
)

// Server 承载 HTTP 层。
type Server struct {
	cfg   *config.Config
	store *store.Store
	geo   *geoip.Resolver
	guard *guard.Manager
	log   *slog.Logger

	jwtSecret []byte
	tokenTTL  time.Duration

	// 面板凭据（bcrypt 哈希），支持运行期改密码
	credMu   sync.RWMutex
	username string
	passHash string

	// 面板登录限速，防止管理入口被爆破
	loginLim *loginLimiter

	// 防火墙后端可运行期切换
	fwMu   sync.RWMutex
	report *firewall.Report
	drv    firewall.Driver

	// 版本更新检查（带缓存，不下载任何东西）
	updater *update.Checker

	startedAt time.Time
	webFS     fs.FS
}

// New 创建 API 服务。
func New(
	cfg *config.Config,
	st *store.Store,
	geo *geoip.Resolver,
	g *guard.Manager,
	drv firewall.Driver,
	report *firewall.Report,
	jwtSecret, username, passHash string,
	webFS fs.FS,
	log *slog.Logger,
) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		cfg:       cfg,
		store:     st,
		geo:       geo,
		guard:     g,
		log:       log,
		jwtSecret: []byte(jwtSecret),
		tokenTTL:  time.Duration(cfg.Server.Auth.TokenTTLHours) * time.Hour,
		username:  username,
		passHash:  passHash,
		drv:       drv,
		report:    report,
		updater:   update.New(update.WithRepo(cfg.Update.Repo)),
		startedAt: time.Now(),
		webFS:     webFS,
		loginLim:  newLoginLimiter(),
	}
}

// SetDriver 在切换防火墙后端后更新引用。
func (s *Server) SetDriver(drv firewall.Driver, report *firewall.Report) {
	s.fwMu.Lock()
	s.drv = drv
	s.report = report
	s.fwMu.Unlock()
}

func (s *Server) driver() firewall.Driver {
	s.fwMu.RLock()
	defer s.fwMu.RUnlock()
	return s.drv
}

func (s *Server) reportSnapshot() *firewall.Report {
	s.fwMu.RLock()
	defer s.fwMu.RUnlock()
	return s.report
}

// Routes 组装全部路由。
func (s *Server) Routes() http.Handler {
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(s.accessLog())

	v1 := r.Group("/api/v1")

	// 登录与初始化都不需要鉴权，但同样有速率限制（防止面板自身被爆破）
	v1.GET("/auth/status", s.handleAuthStatus)
	v1.POST("/auth/login", s.loginRateLimit(), s.handleLogin)
	v1.POST("/auth/setup", s.loginRateLimit(), s.handleSetup)

	auth := v1.Group("")
	auth.Use(s.authMiddleware())
	{
		auth.GET("/auth/me", s.handleMe)
		auth.POST("/auth/logout", s.handleLogout)
		auth.POST("/auth/password", s.handleChangePassword)

		// ---- 系统 ----
		auth.GET("/system/info", s.handleSystemInfo)
		auth.GET("/system/detect", s.handleSystemDetect)
		auth.POST("/system/firewall/mode", s.handleSwitchMode)
		auth.GET("/system/update", s.handleUpdateStatus)
		auth.POST("/system/update/check", s.handleUpdateCheck)

		// ---- 配置 ----
		auth.GET("/config", s.handleGetConfig)
		auth.PUT("/config", s.handleUpdateConfig)

		// ---- 防火墙 ----
		auth.GET("/firewall/managed", s.handleManagedRules)
		auth.GET("/firewall/counters", s.handleCounters)
		auth.GET("/firewall/system", s.handleSystemRules)
		auth.POST("/firewall/preview", s.handlePreview)
		auth.POST("/firewall/reconcile", s.handleReconcile)
		auth.GET("/firewall/snapshot", s.handleSnapshot)

		// ---- 黑白名单 ----
		auth.GET("/acl/:kind", s.handleListACL)
		auth.POST("/acl/:kind", s.handleCreateACL)
		auth.PUT("/acl/:kind/:id", s.handleUpdateACL)
		auth.DELETE("/acl/:kind/:id", s.handleDeleteACL)
		auth.POST("/acl/:kind/batch", s.handleBatchACL)
		auth.POST("/acl/:kind/import", s.handleImportACL)
		auth.GET("/acl/:kind/export", s.handleExportACL)

		// ---- 封禁 ----
		auth.GET("/bans", s.handleListBans)
		auth.GET("/bans/active", s.handleActiveBans)
		auth.POST("/bans", s.handleCreateBan)
		auth.DELETE("/bans/:id", s.handleDeleteBan)
		auth.POST("/bans/batch-delete", s.handleBatchDeleteBan)
		auth.POST("/bans/lookup", s.handleLookupIP)

		// ---- 策略 ----
		auth.GET("/policy", s.handleGetPolicy)
		auth.PUT("/policy", s.handleUpdatePolicy)
		// 细分规则的读取单独一个接口；写入走 PUT /policy 的 rules 字段，
		// 让"策略 + 规则"落在同一次请求、同一个事务里。
		auth.GET("/policy/rules", s.handleListRateRules)

		// ---- GeoIP ----
		auth.POST("/geoip/lookup", s.handleGeoLookup)
		auth.POST("/geoip/lookup/batch", s.handleGeoLookupBatch)
		auth.GET("/geoip/status", s.handleGeoStatus)
		auth.POST("/geoip/upload", s.handleGeoUpload)
		auth.GET("/geoip/countries", s.handleGeoCountries)
		auth.GET("/geoip/provinces", s.handleGeoProvinces)
		// 从上游直接拉库（P3TERX/GeoLite.mmdb、lionsoul2014/ip2region），
		// 走国内可用的加速源，免去手动下载再上传。
		auth.GET("/geoip/sources", s.handleGeoSources)
		auth.POST("/geoip/download", s.handleGeoDownload)

		// ---- 事件 ----
		auth.GET("/events", s.handleListEvents)
		auth.GET("/events/stats", s.handleEventStats)
		auth.GET("/events/changes", s.handleListRuleChanges)

		// ---- frps 集成 ----
		auth.GET("/frps/snippet", s.handleFrpsSnippet)
		auth.GET("/frps/health", s.handleFrpsHealth)
		auth.GET("/frps/config", s.handleFrpsConfig)
		// 受保护端口（bind_port ∪ 代理端口）。写接口只改代理端口那一半，
		// 保存后立即重算内核规则，不需要重启。
		auth.GET("/frps/protect-ports", s.handleGetFrpsProtectPorts)
		auth.PUT("/frps/protect-ports", s.handleUpdateFrpsProtectPorts)
	}

	s.mountWeb(r)
	return r
}

// mountWeb 挂载前端静态资源。
// 前端产物用 go:embed 打进二进制，部署时只有一个文件。
func (s *Server) mountWeb(r *gin.Engine) {
	if s.webFS == nil {
		r.NoRoute(func(c *gin.Context) {
			c.JSON(http.StatusNotFound, gin.H{"error": "接口不存在（前端资源未打包）"})
		})
		return
	}

	fileServer := http.FileServer(http.FS(s.webFS))

	r.NoRoute(func(c *gin.Context) {
		p := c.Request.URL.Path
		// 接口路径不落到这里
		if strings.HasPrefix(p, "/api/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "接口不存在"})
			return
		}
		// 静态资源存在就直接给
		if f, err := s.webFS.Open(strings.TrimPrefix(p, "/")); err == nil {
			_ = f.Close()
			fileServer.ServeHTTP(c.Writer, c.Request)
			return
		}
		// 其余走 SPA 首页
		index, err := fs.ReadFile(s.webFS, "index.html")
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "index.html 缺失"})
			return
		}
		c.Data(http.StatusOK, "text/html; charset=utf-8", index)
	})
}

// accessLog 记录管理操作，跳过静态资源减少噪音。
func (s *Server) accessLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.Next()
			return
		}
		start := time.Now()
		c.Next()
		s.log.Info("api",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"cost_ms", time.Since(start).Milliseconds(),
			"ip", c.ClientIP(),
		)
	}
}

// ---- 通用响应辅助 ----

func ok(c *gin.Context, data any) {
	c.JSON(http.StatusOK, gin.H{"ok": true, "data": data})
}

func fail(c *gin.Context, status int, msg string) {
	c.JSON(status, gin.H{"ok": false, "error": msg})
}

func badRequest(c *gin.Context, msg string) { fail(c, http.StatusBadRequest, msg) }
func serverErr(c *gin.Context, err error) {
	fail(c, http.StatusInternalServerError, err.Error())
}

// Shutdown 停机钩子。
func (s *Server) Shutdown(ctx context.Context) error {
	_ = ctx
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
