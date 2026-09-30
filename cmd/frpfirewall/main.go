// Command frpfirewall 是运行在 frps 所在主机上的防火墙与防爆破插件。
//
// 它同时提供三个角色：
//   - frps 服务端插件（实现 Login / NewUserConn 回调，做频次与属地判定）
//   - 防火墙管理器（把封禁落到 iptables / nftables）
//   - Web 控制台（单二进制内嵌前端）
//
// 配置全部持久化在数据目录的 SQLite 里，启动时只需要给出数据目录。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/api"
	"github.com/dreamstation625/FrpFireWall/internal/config"
	"github.com/dreamstation625/FrpFireWall/internal/firewall"
	"github.com/dreamstation625/FrpFireWall/internal/frpsplugin"
	"github.com/dreamstation625/FrpFireWall/internal/geoip"
	"github.com/dreamstation625/FrpFireWall/internal/guard"
	"github.com/dreamstation625/FrpFireWall/internal/model"
	"github.com/dreamstation625/FrpFireWall/internal/store"
	"github.com/dreamstation625/FrpFireWall/internal/version"
	"github.com/dreamstation625/FrpFireWall/internal/web"
)

func main() {
	var (
		dataDir = flag.String("data", "./data", "数据目录，存放 SQLite 数据库与属地库文件")
		listen  = flag.String("listen", "", "临时覆盖面板监听地址，仅本次运行有效（改错地址后用来救急）")
		showVer = flag.Bool("version", false, "打印版本后退出")
		hashPwd = flag.String("hash-password", "", "把给定明文密码转成 bcrypt 哈希后退出")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("FrpFireWall %s (commit %s, built %s)\n", version.Version, version.Commit, version.BuildTime)
		return
	}
	if *hashPwd != "" {
		h, err := config.HashPassword(*hashPwd)
		if err != nil {
			fmt.Fprintln(os.Stderr, "生成失败:", err)
			os.Exit(1)
		}
		fmt.Println(h)
		return
	}

	if err := run(*dataDir, *listen); err != nil {
		fmt.Fprintln(os.Stderr, "启动失败:", err)
		os.Exit(1)
	}
}

func run(dataDir, listenOverride string) error {
	// 数据目录必须先于一切确定：配置本身也存在这个目录的数据库里。
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("创建数据目录 %s 失败: %w", dataDir, err)
	}

	st, err := store.Open(dataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	// ---- 配置 ----
	// 全部取自数据库；后续版本新增的配置项会自动补上默认值，
	// 已存在的项保持用户当前设置不变。
	saved, err := st.AllSettings()
	if err != nil {
		return fmt.Errorf("读取配置失败: %w", err)
	}
	cfg, err := config.FromSettings(saved)
	if err != nil {
		return fmt.Errorf("配置无效: %w", err)
	}
	cfg.DataDir = dataDir

	missing := map[string]string{}
	for k, v := range cfg.ToSettings() {
		if _, ok := saved[k]; !ok {
			missing[k] = v
		}
	}
	if len(missing) > 0 {
		if err := st.SetSettings(missing); err != nil {
			return fmt.Errorf("写入默认配置失败: %w", err)
		}
	}

	// 命令行覆盖不落库，只影响本次运行。
	if listenOverride != "" {
		cfg.Server.Listen = listenOverride
	}

	logger, closeLog, err := setupLogger(cfg)
	if err != nil {
		return err
	}
	defer closeLog()

	logger.Info("FrpFireWall 启动中",
		"version", version.Version,
		"data_dir", dataDir,
		"panel", cfg.Server.Listen,
		"plugin", cfg.Frps.PluginListen,
	)

	// ---- 面板初始化 ----
	passHash, err := st.GetSetting(model.SettingPasswordHash)
	if err != nil {
		return fmt.Errorf("读取面板凭据失败: %w", err)
	}
	setupToken, err := config.EnsureSetupToken(st)
	if err != nil {
		return fmt.Errorf("生成初始化令牌失败: %w", err)
	}

	tokenFile := filepath.Join(dataDir, "setup_token.txt")
	if setupToken != "" {
		if err := os.WriteFile(tokenFile, []byte(setupToken+"\n"), 0o600); err != nil {
			logger.Warn("初始化令牌文件写入失败", "path", tokenFile, "err", err)
		}
		fmt.Printf("\n"+
			"==================================================\n"+
			" 尚未设置面板密码，请打开面板完成初始化\n"+
			" 初始化令牌: %s\n"+
			" 令牌仅此一次有效，设置完密码后自动作废\n"+
			" 令牌同时保存在: %s\n"+
			"==================================================\n\n", setupToken, tokenFile)
		logger.Warn("面板尚未初始化，等待设置密码", "token_file", tokenFile)
	} else {
		// 初始化已完成，清掉可能残留的令牌文件
		_ = os.Remove(tokenFile)
	}

	jwtSecret, err := config.EnsureJWTSecret(st)
	if err != nil {
		return fmt.Errorf("初始化 JWT 密钥失败: %w", err)
	}

	// ---- 属地数据库 ----
	geo := geoip.New(dataDir)
	if geoStatus := geo.Status(); !geoStatus.CountryLoaded && !geoStatus.RegionLoaded {
		logger.Warn("未加载任何属地数据库，属地查询与国家封禁暂不可用",
			"data_dir", dataDir,
			"hint", "把 GeoLite2-Country.mmdb / ip2region.xdb 放到数据目录，或在控制台里上传")
	} else {
		logger.Info("属地数据库已加载",
			"maxmind", geo.Status().CountryLoaded,
			"ip2region", geo.Status().RegionLoaded,
			"stale", geo.Status().Stale)
	}

	// ---- 防火墙后端 ----
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	probeCtx, probeCancel := context.WithTimeout(ctx, 20*time.Second)
	report := firewall.Detect(probeCtx)
	probeCancel()

	// 界面上切换过的后端记录在 firewall_profiles 表，优先于配置里的初始偏好
	preferred := cfg.Backend
	if profile, err := st.GetFirewallProfile(); err == nil && profile.Preferred != "" && profile.Preferred != "auto" {
		preferred = profile.Preferred
	}
	if preferred == "auto" || preferred == "" {
		preferred = string(firewall.BackendAuto)
	}

	drv, err := firewall.New(ctx, preferred, report)
	if err != nil {
		logger.Error("没有可用的防火墙后端，网络层封禁将不可用（插件判定与面板仍可正常工作）", "err", err)
		drv = nil
	} else {
		logger.Info("防火墙后端就绪",
			"backend", drv.Name(),
			"capability", drv.Capability())
	}

	// ---- 引擎 ----
	mgr := guard.New(cfg, st, geo, drv, logger)
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("启动封禁引擎失败: %w", err)
	}

	// ---- frps 插件服务 ----
	pluginSrv := frpsplugin.New(cfg.Frps.PluginListen, cfg.Frps.PluginPath, mgr, logger, func() bool {
		p, err := st.GetPolicy()
		if err != nil || p == nil {
			return true // 读不到策略时默认放行，避免把自己锁死
		}
		return p.FailMode != "close"
	})
	if err := pluginSrv.Start(); err != nil {
		return err
	}

	// ---- HTTP 面板 ----
	srv := api.New(cfg, st, geo, mgr, drv, report, jwtSecret, cfg.Server.Auth.Username, passHash, web.FS(), logger)

	httpSrv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		if cfg.Server.TLS.Enabled {
			logger.Info("控制台已启动（HTTPS）", "addr", cfg.Server.Listen)
			serveErr <- httpSrv.ListenAndServeTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
			return
		}
		logger.Warn("控制台以 HTTP 方式启动。若监听在公网地址，请开启 TLS，否则登录密码是明文传输",
			"addr", cfg.Server.Listen,
			"hint", "在面板的「系统设置」里启用 HTTPS 并填写证书路径")
		serveErr <- httpSrv.ListenAndServe()
	}()

	// ---- 等待退出信号 ----
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("HTTP 服务异常退出: %w", err)
		}
	case <-sigCtx.Done():
		logger.Info("收到退出信号，正在关闭…")
	}

	// 注意：退出时**不清理防火墙规则**。
	// 保持封禁有效比"干净退出"更重要，残留规则会在下次启动时被 reconcile 收拢。
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancelShutdown()

	_ = httpSrv.Shutdown(shutdownCtx)
	_ = pluginSrv.Stop(shutdownCtx)
	cancel()

	logger.Info("已退出")
	return nil
}

// setupLogger 按配置初始化结构化日志。
func setupLogger(cfg *config.Config) (*slog.Logger, func(), error) {
	level := slog.LevelInfo
	switch cfg.Log.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	var w io.Writer = os.Stdout
	closer := func() {}

	if cfg.Log.File != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.Log.File), 0o755); err != nil {
			return nil, nil, fmt.Errorf("创建日志目录失败: %w", err)
		}
		f, err := os.OpenFile(cfg.Log.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			return nil, nil, fmt.Errorf("打开日志文件失败: %w", err)
		}
		w = f
		closer = func() { _ = f.Close() }
	}

	handler := slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})
	return slog.New(handler), closer, nil
}
