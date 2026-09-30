package api

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/dreamstation625/FrpFireWall/internal/config"
	"github.com/dreamstation625/FrpFireWall/internal/model"
)

// ---- JWT ----

type claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func (s *Server) issueToken(username string) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(s.tokenTTL)

	c := claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			Issuer:    "frpfirewall",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(s.jwtSecret)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, exp, nil
}

func (s *Server) parseToken(tokenStr string) (*claims, error) {
	var c claims
	_, err := jwt.ParseWithClaims(tokenStr, &c, func(t *jwt.Token) (any, error) {
		// 明确限定算法，避免 alg=none 之类的降级攻击
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("非预期的签名算法: %v", t.Header["alg"])
		}
		return s.jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := ""
		if h := c.GetHeader("Authorization"); strings.HasPrefix(h, "Bearer ") {
			token = strings.TrimPrefix(h, "Bearer ")
		}
		// 导出场景（比如用浏览器直接下载 CSV）允许 query 传 token
		if token == "" {
			token = c.Query("token")
		}
		if token == "" {
			fail(c, http.StatusUnauthorized, "未登录")
			c.Abort()
			return
		}
		cl, err := s.parseToken(token)
		if err != nil {
			fail(c, http.StatusUnauthorized, "登录状态已失效，请重新登录")
			c.Abort()
			return
		}
		c.Set("username", cl.Username)
		c.Next()
	}
}

func (s *Server) currentUser(c *gin.Context) string {
	if v, ok := c.Get("username"); ok {
		if name, ok := v.(string); ok && name != "" {
			return name
		}
	}
	return "admin"
}

// ---- 登录限速 ----

const (
	loginWindow      = 5 * time.Minute
	loginMaxFailures = 8
	loginLockDur     = 10 * time.Minute
)

// loginLimiter 保护的是**管理面板入口**本身，与业务防火墙无关。
// 面板对外网开放时，这一层是必需的。
type loginLimiter struct {
	mu    sync.Mutex
	state map[string]*loginAttempt
}

type loginAttempt struct {
	fails    []int64
	lockedTo time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{state: make(map[string]*loginAttempt)}
}

func (l *loginLimiter) blocked(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	a, ok := l.state[ip]
	if !ok {
		return false, 0
	}
	now := time.Now()
	if now.Before(a.lockedTo) {
		return true, a.lockedTo.Sub(now)
	}

	// 清理过期记录
	cut := now.Add(-loginWindow).UnixMilli()
	kept := a.fails[:0]
	for _, t := range a.fails {
		if t >= cut {
			kept = append(kept, t)
		}
	}
	a.fails = kept
	return len(a.fails) >= loginMaxFailures, 0
}

func (l *loginLimiter) recordFail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	a, ok := l.state[ip]
	if !ok {
		a = &loginAttempt{}
		l.state[ip] = a
	}
	now := time.Now()
	a.fails = append(a.fails, now.UnixMilli())

	if len(a.fails) >= loginMaxFailures {
		a.lockedTo = now.Add(loginLockDur)
		a.fails = nil
	}
}

func (l *loginLimiter) clear(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.state, ip)
}

func (s *Server) loginRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if blocked, wait := s.loginLim.blocked(ip); blocked {
			fail(c, http.StatusTooManyRequests,
				fmt.Sprintf("登录失败次数过多，已临时锁定，请在 %s 后重试", wait.Round(time.Second)))
			c.Abort()
			return
		}
		c.Next()
	}
}

// ---- 处理器 ----

// handleAuthStatus 是公开接口，供前端判断面板是否已完成初始化。
func (s *Server) handleAuthStatus(c *gin.Context) {
	s.credMu.RLock()
	initialized := s.passHash != ""
	s.credMu.RUnlock()
	ok(c, gin.H{"initialized": initialized})
}

// handleSetup 完成首次初始化：校验一次性令牌，写入用户名与密码。
//
// 面板可能直接开在公网，所以这里不接受"谁先来谁就是管理员"，
// 必须带上启动时生成、且只打印在服务器控制台的令牌。
func (s *Server) handleSetup(c *gin.Context) {
	var req struct {
		Token    string `json:"token"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请求格式不正确")
		return
	}

	s.credMu.RLock()
	initialized := s.passHash != ""
	s.credMu.RUnlock()
	if initialized {
		fail(c, http.StatusConflict, "面板已完成初始化")
		return
	}

	ip := c.ClientIP()
	if !config.SetupTokenMatches(s.store, req.Token) {
		s.loginLim.recordFail(ip)
		fail(c, http.StatusUnauthorized, "初始化令牌不正确")
		return
	}

	if len(req.Password) < 8 {
		badRequest(c, "密码至少 8 位")
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" {
		username = "admin"
	}

	newHash, err := config.HashPassword(req.Password)
	if err != nil {
		serverErr(c, err)
		return
	}

	if err := s.store.SetSettings(map[string]string{
		model.SettingPasswordHash: newHash,
		model.SettingUsername:     username,
		config.KeyAuthUsername:    username,
		config.KeySetupToken:      "", // 令牌用完即废
	}); err != nil {
		serverErr(c, err)
		return
	}

	s.credMu.Lock()
	s.passHash = newHash
	s.username = username
	s.credMu.Unlock()

	// 令牌已用掉，落盘的那份也删掉，不留固定口令在机器上
	_ = os.Remove(filepath.Join(s.cfg.DataDir, "setup_token.txt"))

	_ = s.store.AddEvent(&model.Event{
		Category: model.EvtAuth,
		IP:       ip,
		User:     username,
		Detail:   "完成面板初始化",
		Actor:    username,
	})

	// 初始化完成后直接发放 token，省去再登录一次
	token, exp, err := s.issueToken(username)
	if err != nil {
		serverErr(c, err)
		return
	}
	ok(c, gin.H{"token": token, "expires_at": exp, "username": username})
}

func (s *Server) handleLogin(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请求格式不正确")
		return
	}

	s.credMu.RLock()
	username, hash := s.username, s.passHash
	s.credMu.RUnlock()

	if hash == "" {
		fail(c, http.StatusForbidden, "面板尚未初始化，请先设置密码")
		return
	}

	ip := c.ClientIP()

	if req.Username != username || !config.CheckPassword(hash, req.Password) {
		s.loginLim.recordFail(ip)
		_ = s.store.AddEvent(&model.Event{
			Category: model.EvtAuth,
			IP:       ip,
			User:     req.Username,
			Detail:   "面板登录失败",
			Actor:    req.Username,
		})
		fail(c, http.StatusUnauthorized, "用户名或密码错误")
		return
	}

	s.loginLim.clear(ip)
	token, exp, err := s.issueToken(username)
	if err != nil {
		serverErr(c, err)
		return
	}

	_ = s.store.AddEvent(&model.Event{
		Category: model.EvtAuth,
		IP:       ip,
		User:     username,
		Detail:   "面板登录成功",
		Actor:    username,
	})

	ok(c, gin.H{
		"token":      token,
		"expires_at": exp,
		"username":   username,
	})
}

func (s *Server) handleMe(c *gin.Context) {
	ok(c, gin.H{
		"username": s.currentUser(c),
	})
}

func (s *Server) handleLogout(c *gin.Context) {
	// JWT 无状态，登出由前端丢弃 token 完成。
	// 这里只做一次审计留痕。
	_ = s.store.AddEvent(&model.Event{
		Category: model.EvtAuth,
		IP:       c.ClientIP(),
		Detail:   "面板登出",
		Actor:    s.currentUser(c),
	})
	ok(c, gin.H{"message": "已登出"})
}

func (s *Server) handleChangePassword(c *gin.Context) {
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请求格式不正确")
		return
	}
	if len(req.NewPassword) < 8 {
		badRequest(c, "新密码至少 8 位")
		return
	}

	s.credMu.RLock()
	hash := s.passHash
	s.credMu.RUnlock()

	if !config.CheckPassword(hash, req.OldPassword) {
		badRequest(c, "原密码不正确")
		return
	}

	newHash, err := config.HashPassword(req.NewPassword)
	if err != nil {
		serverErr(c, err)
		return
	}

	// 落库，优先于配置文件生效
	if err := s.store.SetSetting(model.SettingPasswordHash, newHash); err != nil {
		serverErr(c, err)
		return
	}

	s.credMu.Lock()
	s.passHash = newHash
	s.credMu.Unlock()

	_ = s.store.AddEvent(&model.Event{
		Category: model.EvtAuth,
		IP:       c.ClientIP(),
		Detail:   "修改面板密码",
		Actor:    s.currentUser(c),
	})

	ok(c, gin.H{"message": "密码已更新，请用新密码重新登录"})
}
