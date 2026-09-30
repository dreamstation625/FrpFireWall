package api

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
)

// ---- 版本更新检查 ----

// handleUpdateStatus 返回上一次检查的缓存结果，不发起任何网络请求。
//
// 前端在打开面板时调它，可以低成本地拿到「是否已有新版本」的结论；
// 若从未检查过，checked 为 false。
func (s *Server) handleUpdateStatus(c *gin.Context) {
	if !s.cfg.Update.Enabled {
		ok(c, gin.H{
			"enabled": false,
			"checked": false,
			"repo":    s.updater.Repo(),
		})
		return
	}

	res, checked := s.updater.Peek()

	body := gin.H{
		"enabled": true,
		"checked": checked,
		"repo":    s.updater.Repo(),
	}
	// 没检查过就不要给一个空壳 result，否则前端会拿它去渲染空版本号
	if checked {
		body["result"] = res
	}
	ok(c, body)
}

// handleUpdateCheck 主动检查更新。
//
// 请求体可选 {"force": true} —— 前端「重新检查」按钮会带上它，
// 用于绕过服务端缓存（但仍受最小请求间隔保护）。普通调用走缓存，
// 因此前端可以放心在打开面板时自动调一次。
func (s *Server) handleUpdateCheck(c *gin.Context) {
	if !s.cfg.Update.Enabled {
		ok(c, gin.H{
			"enabled": false,
			"checked": false,
			"repo":    s.updater.Repo(),
			"message": "更新检查已在系统设置里关闭",
		})
		return
	}

	var body struct {
		Force bool `json:"force"`
	}
	// 允许空 body：前端自动检查时不带任何参数
	_ = c.ShouldBindJSON(&body)

	// GitHub 请求可能慢，给一个明确上限，避免拖住 gin 的协程。
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()

	res := s.updater.Check(ctx, body.Force)

	ok(c, gin.H{
		"enabled": true,
		"checked": true,
		"result":  res,
	})
}
