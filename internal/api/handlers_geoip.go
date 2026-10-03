package api

import (
	"fmt"

	"github.com/dreamstation625/FrpFireWall/internal/geoip"
	"github.com/dreamstation625/FrpFireWall/internal/model"
	"github.com/gin-gonic/gin"
)

// handleGeoSources 列出可下载的数据库与可选的加速源。
//
// 加速源列表由后端给出，前端不自己硬编码一份：两边各存一份的话，
// 后端换了源前端不知道，用户选个后端不认识的 ID 只能拿到报错。
func (s *Server) handleGeoSources(c *gin.Context) {
	ok(c, gin.H{
		"sources": geoip.Sources(),
		"mirrors": geoip.Mirrors(),
		"auto":    geoip.MirrorAuto,
		"status":  s.geo.Status(),
	})
}

type geoDownloadRequest struct {
	Name   string `json:"name"`
	Mirror string `json:"mirror"`
}

// handleGeoDownload 从上游下载一个属地库并热加载。
//
// 同步下载：GeoLite2-City 有 64MB，慢的时候要几十秒，前端拿 loading 顶着。
// 上限由 geoip 包统一控制（maxFileSize），并且下载完仍要过一遍文件头校验，
// 校验不过旧库原样在用。
func (s *Server) handleGeoDownload(c *gin.Context) {
	var req geoDownloadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请求格式不正确")
		return
	}
	if req.Name == "" {
		badRequest(c, "缺少 name 字段")
		return
	}

	// HTTP 请求断开时取消下载：用户关了页面就别再占着带宽了。
	res, err := s.geo.Download(c.Request.Context(), req.Name, req.Mirror)
	if err != nil {
		// 上游不通、文件不对、已有任务在跑 —— 都属于「这次没成功」，不是服务端故障，
		// 用 400 把原文带回前端，比一个笼统的 500 有用。
		badRequest(c, err.Error())
		return
	}

	detail := fmt.Sprintf("下载更新属地数据库 %s（%s，%d 字节）", res.Name, res.Mirror, res.Size)
	if res.Version != "" {
		detail = fmt.Sprintf("下载更新属地数据库 %s（上游版本 %s，来源 %s，%d 字节）",
			res.Name, res.Version, res.Mirror, res.Size)
	}
	_ = s.store.AddEvent(&model.Event{
		Category: model.EvtGeoIP,
		IP:       c.ClientIP(),
		Detail:   detail,
		Actor:    s.currentUser(c),
	})

	ok(c, gin.H{
		"message": "已更新并热加载",
		"result":  res,
		"status":  s.geo.Status(),
	})
}
