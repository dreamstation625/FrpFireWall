package api

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/dreamstation625/FrpFireWall/internal/config"
	"github.com/dreamstation625/FrpFireWall/internal/model"
)

// storedConfig 从数据库还原配置。密钥类（JWT、初始化令牌）不在其中。
func (s *Server) storedConfig() (*config.Config, error) {
	m, err := s.store.AllSettings()
	if err != nil {
		return nil, err
	}
	return config.FromSettings(m)
}

// effectiveSettings 是"当前进程里正在生效"的配置快照。
//
// 与启动时那份 s.cfg 唯一的区别在支持热改的字段上：目前是 frp 代理端口
// （PUT /frps/protect-ports 保存后立即生效）与事件保留天数（保存系统配置后
// 立即生效）。不把这两者区分开的话，在 frp 接入页改完端口、或在系统设置里
// 改完保留天数，配置页会一直标着"需要重启"——而它们其实已经在生效了。
//
// 不直接改 s.cfg 是有意的：那份配置被多个组件共享（驱动、guard 都拿着同一个
// 指针），运行期就地改字段会让"这份配置是什么时候的"变得没法回答。
func (s *Server) effectiveSettings() map[string]string {
	m := s.cfg.ToSettings()
	_, proxyPorts, _ := s.guard.FrpsPorts()
	m[config.KeyProxyPorts] = proxyPorts.String()
	m[config.KeyEventRetention] = strconv.Itoa(s.guard.EventRetention())
	return m
}

// settingsDiffer 比较入库的配置与当前进程生效值是否有实质差异。
func settingsDiffer(cfg *config.Config, effective map[string]string) bool {
	for k, v := range cfg.ToSettings() {
		if effective[k] != v {
			return true
		}
	}
	return false
}

// handleGetConfig 返回已保存的配置，并指出是否与当前进程生效的一致。
func (s *Server) handleGetConfig(c *gin.Context) {
	cfg, err := s.storedConfig()
	if err != nil {
		serverErr(c, err)
		return
	}
	cfg.DataDir = s.cfg.DataDir
	ok(c, gin.H{
		"config":           cfg,
		"restart_required": settingsDiffer(cfg, s.effectiveSettings()),
		"data_dir":         s.cfg.DataDir,
	})
}

// handleUpdateConfig 保存配置。
//
// 监听地址、TLS、日志这类参数在进程启动时就已经生效，运行期改不了，
// 所以这里只落库并如实告诉前端"需要重启"，不做假的热更新。
func (s *Server) handleUpdateConfig(c *gin.Context) {
	var in config.Config
	if err := c.ShouldBindJSON(&in); err != nil {
		// 把底层原因带上：这个 body 里唯一有自由文本写法的就是端口这类字段，
		// 只说一句"请求格式不正确"，用户对着它猜不出自己哪里写错了。
		badRequest(c, "配置格式不正确："+err.Error())
		return
	}

	// 数据目录由启动参数决定，不接受接口修改
	in.DataDir = s.cfg.DataDir
	if err := in.Validate(); err != nil {
		badRequest(c, err.Error())
		return
	}

	if err := s.store.SetSettings(in.ToSettings()); err != nil {
		serverErr(c, err)
		return
	}

	// 事件保留期走热更路径：落库之后立刻换成新的运行期值，并按新保留期清一次
	// 超期数据 —— 不必重启，也不必等下一个清理周期。其余字段（监听地址、TLS、
	// 日志）仍然是"存下来、重启才生效"。
	s.guard.SetEventRetention(in.Event.RetentionDays)

	_ = s.store.AddEvent(&model.Event{
		Category: model.EvtConfig,
		IP:       c.ClientIP(),
		Detail:   "更新系统配置",
		Actor:    s.currentUser(c),
	})

	ok(c, gin.H{
		"restart_required": settingsDiffer(&in, s.effectiveSettings()),
		"message":          "配置已保存，重启服务后生效",
	})
}
