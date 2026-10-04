package api

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"github.com/dreamstation625/FrpFireWall/internal/model"
)

// ---- 频控细分规则 ----

// rateRuleView 是给界面的规则形态：在存储结构上补一个"落点"。
//
// 落点不落库、由"有没有端口条件"推出来（见 model.RateRule 的注释），
// 这里算一遍给前端就行。让前端自己再推一套的话，两边只要有一边改了，
// 界面上就会显示"落在内核层"而实际落在应用层。
type rateRuleView struct {
	model.RateRule
	Layer string `json:"layer"`
}

func newRateRuleView(r model.RateRule) rateRuleView {
	return rateRuleView{RateRule: r, Layer: r.Layer()}
}

func (s *Server) handleListRateRules(c *gin.Context) {
	rows, err := s.store.RateRules()
	if err != nil {
		serverErr(c, err)
		return
	}
	out := make([]rateRuleView, 0, len(rows))
	for _, r := range rows {
		out = append(out, newRateRuleView(r))
	}
	ok(c, gin.H{"rules": out})
}

// rateRuleInput 是请求体里的一条细分规则。
//
// 不直接拿 model.RateRule 绑定，唯一但关键的原因是 Enabled 必须是**指针**：
// 「没有这个字段」要按启用处理，传 false 才是停用。用值类型的话两者都是 false，
// 一个不带 enabled 的请求会创建出一条**静默不生效**的规则 ——
// 库里存着、列表里显示着、实际一条都没编译进判定引擎。
// （模型的列上也没有 DB 默认值可用：GORM 对带默认值的布尔字段会跳过零值写入，
// 那正好会把显式写入的 false 反过来吃掉，见 model.RateRule 的注释。）
//
// 字段与 model.RateRule 的可写集合一一对应 —— id / priority / layer / 时间戳
// 由服务端决定（priority 取数组下标）。对应的往返测试是
// TestRateRuleInputCoversAllWritableFields，加字段时它会提醒这里也要加。
type rateRuleInput struct {
	Name          string `json:"name"`
	Enabled       *bool  `json:"enabled"`
	Countries     string `json:"countries"`
	Provinces     string `json:"provinces"`
	Cities        string `json:"cities"`
	Cidrs         string `json:"cidrs"`
	Ports         string `json:"ports"`
	Block         bool   `json:"block"`
	PerSec        int    `json:"per_sec"`
	Burst         int    `json:"burst"`
	WindowSeconds int    `json:"window_seconds"`
	Threshold     int    `json:"threshold"`
	BanDurations  string `json:"ban_durations"`
	Remark        string `json:"remark"`
}

// toModel 转成存储模型。缺 enabled 时按启用处理。
func (in rateRuleInput) toModel() model.RateRule {
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	return model.RateRule{
		Name:          in.Name,
		Enabled:       enabled,
		Countries:     in.Countries,
		Provinces:     in.Provinces,
		Cities:        in.Cities,
		CIDRs:         in.Cidrs,
		Ports:         in.Ports,
		Block:         in.Block,
		PerSec:        in.PerSec,
		Burst:         in.Burst,
		WindowSeconds: in.WindowSeconds,
		Threshold:     in.Threshold,
		BanDurations:  in.BanDurations,
		Remark:        in.Remark,
	}
}

// policyRequest 是 PUT /policy 的请求体。
//
// Rules 用**指针**：没有这个字段表示"这次不动规则"（脚本、老客户端），
// 传空数组才表示"把规则全删"。用值类型的话这两种请求长得一样，
// 一个不带 rules 的请求会把用户配好的规则全部清空，而且返回 200。
type policyRequest struct {
	model.Policy
	Rules *[]rateRuleInput `json:"rules"`
}

// normalizeRateRules 规范化 + 校验一批规则，任一条不过就整体拒绝。
//
// **先 Normalize 再 Validate**，顺序不能反：Normalize 会把「广东省」收敛成「广东」、
// 把裸 IP 补成 /32，而 Validate 的省份白名单和端口解析都建立在这个形态上。
// 反过来做的话，用户规规矩矩填的「广东省」会被判成"无法识别"。
//
// ID 一律清零、priority 按下标重排：规则每次保存都是整体重建（见 store 里的说明），
// 接受客户端传来的 ID 只会让人误以为 ID 是稳定的。
func normalizeRateRules(inputs []rateRuleInput) ([]model.RateRule, error) {
	out := make([]model.RateRule, 0, len(inputs))
	for i := range inputs {
		r := inputs[i].toModel()
		r.Normalize()
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("第 %d 条规则：%w", i+1, err)
		}
		r.ID = 0
		r.Priority = i
		out = append(out, r)
	}
	return out, nil
}

// handleGeoProvinces 返回省份候选值，供规则编辑器做多选。
//
// 走服务端的理由和 /geoip/countries 一样：规则里存的省份名必须和
// 属地库返回的名字是同一套写法，候选表放在前端就等于把这份约定抄了一份。
func (s *Server) handleGeoProvinces(c *gin.Context) {
	ok(c, gin.H{
		"provinces": model.Provinces(),
		// 省份只在有属地库时才有意义，和地域封禁用的是同一个前提。
		"available": s.geo.CountryBlockAvailable(),
	})
}
