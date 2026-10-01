package api

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/dreamstation625/FrpFireWall/internal/model"
)

func ptrBool(v bool) *bool { return &v }

func TestNormalizeRateRules(t *testing.T) {
	t.Run("按下标定优先级并清掉客户端传来的 ID", func(t *testing.T) {
		in := []rateRuleInput{
			{Name: "第二", Countries: "HK", PerSec: 5},
			{Name: "第一", Ports: "20000-30000", PerSec: 9},
		}
		out, err := normalizeRateRules(in)
		if err != nil {
			t.Fatal(err)
		}
		if out[0].Priority != 0 || out[1].Priority != 1 {
			t.Errorf("priority 应当按下标重排，实际 %d / %d", out[0].Priority, out[1].Priority)
		}
		for i, r := range out {
			if r.ID != 0 {
				t.Errorf("第 %d 条的 ID 应当被清掉（规则每次保存都是整体重建），实际 %d", i+1, r.ID)
			}
		}
		if out[0].Name != "第二" {
			t.Errorf("顺序不该被改动，实际 %q 在首位", out[0].Name)
		}
	})

	t.Run("先归一化再校验", func(t *testing.T) {
		// 「广东省」只有在归一化之后才是候选表里认得的「广东」。
		// 实现里如果先 Validate 再 Normalize，这条会以"省份无法识别"被拒。
		in := []rateRuleInput{{Name: "广东访客", Provinces: "广东省", Cidrs: "203.0.113.7", PerSec: 5}}
		out, err := normalizeRateRules(in)
		if err != nil {
			t.Fatalf("归一化过的输入不该被拒：%v", err)
		}
		if out[0].Provinces != "广东" {
			t.Errorf("省份应当被归一化成 广东，实际 %q", out[0].Provinces)
		}
		if out[0].CIDRs != "203.0.113.7/32" {
			t.Errorf("裸 IP 应当被补成 /32，实际 %q", out[0].CIDRs)
		}
		if out[0].Burst != 10 {
			t.Errorf("未配突发额度应当按 PerSec*2 补齐，实际 %d", out[0].Burst)
		}
	})

	t.Run("错误信息要指出是第几条", func(t *testing.T) {
		in := []rateRuleInput{
			{Name: "好的", Countries: "HK", PerSec: 5},
			{Name: "坏的", Countries: "HK", Ports: "443", PerSec: 5}, // 地区 + 端口
		}
		_, err := normalizeRateRules(in)
		if err == nil {
			t.Fatal("混搭条件应当被拒")
		}
		if !strings.HasPrefix(err.Error(), "第 2 条规则：") {
			t.Errorf("错误信息应当以「第 2 条规则：」开头，实际 %q", err.Error())
		}
		if !strings.Contains(err.Error(), "无法生效") {
			t.Errorf("应当说明为什么不能生效，实际 %q", err.Error())
		}
	})

	t.Run("不止第一条会出错", func(t *testing.T) {
		// 逐条校验意味着下标必须跟着循环走，不能一直报"第 1 条"。
		in := []rateRuleInput{
			{Name: "一", Countries: "HK", PerSec: 5},
			{Name: "二", Countries: "US", PerSec: 5},
			{Name: "三", PerSec: 5}, // 没有任何条件
		}
		_, err := normalizeRateRules(in)
		if err == nil || !strings.HasPrefix(err.Error(), "第 3 条规则：") {
			t.Fatalf("应当报第 3 条，实际 %v", err)
		}
	})

	t.Run("空列表合法", func(t *testing.T) {
		out, err := normalizeRateRules(nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 0 {
			t.Errorf("空列表应当归一化成空列表，实际 %+v", out)
		}
	})
}

// 不带 enabled 的规则必须**默认启用**。
//
// 这条是踩出来的：去掉了模型上的 default:true（GORM 会用它把显式写入的 false 吃掉），
// 默认启用的责任就落到了接口层。漏掉这一层的话，从 curl / 脚本建出来的规则
// 一律是停用状态 —— 库里存着、界面列表里也显示着，实际一条都没进判定引擎。
func TestRateRuleInputDefaultsEnabled(t *testing.T) {
	cases := []struct {
		name string
		in   rateRuleInput
		want bool
	}{
		{"不带 enabled → 启用", rateRuleInput{Name: "x", Countries: "HK", PerSec: 5}, true},
		{"显式 true → 启用", rateRuleInput{Name: "x", Countries: "HK", PerSec: 5, Enabled: ptrBool(true)}, true},
		{"显式 false → 停用", rateRuleInput{Name: "x", Countries: "HK", PerSec: 5, Enabled: ptrBool(false)}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.in.toModel().Enabled; got != c.want {
				t.Errorf("Enabled = %v，期望 %v", got, c.want)
			}
		})
	}

	// 走一遍 JSON：字段缺席和显式 null 都要落到"启用"
	for _, body := range []string{
		`{"name":"x","countries":"HK","per_sec":5}`,
		`{"name":"x","countries":"HK","per_sec":5,"enabled":null}`,
	} {
		var in rateRuleInput
		if err := json.Unmarshal([]byte(body), &in); err != nil {
			t.Fatal(err)
		}
		if !in.toModel().Enabled {
			t.Errorf("%s 应当默认启用", body)
		}
	}
}

// rateRuleInput 必须覆盖 model.RateRule 的**全部可写字段**。
//
// 这份 DTO 是模型可写字段的手抄副本，存在的唯一理由是 Enabled 需要指针。
// 手抄就会漂移：模型加了字段、接口层忘了加，结果是那个字段**接收不到、静默丢弃** ——
// 用户填了却不起作用，而且不报错。这条测试用反射把"可写字段集合"钉死，
// 加字段时它会红，提醒来这里同步。
func TestRateRuleInputCoversAllWritableFields(t *testing.T) {
	// 由服务端决定的字段，不接受客户端传值（priority 取数组下标，id 每次重建）。
	readOnly := map[string]bool{
		"id":         true,
		"priority":   true,
		"created_at": true,
		"updated_at": true,
	}

	inputTags := map[string]bool{}
	it := reflect.TypeOf(rateRuleInput{})
	for i := 0; i < it.NumField(); i++ {
		tag := jsonTag(it.Field(i))
		if tag != "" {
			inputTags[tag] = true
		}
	}

	mt := reflect.TypeOf(model.RateRule{})
	writable := 0
	for i := 0; i < mt.NumField(); i++ {
		f := mt.Field(i)
		tag := jsonTag(f)
		if tag == "" || readOnly[tag] {
			continue
		}
		writable++
		if !inputTags[tag] {
			t.Errorf("model.RateRule 的可写字段 %q（Go 字段 %s）没有出现在 rateRuleInput 里，"+
				"客户端传了这个字段会被静默丢掉", tag, f.Name)
		}
	}

	if writable != len(inputTags) {
		t.Errorf("rateRuleInput 有 %d 个字段，model.RateRule 有 %d 个可写字段，两边对不上（多抄或少抄）",
			len(inputTags), writable)
	}
	if writable == 0 {
		t.Fatal("一个可写字段都没扫到，说明反射逻辑失效了")
	}
}

func jsonTag(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	if tag == "" || tag == "-" {
		return ""
	}
	return strings.Split(tag, ",")[0]
}

// rules 字段在请求里"缺席"和"是空数组"必须能区分开。
//
// 两者混成一种的话，一个不带 rules 的老请求（脚本、旧版前端）会把用户配好的
// 细分规则全部删掉，而且返回 200、没有任何提示 —— 这是最难被发现的那类数据丢失。
func TestPolicyRequestDistinguishesAbsentAndEmptyRules(t *testing.T) {
	t.Run("缺席 → 不动规则", func(t *testing.T) {
		var req policyRequest
		body := `{"window_seconds":60,"threshold":10,"ban_durations":"60,300"}`
		if err := json.Unmarshal([]byte(body), &req); err != nil {
			t.Fatal(err)
		}
		if req.Rules != nil {
			t.Errorf("请求里没有 rules，应当保持 nil（= 不动规则），实际 %+v", *req.Rules)
		}
		if req.WindowSeconds != 60 || req.BanDurations != "60,300" {
			t.Errorf("内嵌的策略字段没绑上：%+v", req.Policy)
		}
	})

	t.Run("空数组 → 清空规则", func(t *testing.T) {
		var req policyRequest
		if err := json.Unmarshal([]byte(`{"window_seconds":60,"rules":[]}`), &req); err != nil {
			t.Fatal(err)
		}
		if req.Rules == nil {
			t.Fatal("显式传了空数组，应当是非 nil（= 清空），否则删不掉规则")
		}
		if len(*req.Rules) != 0 {
			t.Errorf("应当是空列表，实际 %+v", *req.Rules)
		}
	})

	t.Run("带内容的数组能绑到规则字段", func(t *testing.T) {
		var req policyRequest
		body := `{"window_seconds":60,"rules":[
			{"name":"香港访客","countries":"HK","provinces":"广东省","per_sec":5,"window_seconds":30,"threshold":3,"ban_durations":"60,300"},
			{"name":"扫描端口","ports":"20000-30000","per_sec":9,"enabled":false}
		]}`
		if err := json.Unmarshal([]byte(body), &req); err != nil {
			t.Fatal(err)
		}
		if req.Rules == nil || len(*req.Rules) != 2 {
			t.Fatalf("应当解析出 2 条规则，实际 %+v", req.Rules)
		}
		r := (*req.Rules)[0]
		if r.Name != "香港访客" || r.Countries != "HK" || r.Provinces != "广东省" || r.Threshold != 3 {
			t.Errorf("规则字段没绑对：%+v", r)
		}
		// 绑定阶段不做任何转换：归一化发生在 normalizeRateRules 里。
		// 在这里就动手的话，Validate 拿到的就不是用户填的东西了。
		if (*req.Rules)[1].Ports != "20000-30000" {
			t.Errorf("端口没绑对：%+v", (*req.Rules)[1])
		}
		if (*req.Rules)[1].Enabled == nil || *(*req.Rules)[1].Enabled {
			t.Error("显式传的 enabled=false 没绑上")
		}
	})
}

// 落点由端口条件推出，且只有这一处实现。
func TestRateRuleViewExposesLayer(t *testing.T) {
	kernel := newRateRuleView(model.RateRule{Name: "端口", Ports: "443", PerSec: 5})
	if kernel.Layer != model.LayerKernel {
		t.Errorf("带端口的规则应当标成内核层，实际 %q", kernel.Layer)
	}
	app := newRateRuleView(model.RateRule{Name: "地区", Countries: "HK", PerSec: 5})
	if app.Layer != model.LayerApp {
		t.Errorf("不带端口的规则应当标成应用层，实际 %q", app.Layer)
	}
	// 内嵌结构要能被 JSON 摊平，前端读的是 r.name / r.layer 这一层。
	b, err := json.Marshal(app)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"name":"地区"`, `"layer":"app"`, `"per_sec":5`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("序列化结果里缺少 %s：%s", want, b)
		}
	}
}
