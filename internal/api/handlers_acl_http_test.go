package api

import (
	"net/http"
	"strconv"
	"testing"
)

// 取一条名单条目当前在**库里**的样子。
//
// 刻意不用接口返回的那份：接口返回的是请求体拼出来的对象，它正确不代表真的写进去了。
// 这次改动里最先踩到的就是这个 —— UpdateACL 的更新列漏了 ports，接口老老实实
// 把新端口回给了前端，库里却一个字节都没变，界面刷新一下又变回旧值。
func aclRow(t *testing.T, h *harness, id uint) (scope, ports, remark string) {
	t.Helper()
	e, err := h.srv.store.GetACL(id)
	if err != nil {
		t.Fatalf("读条目 %d 失败：%v", id, err)
	}
	return e.Scope, e.Ports, e.Remark
}

func entryID(t *testing.T, h *harness, r resp) uint {
	t.Helper()
	d := h.data(r)
	// JSON 数字会解成 float64
	f, ok := d["id"].(float64)
	if !ok || f <= 0 {
		t.Fatalf("接口没返回有效 id：%v", d["id"])
	}
	return uint(f)
}

// TestACLCustomPortsEndToEnd 走完"自定义端口"这条链：新增 → 落库 → 修改 → 再落库。
//
// 范围只影响内核规则怎么写（全端口丢 / 只在某些端口上丢），不影响插件层
// "是否命中"的判定 —— 插件只作用于 frp 连接、拿不到端口。所以自定义端口这一档
// 完全靠"库里那一列"决定内核封哪些端口，那一列丢了整档就是空的。
func TestACLCustomPortsEndToEnd(t *testing.T) {
	h := newHarness(t)

	// 新增：乱序 + 区间 + 重复，接口负责归一化后再入库
	code, r := h.call(http.MethodPost, "/api/v1/acl/black", map[string]any{
		"target": "203.0.113.5",
		"scope":  "custom",
		"ports":  "9000-9100, 8080 ,8080",
		"remark": "机房备用机",
	})
	if code != http.StatusOK {
		t.Fatalf("POST 应 200，得到 %d %s", code, r.Error)
	}
	id := entryID(t, h, r)
	if scope, ports, remark := aclRow(t, h, id); scope != "custom" || ports != "8080,9000-9100" || remark != "机房备用机" {
		t.Fatalf("入库结果 = (%q, %q, %q)，期望 (custom, 8080,9000-9100, 机房备用机)", scope, ports, remark)
	}

	// 修改端口：只传 ports，scope 不动
	code, r = h.call(http.MethodPut, "/api/v1/acl/black/"+strconv.Itoa(int(id)), map[string]any{"ports": "8081"})
	if code != http.StatusOK {
		t.Fatalf("PUT 应 200，得到 %d %s", code, r.Error)
	}
	if _, ports, _ := aclRow(t, h, id); ports != "8081" {
		t.Errorf("改完端口后库里 = %q，期望 8081（接口的值和库里的值必须一致）", ports)
	}

	// 换成非自定义范围：端口必须被清掉。
	// 库里残留一份不参与生效的端口是"配置里写着、实际不生效"那类最难排查的问题。
	code, r = h.call(http.MethodPut, "/api/v1/acl/black/"+strconv.Itoa(int(id)), map[string]any{"scope": "frp"})
	if code != http.StatusOK {
		t.Fatalf("PUT 应 200，得到 %d %s", code, r.Error)
	}
	if scope, ports, _ := aclRow(t, h, id); scope != "frp" || ports != "" {
		t.Errorf("切到 frp 范围后 = (%q, %q)，期望 (frp, 空)", scope, ports)
	}

	// 只改备注的请求不带 scope / ports，不能把范围偷偷放宽成"封全部端口"
	code, r = h.call(http.MethodPut, "/api/v1/acl/black/"+strconv.Itoa(int(id)), map[string]any{"remark": "改个备注"})
	if code != http.StatusOK {
		t.Fatalf("PUT 应 200，得到 %d %s", code, r.Error)
	}
	if scope, _, remark := aclRow(t, h, id); scope != "frp" || remark != "改个备注" {
		t.Errorf("只改备注后 = (%q, %q)，范围不该被改动", scope, remark)
	}

	// 重新添加同一个地址走的是 upsert 分支：端口是这次改动的本体，必须跟着更新
	code, r = h.call(http.MethodPost, "/api/v1/acl/black", map[string]any{
		"target": "203.0.113.5",
		"scope":  "custom",
		"ports":  "7000-7100",
	})
	if code != http.StatusOK {
		t.Fatalf("重复 POST 应 200，得到 %d %s", code, r.Error)
	}
	if scope, ports, _ := aclRow(t, h, id); scope != "custom" || ports != "7000-7100" {
		t.Errorf("重复添加后 = (%q, %q)，期望 (custom, 7000-7100)", scope, ports)
	}
}

// TestACLCustomPortsRejectsBadInput 自定义范围写不出端口时必须当场报错。
//
// 放过去的后果是"名单上它在、内核对不上"：范围是自定义却没有端口，内核一条
// 规则都生成不出来，而列表里它显示成一条正常生效中的条目。
func TestACLCustomPortsRejectsBadInput(t *testing.T) {
	h := newHarness(t)

	cases := []struct {
		name string
		body map[string]any
	}{
		{"缺端口", map[string]any{"target": "203.0.113.6", "scope": "custom"}},
		{"端口为空串", map[string]any{"target": "203.0.113.6", "scope": "custom", "ports": ""}},
		{"端口非法", map[string]any{"target": "203.0.113.6", "scope": "custom", "ports": "8080~9000"}},
		{"端口越界", map[string]any{"target": "203.0.113.6", "scope": "custom", "ports": "70000"}},
		// 范围写法只属于导入文件那一列，接口参数收到的是裸范围名
		{"把导入写法当接口参数", map[string]any{"target": "203.0.113.6", "scope": "custom:8080"}},
		{"未知范围", map[string]any{"target": "203.0.113.6", "scope": "some"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, r := h.call(http.MethodPost, "/api/v1/acl/black", c.body)
			if code != http.StatusBadRequest {
				t.Fatalf("应 400，得到 %d %s", code, r.Error)
			}
		})
	}

	// 白名单条目本身不产生任何封禁动作，范围恒为 all：手工塞进来的端口
	// 不能在库里留下一句读不懂也没用途的话。
	code, r := h.call(http.MethodPost, "/api/v1/acl/white", map[string]any{
		"target": "203.0.113.7",
		"scope":  "custom",
		"ports":  "8080",
	})
	if code != http.StatusOK {
		t.Fatalf("白名单条目应正常新增，得到 %d %s", code, r.Error)
	}
	if scope, ports, _ := aclRow(t, h, entryID(t, h, r)); scope != "all" || ports != "" {
		t.Errorf("白名单条目 = (%q, %q)，期望 (all, 空)", scope, ports)
	}
}
