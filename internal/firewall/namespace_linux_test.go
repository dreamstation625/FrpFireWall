//go:build linux

package firewall

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreamstation625/FrpFireWall/internal/portrange"
)

// 必须明确启用且已进入独立 net namespace，防止测试误改宿主机规则。
func requireIsolatedNetwork(t *testing.T) {
	t.Helper()
	if os.Getenv("FRPFIREWALL_NAMESPACE_TEST") != "1" {
		t.Skip("仅在隔离网络空间中启用")
	}
	a, e1 := os.Readlink("/proc/self/ns/net")
	b, e2 := os.Readlink("/proc/1/ns/net")
	if e1 != nil || e2 != nil || a == b {
		t.Fatal("拒绝在宿主机网络空间执行防火墙测试")
	}
}

func namespaceCommand(t *testing.T, cmd string, args ...string) string {
	t.Helper()
	out, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v %s", cmd, args, err, out)
	}
	return string(out)
}

func TestIsolatedFirewallTransactions(t *testing.T) {
	requireIsolatedNetwork(t)
	namespaceCommand(t, "ip", "link", "set", "lo", "up")
	for _, ip := range []string{"203.0.113.2/32", "198.51.100.2/32", "198.51.100.3/32"} {
		namespaceCommand(t, "ip", "addr", "add", ip, "dev", "lo")
	}
	ln, err := net.Listen("tcp", "203.0.113.2:7000")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	connect := func(ip string) bool {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)}, Timeout: 250 * time.Millisecond}
		c, err := d.Dial("tcp", "203.0.113.2:7000")
		if err != nil {
			return false
		}
		c.Close()
		return true
	}
	if !connect("198.51.100.2") {
		t.Fatal("隔离测试基线不可连接")
	}
	ctx := context.Background()
	report := &Report{HasIPTables: true, HasNFTables: true, NFTablesVersion: "1.0.6"}
	ipt, err := New(ctx, "iptables", report)
	if err != nil {
		t.Fatal(err)
	}
	des := Desired{Blacklist: []string{"198.51.100.2/32"}}
	if err = ipt.Sync(des); err != nil {
		t.Fatal(err)
	}
	if connect("198.51.100.2") || !connect("198.51.100.3") {
		t.Fatal("iptables 封禁或非目标连接不符合预期")
	}
	// 非法规则预检失败后，旧规则必须继续保护。
	bad := des
	bad.RateLimits = []RateLimitRule{{Key: "bad", PerSec: int(^uint(0) >> 1), Ports: portrange.Ports(7000), Sources: []string{"198.51.100.2/32"}, Burst: 1}}
	if err = ipt.Sync(bad); err == nil {
		t.Fatal("非法内核限速参数应使预检失败")
	}
	if connect("198.51.100.2") {
		t.Fatal("失败同步丢失旧封禁")
	}
	// 使用 restore API 的非法目标测试回滚前置校验，不清空已生效规则。
	if err = ipt.Restore("# executable FRPFIREWALL_GUARD\n-A FRPFIREWALL_GUARD -j RETURN\n"); err == nil {
		t.Fatal("非法快照可执行文件未被拒绝")
	}
	if connect("198.51.100.2") {
		t.Fatal("非法恢复清除了旧封禁")
	}
	// 20 个范围需要分为 3 块；在实际 multiport 模块上提交。
	var ranges portrange.Set
	for i := 0; i < 20; i++ {
		ranges = ranges.Merge(portrange.Span(1000+i*1000, 1499+i*1000))
	}
	withPorts := des
	withPorts.PortBlacklists = []PortBlacklist{{Key: ranges.String(), Prefixes: []string{"198.51.100.3/32"}, Ports: ranges}}
	if err = ipt.Sync(withPorts); err != nil {
		t.Fatal(err)
	}
	if err = ipt.Sync(des); err != nil {
		t.Fatal(err)
	}
	nft, err := New(ctx, "nftables", report)
	if err != nil {
		t.Fatal(err)
	}
	if err = nft.Sync(des); err != nil {
		t.Fatal(err)
	}
	if err = Cleanup(ipt); err != nil {
		t.Fatal(err)
	}
	if connect("198.51.100.2") || !connect("198.51.100.3") {
		t.Fatal("iptables → nft 迁移后保护不正确")
	}
	if err = nft.Sync(Desired{}); err != nil {
		t.Fatal(err)
	}
	if !connect("198.51.100.2") {
		t.Fatal("nft 解封不生效或残留旧后端规则")
	}
	// 重叠的全局 1/s 不能覆盖首条 100/s 的细分规则。
	rate := Desired{RateLimits: []RateLimitRule{{Key: "fine", PerSec: 100, Burst: 100, Ports: portrange.Ports(7000), Sources: []string{"198.51.100.3/32"}}, {Key: "global", PerSec: 1, Burst: 1, Ports: portrange.Ports(7000)}}}
	if err = nft.Sync(rate); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if !connect("198.51.100.3") {
			t.Fatal("nft 细分规则被全局限速叠加")
		}
	}
	if err = ipt.Sync(rate); err != nil {
		t.Fatal(err)
	}
	if err = Cleanup(nft); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if !connect("198.51.100.3") {
			t.Fatal("iptables 细分规则被全局限速叠加")
		}
	}
	if err = Cleanup(ipt); err != nil {
		t.Fatal(err)
	}
	// 既有系统 DROP 必须继续执行，细分规则的 RETURN 只能退出受管子链。
	namespaceCommand(t, "nft", "add", "table", "inet", "system_test")
	namespaceCommand(t, "nft", "add", "chain", "inet", "system_test", "input", "{ type filter hook input priority 10; policy drop; }")
	if err = nft.Sync(rate); err != nil {
		t.Fatal(err)
	}
	if connect("198.51.100.3") {
		t.Fatal("受管规则绕过了系统 DROP")
	}
	if err = Cleanup(nft); err != nil {
		t.Fatal(err)
	}
	all := namespaceCommand(t, "nft", "list", "ruleset")
	if strings.Contains(all, "frpfirewall:rate") || strings.Contains(all, "FRPFIREWALL_GUARD") {
		t.Fatal("清理后存在受管拦截规则")
	}
	if !strings.Contains(all, "policy drop") {
		t.Fatal("系统策略被覆盖")
	}
}

func TestIsolatedNFTWithoutInputAndExistingDropPolicy(t *testing.T) {
	requireIsolatedNetwork(t)
	namespaceCommand(t, "nft", "add", "table", "inet", "filter")
	namespaceCommand(t, "nft", "add", "chain", "inet", "filter", "input", "{ type filter hook input priority 0; policy drop; }")
	d := newNFTablesDriver(&Report{HasNFTables: true, NFTablesVersion: "1.0.6"})
	if err := d.Sync(Desired{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(namespaceCommand(t, "nft", "list", "chain", "inet", "filter", "input"), "policy drop") {
		t.Fatal("系统 input policy 被改变")
	}
}

func TestIsolatedNFTCreatesOnlyOwnedTableOnEmptyRuleset(t *testing.T) {
	requireIsolatedNetwork(t)
	d := newNFTablesDriver(&Report{HasNFTables: true, NFTablesVersion: "1.0.6"})
	if err := d.Sync(Desired{Blacklist: []string{"198.51.100.2/32", "198.51.100.0/24"}}); err != nil {
		t.Fatal(err)
	}
	out := namespaceCommand(t, "nft", "list", "ruleset")
	if !strings.Contains(out, "table inet frpfirewall") || strings.Contains(out, "table inet filter") {
		t.Fatal("空规则集创建了非受管表")
	}
	if err := d.Cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestIsolatedNFTReadFailuresDoNotCreateChains(t *testing.T) {
	requireIsolatedNetwork(t)
	for _, response := range []string{"exit 1", "printf 'invalid JSON'", "printf '{}'"} {
		t.Run(response, func(t *testing.T) {
			dir := t.TempDir()
			log := filepath.Join(dir, "calls")
			script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + log + "'\n" + response + "\n"
			if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
			d := newNFTablesDriver(&Report{HasNFTables: true})
			if err := d.EnsureBase(); err == nil {
				t.Fatal("读取失败未中止")
			}
			calls, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			if string(calls) != "-j list ruleset\n" {
				t.Fatalf("读取失败后仍执行了命令: %s", calls)
			}
		})
	}
}

func TestIsolatedPanicScriptPreservesForeignRules(t *testing.T) {
	requireIsolatedNetwork(t)
	script := os.Getenv("FRPFIREWALL_PANIC_SCRIPT")
	if script == "" {
		t.Skip("需要显式提供救援脚本路径")
	}
	ctx := context.Background()
	report := &Report{HasIPTables: true, HasNFTables: true, NFTablesVersion: "1.0.6"}
	ipt, err := New(ctx, "iptables", report)
	if err != nil {
		t.Fatal(err)
	}
	nft, err := New(ctx, "nftables", report)
	if err != nil {
		t.Fatal(err)
	}
	des := Desired{Blacklist: []string{"198.51.100.2/32"}, PortBlacklists: []PortBlacklist{{Key: "7000", Prefixes: []string{"198.51.100.3/32"}, Ports: portrange.Ports(7000)}}, RateLimits: []RateLimitRule{{Key: "rescue", PerSec: 1, Burst: 1, Ports: portrange.Ports(7000)}}}
	if err = ipt.Sync(des); err != nil {
		t.Fatal(err)
	}
	if err = nft.Sync(des); err != nil {
		t.Fatal(err)
	}
	namespaceCommand(t, "nft", "add", "table", "inet", "foreign")
	namespaceCommand(t, "nft", "add", "chain", "inet", "foreign", "input", "{ type filter hook input priority 10; policy drop; }")
	namespaceCommand(t, "nft", "add", "rule", "inet", "foreign", "input", "tcp dport 22 accept comment \"keep me\"")
	before := namespaceCommand(t, "nft", "-s", "list", "ruleset")
	namespaceCommand(t, "bash", script, "--dry-run")
	if after := namespaceCommand(t, "nft", "-s", "list", "ruleset"); before != after {
		t.Fatal("救援预览修改了规则")
	}
	namespaceCommand(t, "bash", script, "--yes")
	all := namespaceCommand(t, "nft", "list", "ruleset")
	if strings.Contains(all, "frpfirewall:") || strings.Contains(all, "FRPFIREWALL_") || strings.Contains(all, nftRateChain) {
		t.Fatalf("受管对象清理不完整: %s", all)
	}
	if !strings.Contains(all, "policy drop") || !strings.Contains(all, "keep me") {
		t.Fatal("误删系统策略或规则")
	}
	// 重复运行仍应成功。
	namespaceCommand(t, "bash", script, "--yes")
}
