package guard

import (
	"fmt"
	"net/netip"
	"strings"
)

// builtinTrustedProxies 是内置的可信回源网段。
//
// 为什么必须有这个：本方案的部署形态是「CDN → frps 回源」。
// frps 插件的 NewUserConn 回调只给一个 TCP 层 remote_addr，
// 在回源场景下那其实是 **CDN 边缘节点的 IP**，不是终端用户 IP。
// 如果按它做封禁，封掉一个 CDN 节点等于掐死一大片正常用户。
//
// 所以：来自这些网段的连接，只记录事件、不做任何封禁决策。
// 真实客户端 IP 的封禁需要 HTTP 层能力（nginx / 宝塔 WAF），不在本程序职责内。
var builtinTrustedProxies = []string{
	// Cloudflare 官方公布的 IPv4 回源段
	"103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
	"131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
	"172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
	"190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
	// Cloudflare IPv6
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
	"2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

// protector 负责两类"绝不能封"的地址判定。
type protector struct {
	// trusted 可信回源段：命中则跳过封禁决策。
	trusted []netip.Prefix
}

func newProtector(extra ...string) (*protector, error) {
	p := &protector{}
	var bad []string

	for _, s := range builtinTrustedProxies {
		if pre, err := netip.ParsePrefix(s); err == nil {
			p.trusted = append(p.trusted, pre.Masked())
		}
	}
	for _, s := range extra {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		pre, err := parsePrefixOrAddr(s)
		if err != nil {
			bad = append(bad, s)
			continue
		}
		p.trusted = append(p.trusted, pre)
	}
	if len(bad) > 0 {
		return p, fmt.Errorf("以下可信回源段无法解析，已忽略: %s", strings.Join(bad, ", "))
	}
	return p, nil
}

// IsSystemProtected 判断地址是否属于"无论什么情况都不能封"的范畴。
//
// 回环、私有、链路本地这些地址封了没有任何安全收益，
// 却极可能把自己（SSH、本机 frpc、内网面板访问）一起锁在门外。
func IsSystemProtected(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	addr = addr.Unmap()
	return addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified()
}

// IsTrustedProxy 判断地址是否来自可信回源网段（CDN / 反向代理）。
func (p *protector) IsTrustedProxy(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, pre := range p.trusted {
		if pre.Contains(addr) {
			return true
		}
	}
	return false
}

// TrustedCount 返回可信段数量，供 UI 展示。
func (p *protector) TrustedCount() int { return len(p.trusted) }

func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}
