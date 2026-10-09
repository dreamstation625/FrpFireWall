package guard

import (
	"net/netip"
	"strings"
)

var systemProtected = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"0.0.0.0/32", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// subtractPrefixes 按前缀拆分差集，不枚举网段内的地址。
func subtractPrefixes(p netip.Prefix, exceptions []netip.Prefix) []netip.Prefix {
	out := []netip.Prefix{p.Masked()}
	for _, e := range exceptions {
		var next []netip.Prefix
		for _, x := range out {
			next = append(next, subtractPrefix(x, e.Masked())...)
		}
		out = next
	}
	return out
}

func subtractPrefix(p, e netip.Prefix) []netip.Prefix {
	if p.Addr().BitLen() != e.Addr().BitLen() || !p.Overlaps(e) {
		return []netip.Prefix{p}
	}
	if e.Bits() <= p.Bits() {
		return nil
	}
	bits := p.Bits() + 1
	a := p.Addr()
	var other netip.Addr
	if a.Is4() {
		b := a.As4()
		b[p.Bits()/8] |= 1 << (7 - p.Bits()%8)
		other = netip.AddrFrom4(b)
	} else {
		b := a.As16()
		b[p.Bits()/8] |= 1 << (7 - p.Bits()%8)
		other = netip.AddrFrom16(b)
	}
	return append(subtractPrefix(netip.PrefixFrom(a, bits), e), subtractPrefix(netip.PrefixFrom(other, bits), e)...)
}

func (b *tokenBucket) resetPrefix(p netip.Prefix) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for k := range b.state {
		if a, err := netip.ParseAddr(k[strings.LastIndex(k, "|")+1:]); err == nil && p.Contains(a) {
			delete(b.state, k)
		}
	}
}
