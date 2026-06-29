package ratelimit

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// prefix is a parsed trusted-proxy entry (a CIDR or a single address).
type prefix struct{ p netip.Prefix }

func (pp prefix) contains(a netip.Addr) bool { return pp.p.Contains(a) }

// parsePrefixes parses the trusted-proxy list (CIDRs or bare IPs). It is called
// both by Validate (to surface config errors) and New (to build the parsed set).
func parsePrefixes(cidrs []string) ([]prefix, error) {
	out := make([]prefix, 0, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if strings.Contains(c, "/") {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				return nil, fmt.Errorf("ratelimit: invalid trusted proxy CIDR %q: %w", c, err)
			}
			out = append(out, prefix{p.Masked()})
			continue
		}
		a, err := netip.ParseAddr(c)
		if err != nil {
			return nil, fmt.Errorf("ratelimit: invalid trusted proxy address %q: %w", c, err)
		}
		out = append(out, prefix{netip.PrefixFrom(a, a.BitLen())})
	}
	return out, nil
}

// ClientIP returns the client IP to key per-IP limiting on. A forwarded header
// is honoured only when the request's RemoteAddr is a configured trusted proxy;
// otherwise RemoteAddr's IP is used (review finding #8). With a proxy chain the
// rightmost address in the header that is not itself a trusted proxy is taken as
// the real client. A nil *Limiter (disabled / no trusted proxies) returns the
// RemoteAddr IP.
func (l *Limiter) ClientIP(r *http.Request) string {
	host := remoteHost(r.RemoteAddr)
	if l == nil || len(l.proxies) == 0 {
		return host
	}
	ra, err := netip.ParseAddr(host)
	if err != nil || !l.trusted(ra) {
		// RemoteAddr is not a trusted proxy: the forwarded header is
		// untrustworthy (spoofable), so we key on the direct peer.
		return host
	}
	hdr := r.Header.Get(l.forwardedHeader)
	if hdr == "" {
		return host
	}
	parts := strings.Split(hdr, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(parts[i])
		a, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		if !l.trusted(a) {
			return a.String()
		}
	}
	// Every hop was a trusted proxy; fall back to the direct peer.
	return host
}

func (l *Limiter) trusted(a netip.Addr) bool {
	for _, p := range l.proxies {
		if p.contains(a) {
			return true
		}
	}
	return false
}

// remoteHost strips the port from RemoteAddr, returning the raw string when it
// has no port (best-effort — RemoteAddr is normally host:port).
func remoteHost(remoteAddr string) string {
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return h
	}
	return remoteAddr
}
