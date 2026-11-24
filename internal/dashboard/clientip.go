package dashboard

import (
	"context"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
)

// Who is the visitor? The address the connection comes from, unless that is a
// reverse proxy listed in dashboard.trusted_proxies: only then is
// X-Forwarded-For read. Anyone can send that header, so believing a stranger's
// would let a visitor dodge the login lockout and choose the address shown
// beside a login or an approval.

type clientKey struct{}

// withClient works out the visitor's address once and attaches it to the request.
func withClient(r *http.Request, trusted []netip.Prefix) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), clientKey{}, findClient(r, trusted)))
}

// extractClientIP is the visitor's address, for the login lockout and the
// audit log. Without withClient it is the socket's.
func extractClientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(clientKey{}).(string); ok {
		return ip
	}
	return findClient(r, nil)
}

// isTLS reports whether the login cookie gets its Secure flag: the request came
// over HTTPS, or says a proxy in front did. X-Forwarded-Proto is believed from
// anyone on purpose. It can only make the sender's own cookie stricter, so a
// lie gains nothing, while not believing it would take Secure away from every
// install behind a proxy that has not set trusted_proxies yet. It must never
// decide anything else.
func isTLS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// findClient reads X-Forwarded-For only when the peer is trusted. Proxies
// append to it, so it is walked from the right: the first hop that is not a
// trusted proxy is the visitor, and everything left of it is whatever the
// visitor chose to send.
func findClient(r *http.Request, trusted []netip.Prefix) string {
	peer, ok := parseHop(r.RemoteAddr)
	if !ok {
		return r.RemoteAddr
	}
	ip := peer.String()
	if !contains(trusted, peer) {
		return ip
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop, ok := parseHop(strings.TrimSpace(hops[i]))
		if !ok {
			break
		}
		ip = hop.String()
		if !contains(trusted, hop) {
			break
		}
	}
	return ip
}

// parseHop parses an address with or without a port, in one spelling per
// address (no IPv4-mapped IPv6, no zone).
func parseHop(s string) (netip.Addr, bool) {
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	a, err := netip.ParseAddr(s)
	return a.Unmap().WithZone(""), err == nil
}

func contains(prefixes []netip.Prefix, a netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// proxyHints logs, once per peer, that a forwarded header was ignored, so the
// owner of an install behind a proxy can see what to set.
type proxyHints struct {
	mu   sync.Mutex
	seen map[string]bool
}

// maxProxyHints bounds the memory and log lines a stranger can cause.
const maxProxyHints = 10

func (p *proxyHints) check(r *http.Request, trusted []netip.Prefix) {
	if r.Header.Get("X-Forwarded-For") == "" {
		return
	}
	peer, ok := parseHop(r.RemoteAddr)
	if !ok || contains(trusted, peer) {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen[peer.String()] || len(p.seen) >= maxProxyHints {
		return
	}
	if p.seen == nil {
		p.seen = map[string]bool{}
	}
	p.seen[peer.String()] = true
	log.Printf("Dashboard: ignored X-Forwarded-For from %s. If that is your own reverse proxy, "+
		"add it to dashboard.trusted_proxies and restart; if not, someone sent it by hand.", peer)
}
