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
// reverse proxy listed in dashboard.trusted_proxies: only then are the
// X-Forwarded-For and X-Forwarded-Proto headers read. Anyone can send those
// headers, so believing a stranger's would let a visitor dodge the login
// lockout and choose the address shown beside a login or an approval.

// client is what the dashboard knows about where a request came from.
type client struct {
	ip    string
	https bool
}

type clientKey struct{}

// withClient works out the client once and attaches it to the request.
func withClient(r *http.Request, trusted []netip.Prefix) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), clientKey{}, findClient(r, trusted)))
}

// clientOf returns what withClient found, or, without it, the socket's view.
func clientOf(r *http.Request) client {
	if c, ok := r.Context().Value(clientKey{}).(client); ok {
		return c
	}
	return findClient(r, nil)
}

// extractClientIP is the visitor's address, for the login lockout and the
// audit log.
func extractClientIP(r *http.Request) string { return clientOf(r).ip }

// isTLS reports whether the visitor reached the dashboard over HTTPS, directly
// or through a trusted proxy.
func isTLS(r *http.Request) bool { return clientOf(r).https }

// findClient reads the forwarded headers only when the peer is trusted.
// Proxies append to X-Forwarded-For, so it is walked from the right: the first
// hop that is not a trusted proxy is the visitor, and everything left of it is
// whatever the visitor chose to send.
func findClient(r *http.Request, trusted []netip.Prefix) client {
	peer, ok := parseHop(r.RemoteAddr)
	if !ok {
		return client{ip: r.RemoteAddr, https: r.TLS != nil}
	}
	c := client{ip: peer.String(), https: r.TLS != nil}
	if !contains(trusted, peer) {
		return c
	}
	if protos := r.Header.Values("X-Forwarded-Proto"); len(protos) > 0 && strings.EqualFold(protos[len(protos)-1], "https") {
		c.https = true
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop, ok := parseHop(strings.TrimSpace(hops[i]))
		if !ok {
			break
		}
		c.ip = hop.String()
		if !contains(trusted, hop) {
			break
		}
	}
	return c
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
	if r.Header.Get("X-Forwarded-For") == "" && r.Header.Get("X-Forwarded-Proto") == "" {
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
	log.Printf("Dashboard: ignored X-Forwarded headers from %s. If that is your own reverse proxy, "+
		"add it to dashboard.trusted_proxies and restart; if not, someone sent them by hand.", peer)
}
