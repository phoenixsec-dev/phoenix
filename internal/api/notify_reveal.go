package api

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/phoenixsec/phoenix/internal/config"
)

// The ping when a secret is shown or copied in the dashboard. It goes where
// access-request notifications go (access_requests.notify_url and its token),
// the same way: one POST in the background, no retries, a failure is logged.
// It does not need access requests to be on. dashboard.notify_on_reveal
// switches it off; the audit line is written either way.

// revealPingEvery is how long one login's further shows and copies of the same
// secret are covered by the ping already sent.
const revealPingEvery = 5 * time.Minute

// revealPings remembers which pings went out lately.
type revealPings struct {
	mu   sync.Mutex
	sent map[revealKey]time.Time
}

// revealKey is what one ping covers.
type revealKey struct{ login, path string }

// start reports whether a ping is due for k, and if so counts it as sent.
// Entries too old to matter are dropped, so the map stays small.
func (p *revealPings) start(k revealKey, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for old, at := range p.sent {
		if now.Sub(at) >= revealPingEvery {
			delete(p.sent, old)
		}
	}
	if _, ok := p.sent[k]; ok {
		return false
	}
	if p.sent == nil {
		p.sent = make(map[revealKey]time.Time)
	}
	p.sent[k] = now
	return true
}

// failed takes back a start, so the next show or copy tries again.
func (p *revealPings) failed(k revealKey) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.sent, k)
}

// NotifyConfigured reports whether notifications have somewhere to go.
func (s *Server) NotifyConfigured() bool {
	return s.accessSettings().NotifyURL != ""
}

// NotifySecretUsed pings the owner that path was "shown" or "copied" in the
// dashboard by the login with this ID, device and address. It never waits, and
// one login and secret get one ping per revealPingEvery.
func (s *Server) NotifySecretUsed(path, verb, login, device, ip string) {
	cfg := s.accessSettings()
	k := revealKey{login, path}
	if cfg.NotifyURL == "" || !s.reveals.start(k, s.now()) {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), s.notifyTimeout)
		defer cancel()
		if err := s.sendRevealNotify(ctx, cfg, path, verb, login, device, ip); err != nil {
			s.reveals.failed(k)
			log.Printf("dashboard: notify that %q was %s by login %s failed: %v", path, verb, login, err)
		}
	}()
}

// sendRevealNotify does the one POST. It names the secret, never its value.
func (s *Server) sendRevealNotify(ctx context.Context, cfg config.AccessRequestsSettings, path, verb, login, device, ip string) error {
	link := ""
	if cfg.NotifyDashboardURL != "" {
		link = strings.TrimRight(cfg.NotifyDashboardURL, "/") + "/dashboard/sessions"
	}
	body := fmt.Sprintf("%s was %s in the dashboard.\nDevice: %s\nAddress: %s\nLogin: %s\nNot you? Sign that login out on the Sessions page and change the dashboard password.\n",
		notifyText(path, 300), verb, notifyText(device, 60), notifyText(ip, 60), login)
	if link != "" {
		body += link + "\n"
	}
	return s.postNotify(ctx, cfg, "Phoenix: secret "+verb, "eyes", link, body)
}

// notifyText makes stored or client-sent text fit one line of a message: no
// control or invisible characters, at most max characters.
func notifyText(s string, max int) string {
	out := make([]rune, 0, max)
	for _, r := range strings.ToValidUTF8(s, "") {
		if len(out) == max {
			return string(out) + "..."
		}
		if unicode.IsPrint(r) {
			out = append(out, r)
		}
	}
	return string(out)
}
