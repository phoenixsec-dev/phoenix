package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/phoenixsec/phoenix/internal/config"
)

// One ping per login and secret per few minutes, naming the secret, device,
// address and login. It is sent with access requests off too.
func TestNotifySecretUsed(t *testing.T) {
	e := newGrantEnv(t)
	ts, hits := fakeNtfy(t, http.StatusOK)
	e.set(func(s *config.AccessRequestsSettings) {
		s.Enabled = false
		s.NotifyURL = ts.URL + "/phoenix"
		s.NotifyDashboardURL = "https://phoenix.example.net/"
	})
	e.srv.NotifySecretUsed("shop/pet\nstore", "shown", "login1", "Chrome on Android", "192.0.2.7\nfake")
	h := waitHit(t, hits)
	for _, want := range []string{`"shop/pet\nstore" was shown`, "Device: Chrome on Android\n", "Address: 192.0.2.7fake\n", "Login: login1\n", "https://phoenix.example.net/dashboard/sessions"} {
		if !strings.Contains(h.body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	if h.header.Get("Title") != "Phoenix: secret shown" || h.header.Get("Click") == "" {
		t.Errorf("title %q, click %q", h.header.Get("Title"), h.header.Get("Click"))
	}

	e.srv.NotifySecretUsed("shop/pet\nstore", "copied", "login1", "d", "ip")
	expectNoHit(t, hits)
	e.srv.NotifySecretUsed("shop/pet\nstore", "copied", "login2", "d", "ip")
	waitHit(t, hits)
	e.srv.NotifySecretUsed("shop/other", "copied", "login1", "d", "ip")
	waitHit(t, hits)
	e.clock.Advance(revealPingEvery)
	e.srv.NotifySecretUsed("shop/pet\nstore", "copied", "login1", "d", "ip")
	waitHit(t, hits)
	if n := len(e.srv.reveals.sent); n != 1 {
		t.Errorf("%d pings remembered, want 1", n)
	}
}

// A ping that fails is logged without the URL or token, and does not count as
// sent. Nothing waits for it.
func TestNotifySecretUsedFailure(t *testing.T) {
	e := newGrantEnv(t)
	buf := captureLog(t)
	ts, hits := fakeNtfy(t, http.StatusInternalServerError)
	e.set(func(s *config.AccessRequestsSettings) { s.NotifyURL = ts.URL + "/private-topic" })
	e.srv.NotifySecretUsed("shop/petstore", "shown", "login1", "d", "ip")
	waitHit(t, hits)
	if s := waitLog(t, buf, "answered HTTP 500"); strings.Contains(s, "private-topic") || !strings.Contains(s, "shop/petstore") {
		t.Error("the log names the URL, or not the secret")
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(hits) == 0 && time.Now().Before(deadline) {
		e.srv.NotifySecretUsed("shop/petstore", "copied", "login1", "d", "ip")
		time.Sleep(20 * time.Millisecond)
	}
	waitHit(t, hits)

	// No notify_url: nothing is sent and nothing is logged.
	e.set(func(s *config.AccessRequestsSettings) { s.NotifyURL = "" })
	if e.srv.NotifyConfigured() {
		t.Error("configured without a URL")
	}
	e.srv.NotifySecretUsed("shop/none", "shown", "login1", "d", "ip")
	if strings.Contains(buf.String(), "shop/none") {
		t.Error("logged a ping nobody asked for")
	}
}

// No two names look the same in a ping.
func TestQuoteOddKeepsNamesApart(t *testing.T) {
	seen := map[string]string{}
	for _, n := range []string{"a/b\nc", `"a/b\nc"`, `a/b\nc`, "a/bc", "a/b\u200bc", "a/b c", `a/"b"`} {
		q := notifyText(quoteOdd(n), 300)
		if other, ok := seen[q]; ok {
			t.Errorf("%q and %q both show as %s", n, other, q)
		}
		seen[q] = n
	}
	if quoteOdd("shop/key?v2 #1") != "shop/key?v2 #1" {
		t.Error("an ordinary name was quoted")
	}
}
