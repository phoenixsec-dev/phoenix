package dashboard

import (
	"bytes"
	"fmt"
	"log"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"
)

// loginAttempt posts a wrong password from peer with the given headers and
// returns where it redirects.
func loginAttempt(h *Handler, peer string, headers map[string]string) string {
	req := httptest.NewRequest("POST", "/dashboard/login", strings.NewReader(url.Values{"credential": {"wrong"}}.Encode()))
	req.RemoteAddr = peer
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Header().Get("Location")
}

// A visitor cannot dodge the login lockout, or choose the address in the audit
// log, by sending a different X-Forwarded-For each time.
func TestForgedForwardedForDoesNotDodgeLockout(t *testing.T) {
	h, _, auditBuf := testHandlerWithAudit(t)
	last := ""
	for i := range loginMaxFailures + 1 {
		last = loginAttempt(h, "192.0.2.10:5000", map[string]string{"X-Forwarded-For": fmt.Sprintf("198.51.100.%d", i)})
	}
	if !strings.Contains(last, "too+many") {
		t.Errorf("attempt %d went to %q, want the lockout", loginMaxFailures+1, last)
	}
	if log := auditBuf.String(); strings.Contains(log, "198.51.100.") || !strings.Contains(log, `"ip":"192.0.2.10"`) {
		t.Errorf("audit log believed the header: %s", log)
	}
}

func TestClientAddress(t *testing.T) {
	prefixes := func(s ...string) (out []netip.Prefix) {
		for _, p := range s {
			out = append(out, netip.MustParsePrefix(p))
		}
		return out
	}
	proxies := prefixes("10.0.0.0/8", "::1/128")
	for name, c := range map[string]struct {
		trusted []netip.Prefix
		peer    string
		xff     []string
		ip      string
	}{
		"unset trusts nobody":            {nil, "127.0.0.1:1", []string{"198.51.100.1"}, "127.0.0.1"},
		"stranger":                       {proxies, "192.0.2.1:1", []string{"198.51.100.1"}, "192.0.2.1"},
		"stranger IPv6":                  {proxies, "[2001:db8::1]:1", []string{"198.51.100.1"}, "2001:db8::1"},
		"proxy":                          {proxies, "10.0.0.1:1", []string{"198.51.100.1"}, "198.51.100.1"},
		"proxy over IPv6":                {proxies, "[::1]:1", []string{"2001:db8::7"}, "2001:db8::7"},
		"proxy as IPv4-mapped":           {proxies, "[::ffff:10.0.0.1]:1", []string{"198.51.100.1"}, "198.51.100.1"},
		"visitor's own value is ignored": {proxies, "10.0.0.1:1", []string{"203.0.113.9, 198.51.100.1"}, "198.51.100.1"},
		"visitor's own header line too":  {proxies, "10.0.0.1:1", []string{"203.0.113.9", "198.51.100.1"}, "198.51.100.1"},
		"two proxies":                    {proxies, "10.0.0.1:1", []string{"203.0.113.9, 198.51.100.1, 10.0.0.2"}, "198.51.100.1"},
		"only proxies":                   {proxies, "10.0.0.1:1", []string{"10.0.0.3, 10.0.0.2"}, "10.0.0.3"},
		"no header":                      {proxies, "10.0.0.1:1", nil, "10.0.0.1"},
		"not an address":                 {proxies, "10.0.0.1:1", []string{"198.51.100.1, unknown, 10.0.0.2"}, "10.0.0.2"},
		"hop with port":                  {proxies, "10.0.0.1:1", []string{"198.51.100.1:4711"}, "198.51.100.1"},
		"IPv6 hop with port":             {proxies, "10.0.0.1:1", []string{"[2001:db8::7]:4711"}, "2001:db8::7"},
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/dashboard/", nil)
			r.RemoteAddr = c.peer
			r.Header["X-Forwarded-For"] = c.xff
			r = withClient(r, c.trusted)
			if got := extractClientIP(r); got != c.ip {
				t.Errorf("address = %q, want %q", got, c.ip)
			}
		})
	}
}

// The server log tells the owner of an install behind a proxy what to set,
// once per peer.
func TestIgnoredForwardedHeaderIsLoggedOnce(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	h, _ := testHandler(t)
	for range 3 {
		loginAttempt(h, "192.0.2.10:5000", map[string]string{"X-Forwarded-For": "198.51.100.1"})
	}
	loginAttempt(h, "192.0.2.11:5000", nil)
	if got := strings.Count(buf.String(), "dashboard.trusted_proxies"); got != 1 || !strings.Contains(buf.String(), "192.0.2.10") {
		t.Errorf("%d log lines: %s", got, buf.String())
	}
}
