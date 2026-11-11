package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phoenixsec/phoenix/internal/audit"
	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/session"

	"golang.org/x/crypto/bcrypt"
)

func testHandler(t *testing.T) (*Handler, *session.Store) {
	t.Helper()
	h, ss, _ := testHandlerWithAudit(t)
	return h, ss
}

func testHandlerWithAudit(t *testing.T) (*Handler, *session.Store, *bytes.Buffer) {
	t.Helper()
	ss, err := session.NewStore(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ss.Stop)

	roles := map[string]config.RoleConfig{
		"deploy": {
			Namespaces:     []string{"prod/*"},
			Actions:        []string{"list", "read_value"},
			BootstrapTrust: []string{"bearer"},
		},
	}

	var auditBuf bytes.Buffer
	al := audit.NewWriterLogger(&auditBuf)

	hash, err := bcrypt.GenerateFromPassword([]byte("testpass"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.DashboardConfig{
		Enabled:      true,
		PasswordHash: string(hash),
	}
	deps := Deps{
		Sessions:     ss,
		SessionRoles: roles,
		StartTime:    time.Now(),
		Audit:        al,
	}

	h, err := New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	return h, ss, &auditBuf
}

// parseAuditEntries reads JSONL audit entries from a buffer.
func parseAuditEntries(buf *bytes.Buffer) []audit.Entry {
	var entries []audit.Entry
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	for dec.More() {
		var e audit.Entry
		if err := dec.Decode(&e); err != nil {
			break
		}
		entries = append(entries, e)
	}
	return entries
}

// findAuditEntry returns the first entry matching action and status.
func findAuditEntry(entries []audit.Entry, action, status string) *audit.Entry {
	for i := range entries {
		if entries[i].Action == action && entries[i].Status == status {
			return &entries[i]
		}
	}
	return nil
}

func login(t *testing.T, h *Handler) *http.Cookie {
	t.Helper()
	form := url.Values{"credential": {"testpass"}}
	req := httptest.NewRequest("POST", "/dashboard/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("login: expected 303, got %d", w.Code)
	}
	cookies := w.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "phoenix_dash" {
			return c
		}
	}
	t.Fatal("no phoenix_dash cookie set")
	return nil
}

// payloadFromCookie returns the verified contents of a dashboard cookie.
func payloadFromCookie(t *testing.T, h *Handler, cookie *http.Cookie) *cookiePayload {
	t.Helper()
	p, err := h.verifyCookie(&http.Request{Header: http.Header{"Cookie": {cookie.String()}}})
	if err != nil {
		t.Fatalf("cookie payload: %v", err)
	}
	return p
}

func csrfFromCookie(t *testing.T, h *Handler, cookie *http.Cookie) string {
	t.Helper()
	return payloadFromCookie(t, h, cookie).CSRF
}

func TestLoginSuccess(t *testing.T) {
	h, _ := testHandler(t)
	cookie := login(t, h)
	if cookie.Value == "" {
		t.Fatal("expected non-empty cookie")
	}
}

func TestLoginFailure(t *testing.T) {
	h, _ := testHandler(t)
	form := url.Values{"credential": {"wrongpass"}}
	req := httptest.NewRequest("POST", "/dashboard/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "error=") {
		t.Fatalf("expected error in redirect, got %s", loc)
	}
}

func TestRequireAuth(t *testing.T) {
	h, _ := testHandler(t)
	req := httptest.NewRequest("GET", "/dashboard/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect to login, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "/dashboard/login") {
		t.Fatalf("expected redirect to login, got %s", loc)
	}
}

func TestPagesRenderOwnContentTemplate(t *testing.T) {
	h, _ := testHandler(t)
	cookie := login(t, h)

	req := httptest.NewRequest("GET", "/dashboard/", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("overview: expected 200, got %d", w.Code)
	}
	overview := w.Body.String()
	if !strings.Contains(overview, "Overview") {
		t.Fatalf("overview page missing overview content: %s", overview)
	}
	if strings.Contains(overview, "Audit Log") {
		t.Fatalf("overview page rendered audit content: %s", overview)
	}

	req = httptest.NewRequest("GET", "/dashboard/audit", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("audit: expected 200, got %d", w.Code)
	}
	auditPage := w.Body.String()
	if !strings.Contains(auditPage, "Audit Log") {
		t.Fatalf("audit page missing audit content: %s", auditPage)
	}
	if strings.Contains(auditPage, "Recent Activity") {
		t.Fatalf("audit page rendered overview content: %s", auditPage)
	}
}

// The Roles page renders every role card in full. Review R1: it read the
// removed role attestation list and stopped mid-page with a template error.
func TestRolesPageRendersRoles(t *testing.T) {
	h, _ := testHandler(t)
	cookie := login(t, h)
	req := httptest.NewRequest("GET", "/dashboard/roles", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "deploy") || !strings.Contains(body, "</html>") || strings.Contains(body, "template error") {
		t.Fatalf("roles page: %d\n%s", w.Code, body)
	}
}

func TestCSRFValidation(t *testing.T) {
	h, _ := testHandler(t)
	cookie := login(t, h)

	// POST without CSRF should fail
	form := url.Values{}
	req := httptest.NewRequest("POST", "/dashboard/sessions/sess_x/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for missing CSRF, got %d", w.Code)
	}
}

func TestSessionRevoke(t *testing.T) {
	h, ss := testHandler(t)
	cookie := login(t, h)
	csrf := csrfFromCookie(t, h, cookie)

	// Create a session directly
	_, sess, err := ss.Create("deploy", "agent1", nil, []string{"prod/*"}, []string{"list"}, "bearer", "10.0.0.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{"_csrf": {csrf}}
	req := httptest.NewRequest("POST", "/dashboard/sessions/"+sess.ID+"/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}

	// Verify session is revoked
	revoked := ss.Get(sess.ID)
	if revoked == nil || !revoked.Revoked {
		t.Fatal("expected session to be revoked")
	}
}

func TestLoginRateLimiting(t *testing.T) {
	h, _ := testHandler(t)

	// Burn through the 5 free failures
	for i := 0; i < loginMaxFailures; i++ {
		form := url.Values{"credential": {"wrong"}}
		req := httptest.NewRequest("POST", "/dashboard/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "10.0.0.99:12345"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		// These should redirect to login with "invalid credentials"
		if w.Code != http.StatusSeeOther {
			t.Fatalf("attempt %d: expected 303, got %d", i+1, w.Code)
		}
	}

	// The next attempt should be rate limited
	form := url.Values{"credential": {"wrong"}}
	req := httptest.NewRequest("POST", "/dashboard/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.0.0.99:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "too+many") && !strings.Contains(loc, "too%20many") {
		t.Fatalf("expected rate limit message in redirect, got %s", loc)
	}

	// A different IP should NOT be rate limited
	form2 := url.Values{"credential": {"wrong"}}
	req2 := httptest.NewRequest("POST", "/dashboard/login", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.RemoteAddr = "10.0.0.100:12345"
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)

	loc2 := w2.Header().Get("Location")
	if strings.Contains(loc2, "too+many") || strings.Contains(loc2, "too%20many") {
		t.Fatal("different IP should not be rate limited")
	}
}

func TestSecureCookieOnTLS(t *testing.T) {
	h, _ := testHandler(t)

	// Login via X-Forwarded-Proto: https
	form := url.Values{"credential": {"testpass"}}
	req := httptest.NewRequest("POST", "/dashboard/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}

	cookies := w.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "phoenix_dash" {
			if !c.Secure {
				t.Fatal("expected Secure flag on cookie when behind TLS proxy")
			}
			return
		}
	}
	t.Fatal("no phoenix_dash cookie set")
}

func TestNonSecureCookieOnPlainHTTP(t *testing.T) {
	h, _ := testHandler(t)

	form := url.Values{"credential": {"testpass"}}
	req := httptest.NewRequest("POST", "/dashboard/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// No TLS, no X-Forwarded-Proto
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	cookies := w.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "phoenix_dash" {
			if c.Secure {
				t.Fatal("expected no Secure flag on plain HTTP")
			}
			return
		}
	}
	t.Fatal("no phoenix_dash cookie set")
}

// --- Audit event tests ---

func TestLoginSuccessAudit(t *testing.T) {
	h, _, buf := testHandlerWithAudit(t)

	form := url.Values{"credential": {"testpass"}}
	req := httptest.NewRequest("POST", "/dashboard/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.0.0.5:9999"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}

	entries := parseAuditEntries(buf)
	e := findAuditEntry(entries, "dashboard.login", "allowed")
	if e == nil {
		t.Fatal("expected allowed dashboard.login audit entry")
	}
	if e.Agent != "dashboard@10.0.0.5" {
		t.Fatalf("expected agent dashboard@10.0.0.5, got %s", e.Agent)
	}
	if e.IP != "10.0.0.5" {
		t.Fatalf("expected IP 10.0.0.5, got %s", e.IP)
	}
}

func TestLoginFailureAudit(t *testing.T) {
	h, _, buf := testHandlerWithAudit(t)

	form := url.Values{"credential": {"wrong"}}
	req := httptest.NewRequest("POST", "/dashboard/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.0.0.5:9999"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	entries := parseAuditEntries(buf)
	e := findAuditEntry(entries, "dashboard.login", "denied")
	if e == nil {
		t.Fatal("expected denied dashboard.login audit entry")
	}
	if e.Agent != "dashboard" {
		t.Fatalf("expected agent 'dashboard' for pre-login failure, got %s", e.Agent)
	}
	if e.Reason != "invalid_credentials" {
		t.Fatalf("expected reason invalid_credentials, got %s", e.Reason)
	}
}

func TestLoginRateLimitAudit(t *testing.T) {
	h, _, buf := testHandlerWithAudit(t)

	// Exhaust free attempts
	for i := 0; i < loginMaxFailures; i++ {
		form := url.Values{"credential": {"wrong"}}
		req := httptest.NewRequest("POST", "/dashboard/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "10.0.0.77:9999"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
	}

	// Next attempt should be rate-limited
	buf.Reset() // clear prior entries, we only care about the rate-limit one
	form := url.Values{"credential": {"wrong"}}
	req := httptest.NewRequest("POST", "/dashboard/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.0.0.77:9999"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	entries := parseAuditEntries(buf)
	e := findAuditEntry(entries, "dashboard.login", "denied")
	if e == nil {
		t.Fatal("expected denied audit entry for rate-limited login")
	}
	if e.Path != "rate_limited" {
		t.Fatalf("expected path 'rate_limited', got %s", e.Path)
	}
}

func TestLogoutAudit(t *testing.T) {
	h, _, buf := testHandlerWithAudit(t)
	cookie := login(t, h)
	csrf := csrfFromCookie(t, h, cookie)

	buf.Reset() // clear login audit

	form := url.Values{"_csrf": {csrf}}
	req := httptest.NewRequest("POST", "/dashboard/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.0.0.5:9999"
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}

	entries := parseAuditEntries(buf)
	e := findAuditEntry(entries, "dashboard.logout", "allowed")
	if e == nil {
		t.Fatal("expected allowed dashboard.logout audit entry")
	}
	if e.Agent != "dashboard@10.0.0.5" {
		t.Fatalf("expected agent dashboard@10.0.0.5, got %s", e.Agent)
	}
}

func TestExpiredCookieAudit(t *testing.T) {
	h, _, buf := testHandlerWithAudit(t)

	// Login first so there's a live login, then craft an expired cookie with its nonce
	nonce := payloadFromCookie(t, h, login(t, h)).Nonce

	// Create a cookie that's already expired but has the right nonce
	payload := cookiePayload{
		Exp:   time.Now().Add(-time.Hour).Unix(), // expired 1h ago
		CSRF:  "deadbeef",
		Nonce: nonce,
	}
	cookieVal, err := h.signCookie(payload)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/dashboard/", nil)
	req.AddCookie(&http.Cookie{Name: "phoenix_dash", Value: cookieVal})
	req.RemoteAddr = "10.0.0.5:9999"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", w.Code)
	}

	entries := parseAuditEntries(buf)
	e := findAuditEntry(entries, "dashboard.auth", "denied")
	if e == nil {
		t.Fatal("expected denied dashboard.auth audit entry for expired cookie")
	}
	if !strings.Contains(e.Reason, "expired") {
		t.Fatalf("expected reason containing 'expired', got %s", e.Reason)
	}
}

func TestCSRFFailureAudit(t *testing.T) {
	h, _, buf := testHandlerWithAudit(t)
	cookie := login(t, h)

	buf.Reset()

	// POST with wrong CSRF
	form := url.Values{"_csrf": {"wrong"}}
	req := httptest.NewRequest("POST", "/dashboard/sessions/sess_x/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.RemoteAddr = "10.0.0.5:9999"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}

	entries := parseAuditEntries(buf)
	e := findAuditEntry(entries, "dashboard.csrf", "denied")
	if e == nil {
		t.Fatal("expected denied dashboard.csrf audit entry")
	}
}

func TestLogoutRequiresAuth(t *testing.T) {
	h, _ := testHandler(t)

	// POST logout without any cookie should redirect to login
	form := url.Values{}
	req := httptest.NewRequest("POST", "/dashboard/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "/dashboard/login") {
		t.Fatalf("expected redirect to login, got %s", loc)
	}
}

// --- Several logins at once ---

// loginAs signs in with a given User-Agent, like a separate phone or desktop.
func loginAs(t *testing.T, h *Handler, ua string) *http.Cookie {
	t.Helper()
	form := url.Values{"credential": {"testpass"}}
	req := httptest.NewRequest("POST", "/dashboard/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", ua)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	for _, c := range w.Result().Cookies() {
		if c.Name == "phoenix_dash" {
			return c
		}
	}
	t.Fatalf("login as %q: no cookie (Location %s)", ua, w.Header().Get("Location"))
	return nil
}

// get fetches a dashboard page with a cookie and returns the response.
func get(h *Handler, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// post sends a CSRF-protected form POST with a cookie.
func post(t *testing.T, h *Handler, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"_csrf": {csrfFromCookie(t, h, cookie)}}
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

const (
	uaDesktop = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
	uaPhone   = "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Mobile Safari/537.36"
)

// The bug this replaces: a desktop login locked the phone out.
func TestTwoLoginsBothWork(t *testing.T) {
	h, _ := testHandler(t)
	desktop := loginAs(t, h, uaDesktop)
	phone := loginAs(t, h, uaPhone)

	for name, c := range map[string]*http.Cookie{"desktop": desktop, "phone": phone} {
		if w := get(h, "/dashboard/", c); w.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", name, w.Code)
		}
	}

	body := get(h, "/dashboard/sessions", phone).Body.String()
	for _, want := range []string{"Firefox on Linux", "Chrome on Android", "this device"} {
		if !strings.Contains(body, want) {
			t.Fatalf("sessions page missing %q", want)
		}
	}
}

// Logging out, or signing another login out from the Sessions page, ends only
// that login.
func TestSigningOneOutLeavesTheOther(t *testing.T) {
	h, _, buf := testHandlerWithAudit(t)
	desktop := loginAs(t, h, uaDesktop)
	phone := loginAs(t, h, uaPhone)
	tablet := loginAs(t, h, uaPhone)

	// Logout on the desktop.
	post(t, h, "/dashboard/logout", desktop)
	if w := get(h, "/dashboard/", desktop); w.Code != http.StatusSeeOther {
		t.Fatalf("desktop after logout: expected redirect, got %d", w.Code)
	}

	// The phone signs the tablet out from the Sessions page.
	tabletID := ""
	tabletNonce := payloadFromCookie(t, h, tablet).Nonce
	for _, l := range h.logins.list(time.Now()) {
		if l.nonce == tabletNonce {
			tabletID = l.ID
		}
	}
	if w := post(t, h, "/dashboard/logins/"+tabletID+"/revoke", phone); !strings.Contains(w.Header().Get("Location"), "/dashboard/sessions") {
		t.Fatalf("revoke: expected back to sessions, got %s", w.Header().Get("Location"))
	}
	if w := get(h, "/dashboard/", tablet); w.Code != http.StatusSeeOther {
		t.Fatalf("tablet after sign-out: expected redirect, got %d", w.Code)
	}
	if w := get(h, "/dashboard/", phone); w.Code != http.StatusOK {
		t.Fatalf("phone: expected 200, got %d", w.Code)
	}
	if findAuditEntry(parseAuditEntries(buf), "dashboard.login_revoke", "allowed") == nil {
		t.Fatal("expected dashboard.login_revoke audit entry")
	}
}

// Past the cap, a new login signs out the least recently used one instead of
// being refused, so the password holder is never locked out.
func TestLoginCapSignsOutLeastRecentlyUsed(t *testing.T) {
	h, _, buf := testHandlerWithAudit(t)
	cookies := make([]*http.Cookie, maxDashboardLogins)
	for i := range cookies {
		cookies[i] = loginAs(t, h, uaDesktop)
	}
	// Make login 1 the least recently used; login 0 was just used.
	base := time.Now().Add(-time.Hour)
	for i, c := range cookies {
		n := payloadFromCookie(t, h, c).Nonce
		h.logins.touch(n, "", base.Add(time.Duration(i)*time.Minute))
	}
	h.logins.touch(payloadFromCookie(t, h, cookies[0]).Nonce, "", time.Now())

	newest := loginAs(t, h, uaPhone)

	if got := len(h.logins.list(time.Now())); got != maxDashboardLogins {
		t.Fatalf("expected %d logins, got %d", maxDashboardLogins, got)
	}
	if w := get(h, "/dashboard/", cookies[1]); w.Code != http.StatusSeeOther {
		t.Fatalf("least recently used login should be signed out, got %d", w.Code)
	}
	for _, c := range []*http.Cookie{cookies[0], cookies[2], newest} {
		if w := get(h, "/dashboard/", c); w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	}
	if findAuditEntry(parseAuditEntries(buf), "dashboard.login_evicted", "allowed") == nil {
		t.Fatal("expected dashboard.login_evicted audit entry")
	}
}

// The audit page filters status inside the search (a denied entry older than
// the newest 50 still shows) and says when older archives went unsearched.
func TestAuditPageStatusFilterAndTruncation(t *testing.T) {
	h, _ := testHandler(t)
	cookie := login(t, h)
	dir := t.TempDir()
	line := func(ts, status, path string) string {
		return `{"ts":"` + ts + `","agent":"a","action":"read","path":"` + path + `","status":"` + status + `","sealed":false}` + "\n"
	}
	var cur strings.Builder
	for i := 0; i < 60; i++ {
		cur.WriteString(line("2026-11-08T00:00:00Z", "allowed", "p/new"))
	}
	os.WriteFile(filepath.Join(dir, "audit.log"), []byte(cur.String()), 0600)
	os.WriteFile(filepath.Join(dir, "audit-20261102T000000.000Z.log"), []byte(line("2026-11-02T00:00:00Z", "denied", "p/denied-old")), 0600)
	os.WriteFile(filepath.Join(dir, "audit-20261101T000000.000Z.log.gz"), nil, 0600) // older history
	h.deps.AuditPath = filepath.Join(dir, "audit.log")

	req := httptest.NewRequest("GET", "/dashboard/audit?status=denied", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body := w.Body.String()
	if !strings.Contains(body, "p/denied-old") || strings.Contains(body, "p/new") {
		t.Fatalf("status filter not applied in the search:\n%s", body)
	}
	// The note must sit inside #audit-table, the part auto-refresh replaces.
	if i, j := strings.Index(body, `id="audit-table"`), strings.Index(body, `id="audit-truncated"`); i < 0 || j < i {
		t.Fatal("truncation notice missing or outside #audit-table")
	}
}

// Overview and Audit show a secret path in full, in a cell that can wrap,
// not cut to 30-40 characters.
func TestPagesShowFullSecretPath(t *testing.T) {
	h, _ := testHandler(t)
	cookie := login(t, h)
	long := "homelab/proxmox/cluster-api-tokens/automation/terraform-provisioner-token"
	path := filepath.Join(t.TempDir(), "audit.log")
	os.WriteFile(path, []byte(`{"ts":"2026-11-08T00:00:00Z","agent":"a","action":"read","path":"`+long+`","status":"allowed","sealed":false}`+"\n"), 0600)
	h.deps.AuditPath = path

	for _, page := range []string{"/dashboard/", "/dashboard/audit"} {
		req := httptest.NewRequest("GET", page, nil)
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if !strings.Contains(w.Body.String(), `<td class="mono path-full">`+long+`</td>`) {
			t.Fatalf("%s: full path not shown in a path-full cell", page)
		}
	}
}
