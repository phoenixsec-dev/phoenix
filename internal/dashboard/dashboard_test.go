package dashboard

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/phoenixsec/phoenix/internal/approval"
	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/session"
)

func testHandler(t *testing.T) (*Handler, *session.Store, *approval.Store) {
	t.Helper()
	ss, err := session.NewStore(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ss.Stop)

	as := approval.NewStore(5 * time.Minute)
	t.Cleanup(as.Stop)

	roles := map[string]config.RoleConfig{
		"deploy": {
			Namespaces:     []string{"prod/*"},
			Actions:        []string{"list", "read_value"},
			BootstrapTrust: []string{"bearer"},
			StepUp:         true,
		},
	}

	cfg := config.DashboardConfig{
		Enabled:  true,
		Password: "testpass",
	}
	deps := Deps{
		Sessions:     ss,
		SessionRoles: roles,
		Approvals:    as,
		StartTime:    time.Now(),
	}

	h, err := New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	return h, ss, as
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

func csrfFromCookie(t *testing.T, h *Handler, cookie *http.Cookie) string {
	t.Helper()
	p, err := h.verifyCookie(&http.Request{Header: http.Header{"Cookie": {cookie.String()}}})
	if err != nil {
		t.Fatalf("csrf extraction: %v", err)
	}
	return p.CSRF
}

func TestLoginSuccess(t *testing.T) {
	h, _, _ := testHandler(t)
	cookie := login(t, h)
	if cookie.Value == "" {
		t.Fatal("expected non-empty cookie")
	}
}

func TestLoginFailure(t *testing.T) {
	h, _, _ := testHandler(t)
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
	h, _, _ := testHandler(t)
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

func TestCSRFValidation(t *testing.T) {
	h, _, as := testHandler(t)
	cookie := login(t, h)

	// Create an approval to have a valid target
	apr, _ := as.Create("deploy", "agent1", nil, []string{"prod/*"}, []string{"list"}, "bearer", "", "10.0.0.1", "", time.Hour, 0)

	// POST without CSRF should fail
	form := url.Values{}
	req := httptest.NewRequest("POST", "/dashboard/approvals/"+apr.ID+"/approve", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for missing CSRF, got %d", w.Code)
	}
}

func TestApproveFlow(t *testing.T) {
	h, ss, as := testHandler(t)
	cookie := login(t, h)
	csrf := csrfFromCookie(t, h, cookie)

	// Create pending approval
	apr, err := as.Create("deploy", "agent1", nil, []string{"prod/*"}, []string{"list", "read_value"}, "bearer", "", "10.0.0.1", "", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Approve via dashboard
	form := url.Values{"_csrf": {csrf}}
	req := httptest.NewRequest("POST", "/dashboard/approvals/"+apr.ID+"/approve", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d (body: %s)", w.Code, w.Body.String())
	}

	// Verify approval is approved
	resolved := as.Get(apr.ID)
	if resolved.Status != approval.StatusApproved {
		t.Fatalf("expected approved, got %s", resolved.Status)
	}

	// Verify session was minted
	if resolved.SessionID == "" {
		t.Fatal("expected session ID on approved approval")
	}

	sess := ss.Get(resolved.SessionID)
	if sess == nil {
		t.Fatal("expected session to exist")
	}
	if sess.Role != "deploy" {
		t.Fatalf("expected role deploy, got %s", sess.Role)
	}
}

func TestDenyFlow(t *testing.T) {
	h, _, as := testHandler(t)
	cookie := login(t, h)
	csrf := csrfFromCookie(t, h, cookie)

	apr, _ := as.Create("deploy", "agent1", nil, []string{"prod/*"}, []string{"list"}, "bearer", "", "10.0.0.1", "", time.Hour, 0)

	form := url.Values{"_csrf": {csrf}}
	req := httptest.NewRequest("POST", "/dashboard/approvals/"+apr.ID+"/deny", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}

	resolved := as.Get(apr.ID)
	if resolved.Status != approval.StatusDenied {
		t.Fatalf("expected denied, got %s", resolved.Status)
	}
}

func TestSessionRevoke(t *testing.T) {
	h, ss, _ := testHandler(t)
	cookie := login(t, h)
	csrf := csrfFromCookie(t, h, cookie)

	// Create a session directly
	_, sess, err := ss.Create("deploy", "agent1", nil, []string{"prod/*"}, []string{"list"}, "bearer", "", "10.0.0.1", time.Hour)
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
	h, _, _ := testHandler(t)

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
	h, _, _ := testHandler(t)

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
	h, _, _ := testHandler(t)

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
