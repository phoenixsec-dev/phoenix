package dashboard

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/phoenixsec/phoenix/internal/approval"
)

// P4: the dashboard step-up approve re-checks allowed_agents (through
// approval.ValidateForMint) and the card shows a badge for unbound roles.
func TestDashboardApproveRejectsUnboundAgent(t *testing.T) {
	h, ss, as := testHandler(t)
	cookie := login(t, h)
	csrf := csrfFromCookie(t, h, cookie)

	apr, err := as.Create("deploy", "agent1", nil, []string{"prod/*"}, []string{"list"}, "bearer", "", "10.0.0.1", "", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}

	get := func(path string) string {
		req := httptest.NewRequest("GET", path, nil)
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d", path, w.Code)
		}
		return w.Body.String()
	}
	page := func() string { return get("/dashboard/approvals") }
	if !strings.Contains(page(), "role has no agent binding") {
		t.Fatal("unbound step-up role: badge missing")
	}
	if !strings.Contains(get("/dashboard/roles"), "any agent (no binding)") {
		t.Fatal("roles page should say the role has no binding")
	}

	role := h.deps.SessionRoles["deploy"]
	role.AllowedAgents = []string{"deployer"}
	h.deps.SessionRoles["deploy"] = role
	if strings.Contains(page(), "role has no agent binding") {
		t.Fatal("bound role still shows the badge")
	}
	if roles := get("/dashboard/roles"); !strings.Contains(roles, "deployer") || strings.Contains(roles, "no binding") {
		t.Fatal("roles page should list the allowed agent")
	}

	form := url.Values{"_csrf": {csrf}}
	req := httptest.NewRequest("POST", "/dashboard/approvals/"+apr.ID+"/approve", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "allowed_agents") {
		t.Errorf("redirect %q should explain the allowed_agents refusal", loc)
	}
	if got := as.Get(apr.ID); got.Status != approval.StatusPending || got.SessionID != "" {
		t.Fatalf("approval = %s (session %q), want still pending with no session", got.Status, got.SessionID)
	}
	if n := len(ss.List()); n != 0 {
		t.Fatalf("%d sessions minted, want 0", n)
	}
}
