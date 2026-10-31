package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/phoenixsec/phoenix/internal/config"
)

// P4 (Q5): a role's allowed_agents is checked at session mint, at step-up
// approval over the API and at renewal. Failures are 403 ROLE_NOT_ALLOWED
// with next_step ask_user. (Dashboard approval: internal/dashboard.)

func postJSON(srv *Server, path, tok, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func expectRoleNotAllowed(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", w.Code, w.Body.String())
	}
	var d map[string]string
	json.Unmarshal(w.Body.Bytes(), &d)
	if d["code"] != CodeRoleNotAllowed || d["next_step"] != NextAskUser {
		t.Fatalf("got code=%q next_step=%q, want ROLE_NOT_ALLOWED / ask_user", d["code"], d["next_step"])
	}
	if strings.Contains(w.Body.String(), "deployer") {
		t.Fatalf("denial leaks the allowed_agents list: %s", w.Body.String())
	}
}

// bindRole replaces one role in the live role map with allowed_agents set.
func bindRole(srv *Server, name string, agents ...string) {
	roles := map[string]config.RoleConfig{}
	for k, v := range srv.sessionRoles {
		roles[k] = v
	}
	r := roles[name]
	r.AllowedAgents = agents
	roles[name] = r
	srv.SetSessionRoles(roles)
}

func TestRoleBindingAtMint(t *testing.T) {
	srv, adminToken := setupTestServerWithStepUp(t)
	bindRole(srv, "deploy", "deployer")

	// admin is not bound: no approval is even created.
	expectRoleNotAllowed(t, postJSON(srv, "/v1/session/mint", adminToken, `{"role":"deploy"}`))
	if n := len(srv.approvals.ListPending()); n != 0 {
		t.Fatalf("%d approvals created for an unbound agent, want 0", n)
	}

	// A non-step-up role is checked the same way.
	bindRole(srv, "dev", "deployer")
	expectRoleNotAllowed(t, postJSON(srv, "/v1/session/mint", adminToken, `{"role":"dev"}`))

	// A listed agent still gets the normal step-up 202.
	bindRole(srv, "deploy", "deployer", "admin")
	if w := postJSON(srv, "/v1/session/mint", adminToken, `{"role":"deploy"}`); w.Code != http.StatusAccepted {
		t.Fatalf("bound agent: status %d, want 202; body %s", w.Code, w.Body.String())
	}
}

func TestRoleBindingAtAPIApproval(t *testing.T) {
	srv, adminToken := setupTestServerWithStepUp(t)

	w := postJSON(srv, "/v1/session/mint", adminToken, `{"role":"deploy"}`)
	var mint struct {
		ApprovalID string `json:"approval_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &mint)
	if mint.ApprovalID == "" {
		t.Fatalf("mint: %d %s", w.Code, w.Body.String())
	}

	// Binding added while the request was pending: approval is refused.
	bindRole(srv, "deploy", "deployer")
	expectRoleNotAllowed(t, postJSON(srv, "/v1/approval/"+mint.ApprovalID+"/approve", adminToken, "{}"))
	if apr := srv.approvals.Get(mint.ApprovalID); apr.Status != "pending" || apr.SessionID != "" {
		t.Fatalf("approval = %s (session %q), want still pending with no session", apr.Status, apr.SessionID)
	}
}

func TestRoleBindingAtRenewal(t *testing.T) {
	srv, adminToken := setupTestServerWithSessions(t)
	tok := mintTestSession(t, srv, adminToken, "dev")

	bindRole(srv, "dev", "deployer")
	expectRoleNotAllowed(t, postJSON(srv, "/v1/session/renew", tok, "{}"))

	bindRole(srv, "dev", "deployer", "admin")
	if w := postJSON(srv, "/v1/session/renew", tok, "{}"); w.Code != http.StatusOK {
		t.Fatalf("bound agent renew: status %d; body %s", w.Code, w.Body.String())
	}
}
