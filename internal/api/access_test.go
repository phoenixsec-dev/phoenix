package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/audit"
	"github.com/phoenixsec/phoenix/internal/ca"
	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/crypto"
	"github.com/phoenixsec/phoenix/internal/grant"
	"github.com/phoenixsec/phoenix/internal/policy"
	"github.com/phoenixsec/phoenix/internal/session"
	"github.com/phoenixsec/phoenix/internal/token"
)

// --- fixture -----------------------------------------------------------------

// testClock is an adjustable clock shared by the grant store and the server.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// grantEnv is the API approver fixture: a server with access requests on,
// an agent "vector" (dev/** only, registered seal key), an approver agent
// "approver" listed in access_requests.approvers, and "admin" (ACL admin on
// everything but NOT an approver). Secrets infra/b2/app-key and
// infra/other exist.
type grantEnv struct {
	srv      *Server
	dir      string
	store    *grant.Store
	clock    *testClock
	sealKP   *crypto.SealKeyPair
	sealPub  string
	settings config.AccessRequestsSettings
}

const (
	vectorTok   = "vector-token"
	approverTok = "approver-token"
	adminTok    = "admin-token"
)

func newGrantEnv(t *testing.T, opts ...func(*grant.Options)) *grantEnv {
	t.Helper()
	srv, _ := setupTestServer(t)
	e := &grantEnv{srv: srv, dir: t.TempDir(), clock: &testClock{t: time.Now().UTC()}}
	if err := srv.acl.AddAgent("vector", vectorTok, []acl.Permission{{Path: "dev/**", Actions: []acl.Action{acl.ActionList, acl.ActionReadValue}}}); err != nil {
		t.Fatal(err)
	}
	if err := srv.acl.AddAgent("approver", approverTok, nil); err != nil {
		t.Fatal(err)
	}
	kp, _ := crypto.GenerateSealKeyPair()
	e.sealKP, e.sealPub = kp, crypto.EncodeSealKey(&kp.PublicKey)
	if err := srv.acl.SetAgentSealKey("vector", e.sealPub); err != nil {
		t.Fatal(err)
	}
	seedSecret(t, srv, adminTok, "infra/b2/app-key", "b2-secret-value")
	seedSecret(t, srv, adminTok, "infra/other", "other-secret-value")
	seedSecret(t, srv, adminTok, "dev/db", "dev-db-value")

	o := grant.Options{
		Path:        filepath.Join(e.dir, "grants.json"),
		Audit:       NewGrantAuditSink(srv.audit),
		Now:         e.clock.Now,
		AgentExists: func(n string) bool { _, err := srv.acl.GetAgent(n); return err == nil },
		Logf:        t.Logf,
	}
	for _, f := range opts {
		f(&o)
	}
	st, err := grant.Open(o)
	if err != nil {
		t.Fatal(err)
	}
	e.store = st
	srv.SetGrantStore(st)
	srv.now = e.clock.Now
	e.settings = (&config.Config{AccessRequests: config.NewInstallAccessRequests()}).AccessRequestsSettings()
	e.settings.Approvers = []string{"approver"}
	srv.SetAccessRequests(e.settings)
	return e
}

// set changes the live access_requests settings.
func (e *grantEnv) set(f func(*config.AccessRequestsSettings)) {
	s := e.settings
	s.Approvers = append([]string(nil), s.Approvers...)
	f(&s)
	e.settings = s
	e.srv.SetAccessRequests(s)
}

// do sends one request. hdr is "Name: value" pairs; "RemoteAddr: ip" sets the source.
func (e *grantEnv) do(method, path, tok, body string, hdr ...string) *httptest.ResponseRecorder {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	for _, h := range hdr {
		k, v, _ := strings.Cut(h, ": ")
		if k == "RemoteAddr" {
			req.RemoteAddr = v + ":1234"
			continue
		}
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, req)
	return w
}

func jsonBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return m
}

// expect checks status and, when code != "", the denial code.
func expect(t *testing.T, w *httptest.ResponseRecorder, status int, code string) map[string]any {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status = %d, want %d; body %s", w.Code, status, w.Body.String())
	}
	m := jsonBody(t, w)
	if code != "" && m["code"] != code {
		t.Fatalf("code = %v, want %s; body %s", m["code"], code, w.Body.String())
	}
	return m
}

// request files a request for vector and returns its id.
func (e *grantEnv) request(t *testing.T, tok string, paths ...string) string {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"paths": paths, "action": "read_value", "reason": "backup job fails auth", "ttl": "30m"})
	m := expect(t, e.do("POST", "/v1/access-requests", tok, string(b)), http.StatusCreated, "")
	return m["id"].(string)
}

// approve approves id as "approver" and returns the grant id.
func (e *grantEnv) approve(t *testing.T, id, body string) string {
	t.Helper()
	m := expect(t, e.do("POST", "/v1/access-requests/"+id+"/approve", approverTok, body), http.StatusOK, "")
	return m["grant_id"].(string)
}

func (e *grantEnv) sealedGet(path, tok string) *httptest.ResponseRecorder {
	return e.do("GET", "/v1/secrets/"+path, tok, "", "X-Phoenix-Seal-Key: "+e.sealPub)
}

func (e *grantEnv) openSealed(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var resp struct {
		SealedValue *crypto.SealedEnvelope `json:"sealed_value"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.SealedValue == nil {
		t.Fatalf("no sealed_value in %s", w.Body.String())
	}
	p, err := crypto.OpenSealedEnvelope(resp.SealedValue, &e.sealKP.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return p.Value
}

// --- happy path, enforcement, revoke and expiry ------------------------------

func TestRequestUseFullFlow(t *testing.T) {
	e := newGrantEnv(t)

	// Denied today, and told it may request use.
	d := expect(t, e.sealedGet("infra/b2/app-key", vectorTok), http.StatusForbidden, CodeACLDenied)
	if d["next_step"] != NextRequestUse {
		t.Fatalf("next_step = %v, want request_use", d["next_step"])
	}

	id := e.request(t, vectorTok, "infra/b2/app-key", "infra/other")
	st := expect(t, e.do("GET", "/v1/access-requests/"+id, vectorTok, ""), http.StatusOK, "")
	if st["status"] != "pending" || st["next_step"] != NextWait {
		t.Fatalf("pending view = %v", st)
	}
	if _, leaked := st["source_ip"]; leaked {
		t.Fatal("agent view must not include approver-only fields")
	}
	// Identical pending request: 200, same id.
	dup := e.do("POST", "/v1/access-requests", vectorTok, `{"paths":["infra/other","infra/b2/app-key"],"reason":"again"}`)
	if m := expect(t, dup, http.StatusOK, ""); m["id"] != id {
		t.Fatalf("duplicate got id %v, want %s", m["id"], id)
	}
	if cc := dup.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q", cc)
	}

	// Approver narrows to one path and 15m.
	gid := e.approve(t, id, `{"paths":["infra/b2/app-key"],"ttl":"15m"}`)
	st = expect(t, e.do("GET", "/v1/access-requests/"+id, vectorTok, ""), http.StatusOK, "")
	if st["status"] != "approved" || st["next_step"] != NextUseExec || st["grant_id"] != gid || st["sealed_only"] != true {
		t.Fatalf("approved view = %v", st)
	}

	// Sealed use to the registered key works and is audited with grant_id.
	w := e.sealedGet("infra/b2/app-key", vectorTok)
	expect(t, w, http.StatusOK, "")
	if got := e.openSealed(t, w); got != "b2-secret-value" {
		t.Fatalf("value = %q", got)
	}
	entries, _ := queryAPIAuditEntries(t, e.srv, adminTok)
	if a := findAPIAuditEntry(entries, "read_value", "infra/b2/app-key", "allowed", ""); a == nil || a.Metadata["grant_id"] != gid {
		t.Fatalf("allowed audit entry missing grant_id: %+v", a)
	}

	// Plaintext is refused for a sealed-only grant.
	d = expect(t, e.do("GET", "/v1/secrets/infra/b2/app-key", vectorTok, ""), http.StatusForbidden, CodeSealedRequired)
	if d["next_step"] != NextUseExec {
		t.Fatalf("next_step = %v", d["next_step"])
	}
	// Resolve through the grant (sealed) works; the narrowed-out path does not.
	rw := e.do("POST", "/v1/resolve", vectorTok, `{"refs":["phoenix://infra/b2/app-key","phoenix://infra/other"]}`, "X-Phoenix-Seal-Key: "+e.sealPub)
	rm := expect(t, rw, http.StatusOK, "")
	if _, ok := rm["sealed_values"].(map[string]any)["phoenix://infra/b2/app-key"]; !ok {
		t.Fatalf("resolve did not return the granted value: %v", rm)
	}
	if c := rm["error_codes"].(map[string]any)["phoenix://infra/other"].(map[string]any)["code"]; c != CodeACLDenied {
		t.Fatalf("other path code = %v", c)
	}
	expect(t, e.sealedGet("infra/other", vectorTok), http.StatusForbidden, CodeACLDenied)
	// Grants never cover write, delete or list.
	expect(t, e.do("PUT", "/v1/secrets/infra/b2/app-key", vectorTok, `{"value":"x"}`), http.StatusForbidden, CodeACLDenied)
	expect(t, e.do("DELETE", "/v1/secrets/infra/b2/app-key", vectorTok, ""), http.StatusForbidden, CodeACLDenied)
	if l := expect(t, e.do("GET", "/v1/secrets/infra/", vectorTok, ""), http.StatusOK, ""); len(l["paths"].([]any)) != 0 {
		t.Fatalf("list exposed paths through a grant: %v", l)
	}
	// Bound to the source IP the request came from (httptest uses 192.0.2.1).
	other := e.do("GET", "/v1/secrets/infra/b2/app-key", vectorTok, "", "X-Phoenix-Seal-Key: "+e.sealPub, "RemoteAddr: 192.0.2.99")
	expect(t, other, http.StatusForbidden, CodeACLDenied)

	// Revoke is immediate: the very next use fails with GRANT_REVOKED.
	rv := expect(t, e.do("POST", "/v1/grants/"+gid+"/revoke", approverTok, ""), http.StatusOK, "")
	if rv["state"] != "revoked" {
		t.Fatalf("revoke response = %v", rv)
	}
	d = expect(t, e.sealedGet("infra/b2/app-key", vectorTok), http.StatusForbidden, CodeGrantRevoked)
	if d["next_step"] != NextAskUser {
		t.Fatalf("revoked next_step = %v", d["next_step"])
	}
	if st = expect(t, e.do("GET", "/v1/access-requests/"+id, vectorTok, ""), http.StatusOK, ""); st["next_step"] != NextAskUser {
		t.Fatalf("revoked request next_step = %v", st["next_step"])
	}
	// Revoke is idempotent.
	expect(t, e.do("POST", "/v1/grants/"+gid+"/revoke", approverTok, ""), http.StatusOK, "")
}

func TestGrantExpiryIsImmediate(t *testing.T) {
	e := newGrantEnv(t)
	id := e.request(t, vectorTok, "infra/b2/app-key")
	gid := e.approve(t, id, `{"ttl":"5m"}`)
	expect(t, e.sealedGet("infra/b2/app-key", vectorTok), http.StatusOK, "")

	e.clock.Advance(5*time.Minute - time.Second)
	expect(t, e.sealedGet("infra/b2/app-key", vectorTok), http.StatusOK, "")
	e.clock.Advance(time.Second) // exactly at expires_at: already expired
	d := expect(t, e.sealedGet("infra/b2/app-key", vectorTok), http.StatusForbidden, CodeGrantExpired)
	if d["next_step"] != NextRequestUse {
		t.Fatalf("expired next_step = %v", d["next_step"])
	}
	st := expect(t, e.do("GET", "/v1/access-requests/"+id, vectorTok, ""), http.StatusOK, "")
	if st["next_step"] != NextRequestUse || st["grant_state"] != "expired" {
		t.Fatalf("expired request view = %v", st)
	}
	// Agent may still list its own inactive grants.
	l := expect(t, e.do("GET", "/v1/grants?include=inactive", vectorTok, ""), http.StatusOK, "")
	if gs := l["grants"].([]any); len(gs) != 1 || gs[0].(map[string]any)["id"] != gid {
		t.Fatalf("grants = %v", l)
	}
}

func TestAttestationStillAppliesToGrants(t *testing.T) {
	e := newGrantEnv(t)
	pe, err := policy.Load([]byte(`{"attestation":{"infra/*":{"deny_bearer":true}}}`))
	if err != nil {
		t.Fatal(err)
	}
	e.srv.SetPolicy(pe)
	e.approve(t, e.request(t, vectorTok, "infra/other"), "")
	d := expect(t, e.sealedGet("infra/other", vectorTok), http.StatusForbidden, CodeAttestationRequired)
	if d["next_step"] != NextAskUser {
		t.Fatalf("next_step = %v", d["next_step"])
	}
}

// --- create errors and limits ------------------------------------------------

func TestAccessRequestCreateErrors(t *testing.T) {
	e := newGrantEnv(t)
	e.set(func(s *config.AccessRequestsSettings) { s.DenyPaths = []string{"phoenix/**"} })
	if err := e.srv.acl.AddAgent("nokey", "nokey-token", nil); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, tok, body string
		status          int
		code            string
	}{
		{"write not grantable", vectorTok, `{"paths":["infra/x"],"action":"write","reason":"r"}`, 400, CodeActionNotGrantable},
		{"glob path", vectorTok, `{"paths":["infra/*"],"reason":"r"}`, 400, CodeInvalidRequest},
		{"bidi path", vectorTok, `{"paths":["infra/\u202ex"],"reason":"r"}`, 400, CodeInvalidRequest},
		{"no paths", vectorTok, `{"paths":[],"reason":"r"}`, 400, CodeInvalidRequest},
		{"no reason", vectorTok, `{"paths":["infra/x"]}`, 400, CodeInvalidRequest},
		{"bad ttl", vectorTok, `{"paths":["infra/x"],"reason":"r","ttl":"soon"}`, 400, CodeInvalidRequest},
		{"bad body", vectorTok, `{`, 400, CodeInvalidRequest},
		{"deny_paths", vectorTok, `{"paths":["infra/x","phoenix/admin-token"],"reason":"r"}`, 403, CodeNotRequestable},
		{"already allowed", vectorTok, `{"paths":["dev/db","dev/other"],"reason":"r"}`, 409, CodeAlreadyAllowed},
		{"no seal key", "nokey-token", `{"paths":["infra/x"],"reason":"r"}`, 400, CodeSealKeyNotRegistered},
		{"unauthenticated", "", `{"paths":["infra/x"],"reason":"r"}`, 401, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			expect(t, e.do("POST", "/v1/access-requests", c.tok, c.body), c.status, c.code)
		})
	}

	// A mixed request (one path already allowed) is accepted, and so is a
	// path that does not exist: same 201 shape, no existence oracle.
	mixed := expect(t, e.do("POST", "/v1/access-requests", vectorTok, `{"paths":["dev/db","infra/nope"],"reason":"r"}`), 201, "")
	missing := expect(t, e.do("POST", "/v1/access-requests", vectorTok, `{"paths":["infra/b2/app-key"],"reason":"r"}`), 201, "")
	if len(mixed) != len(missing) {
		t.Fatalf("response shape differs for a missing path: %v vs %v", mixed, missing)
	}
	// Approver view flags the already-allowed path.
	full := expect(t, e.do("GET", "/v1/access-requests/"+mixed["id"].(string), approverTok, ""), 200, "")
	if aa := full["already_allowed_paths"].([]any); len(aa) != 1 || aa[0] != "dev/db" {
		t.Fatalf("already_allowed_paths = %v", full["already_allowed_paths"])
	}

	// Third pending is fine, fourth is TOO_MANY_PENDING with Retry-After.
	e.request(t, vectorTok, "infra/third")
	w := e.do("POST", "/v1/access-requests", vectorTok, `{"paths":["infra/fourth"],"reason":"r"}`)
	expect(t, w, http.StatusTooManyRequests, CodeTooManyPending)
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}
	entries, _ := queryAPIAuditEntries(t, e.srv, adminTok)
	if findAPIAuditEntry(entries, "access_request.create", "infra/fourth", "denied", "too_many_pending") == nil {
		t.Fatal("429 was not audited")
	}
}

func TestAccessRequestCooldownAndRateLimit(t *testing.T) {
	e := newGrantEnv(t)
	id := e.request(t, vectorTok, "infra/a", "infra/b")
	expect(t, e.do("POST", "/v1/access-requests/"+id+"/deny", approverTok, `{"note":"not now"}`), 200, "")
	// Any overlapping path is in cooldown; a different path is not.
	w := e.do("POST", "/v1/access-requests", vectorTok, `{"paths":["infra/b"],"reason":"r"}`)
	expect(t, w, http.StatusTooManyRequests, CodeRequestCooldown)
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("cooldown without Retry-After")
	}
	st := expect(t, e.do("GET", "/v1/access-requests/"+id, vectorTok, ""), 200, "")
	if st["status"] != "denied" || st["next_step"] != NextAskUser || st["note"] != "not now" {
		t.Fatalf("denied view = %v", st)
	}
	// 10 creates per hour (the denied one counts): 9 more, then RATE_LIMITED.
	for i := range 9 {
		rid := e.request(t, vectorTok, fmt.Sprintf("infra/r%d", i))
		expect(t, e.do("POST", "/v1/access-requests/"+rid+"/deny", approverTok, ""), 200, "")
	}
	expect(t, e.do("POST", "/v1/access-requests", vectorTok, `{"paths":["infra/c"],"reason":"r"}`), http.StatusTooManyRequests, CodeRateLimited)
}

func TestAccessRequestStoreFailures(t *testing.T) {
	t.Run("degraded store", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "grants.json")
		if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
			t.Fatal(err)
		}
		e := newGrantEnv(t, func(o *grant.Options) { o.Path = path })
		expect(t, e.do("POST", "/v1/access-requests", vectorTok, `{"paths":["infra/x"],"reason":"r"}`), http.StatusServiceUnavailable, CodeRequestsDegraded)
		st := expect(t, e.do("GET", "/v1/status", adminTok, ""), 200, "")
		if ar := st["access_requests"].(map[string]any); ar["state"] != "degraded" || ar["quarantined_to"] == nil {
			t.Fatalf("status access_requests = %v", ar)
		}
	})
	t.Run("audit degraded", func(t *testing.T) {
		e := newGrantEnv(t, func(o *grant.Options) {
			// The committed line for a new request cannot be written.
			o.Audit = NewGrantAuditSink(audit.NewWriterLogger(failOn{`"access_request.created"`}))
		})
		e.request(t, vectorTok, "infra/x")
		st := expect(t, e.do("GET", "/v1/status", adminTok, ""), 200, "")
		if a := st["audit"].(map[string]any); a["state"] != "degraded" {
			t.Fatalf("status audit = %v", a)
		}
	})
	t.Run("audit attempt fails", func(t *testing.T) {
		e := newGrantEnv(t, func(o *grant.Options) {
			o.Audit = NewGrantAuditSink(audit.NewWriterLogger(failOn{`"access_request.create.attempt"`}))
		})
		expect(t, e.do("POST", "/v1/access-requests", vectorTok, `{"paths":["infra/x"],"reason":"r"}`), 500, string(grant.CodeAuditWriteFailed))
	})
}

// failOn is an audit writer that fails any line containing marker.
type failOn struct{ marker string }

func (f failOn) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(f.marker)) {
		return 0, errors.New("disk full")
	}
	return len(p), nil
}

// --- approver rules ----------------------------------------------------------

func TestApproverRules(t *testing.T) {
	e := newGrantEnv(t)
	// The approver is also an agent that can file its own requests.
	if err := e.srv.acl.SetAgentSealKey("approver", e.sealPub); err != nil {
		t.Fatal(err)
	}
	id := e.request(t, vectorTok, "infra/b2/app-key", "infra/other")
	own := e.request(t, approverTok, "infra/other")

	// Admin ACL alone is not enough; sessions never approve.
	expect(t, e.do("POST", "/v1/access-requests/"+id+"/approve", adminTok, ""), 403, CodeApproverRequired)
	expect(t, e.do("POST", "/v1/access-requests/"+id+"/deny", adminTok, ""), 403, CodeApproverRequired)
	expect(t, e.do("POST", "/v1/access-requests/"+id+"/approve", vectorTok, ""), 403, CodeApproverRequired)
	// Unknown ids look the same to a non-approver.
	expect(t, e.do("POST", "/v1/access-requests/req_nope/approve", vectorTok, ""), 403, CodeApproverRequired)
	// Self-approval is blocked even for a listed approver.
	expect(t, e.do("POST", "/v1/access-requests/"+own+"/approve", approverTok, ""), 403, CodeSelfApproval)
	expect(t, e.do("POST", "/v1/access-requests/"+own+"/deny", approverTok, ""), 403, CodeSelfApproval)

	// Agents see only their own requests; others are 404.
	expect(t, e.do("GET", "/v1/access-requests/"+own, vectorTok, ""), 404, CodeNotFound)
	l := expect(t, e.do("GET", "/v1/access-requests", vectorTok, ""), 200, "")
	if n := len(l["requests"].([]any)); n != 1 {
		t.Fatalf("vector sees %d requests, want 1", n)
	}
	expect(t, e.do("GET", "/v1/access-requests?agent=approver", vectorTok, ""), 403, CodeApproverRequired)
	// Approvers see everything, with full detail.
	l = expect(t, e.do("GET", "/v1/access-requests?status=pending", approverTok, ""), 200, "")
	if n := len(l["requests"].([]any)); n != 2 {
		t.Fatalf("approver sees %d requests, want 2", n)
	}
	full := expect(t, e.do("GET", "/v1/access-requests/"+id, approverTok, ""), 200, "")
	if full["agent"] != "vector" || full["source_ip"] == nil || full["reason"] == nil {
		t.Fatalf("approver view = %v", full)
	}

	expect(t, e.do("POST", "/v1/access-requests/"+id+"/approve", approverTok, `{"paths":["infra/new"]}`), 400, CodeWideningNotAllowed)
	expect(t, e.do("POST", "/v1/access-requests/"+id+"/approve", approverTok, `{"paths":[]}`), 400, CodeEmptyGrant)
	expect(t, e.do("POST", "/v1/access-requests/"+id+"/approve", approverTok, `{"ttl":"2h"}`), 400, CodeWideningNotAllowed)
	expect(t, e.do("POST", "/v1/access-requests/req_nope/approve", approverTok, ""), 404, CodeNotFound)
	gid := e.approve(t, id, `{"paths":["infra/other"],"ttl":"10m"}`)
	// Same decision again returns the original grant; a different one is 409.
	if again := e.approve(t, id, `{"paths":["infra/other"],"ttl":"10m"}`); again != gid {
		t.Fatalf("repeat approve gave %s, want %s", again, gid)
	}
	expect(t, e.do("POST", "/v1/access-requests/"+id+"/approve", approverTok, ""), 409, CodeNotPending)
	expect(t, e.do("POST", "/v1/access-requests/"+id+"/deny", approverTok, ""), 409, CodeNotPending)

	// Revoke: other agents get 404; the owner may give it up; approvers may revoke any.
	if err := e.srv.acl.AddAgent("mallory", "mallory-token", nil); err != nil {
		t.Fatal(err)
	}
	expect(t, e.do("POST", "/v1/grants/"+gid+"/revoke", "mallory-token", ""), 404, CodeNotFound)
	g := expect(t, e.do("GET", "/v1/grants?agent=vector", approverTok, ""), 200, "")
	if n := len(g["grants"].([]any)); n != 1 {
		t.Fatalf("approver sees %d vector grants", n)
	}
	expect(t, e.do("GET", "/v1/grants?agent=vector", "mallory-token", ""), 403, CodeApproverRequired)
	expect(t, e.do("POST", "/v1/grants/"+gid+"/revoke", vectorTok, ""), 200, "")
}

func TestApprovalRechecksCurrentConfig(t *testing.T) {
	e := newGrantEnv(t)
	id := e.request(t, vectorTok, "infra/b2/app-key", "infra/other")

	e.set(func(s *config.AccessRequestsSettings) { s.DenyPaths = []string{"infra/other"} })
	expect(t, e.do("POST", "/v1/access-requests/"+id+"/approve", approverTok, ""), 403, CodeNotRequestable)

	e.set(func(s *config.AccessRequestsSettings) { s.Enabled = false })
	expect(t, e.do("POST", "/v1/access-requests/"+id+"/approve", approverTok, `{"paths":["infra/b2/app-key"]}`), 501, CodeRequestsDisabled)

	e.set(func(s *config.AccessRequestsSettings) { s.Approvers = nil; s.Enabled = true })
	expect(t, e.do("POST", "/v1/access-requests/"+id+"/approve", approverTok, `{"paths":["infra/b2/app-key"]}`), 403, CodeApproverRequired)

	// Narrowing out the deny-listed path is fine; current max TTL and
	// require_sealed apply, not the values at request time.
	e.set(func(s *config.AccessRequestsSettings) {
		s.Approvers = []string{"approver"}
		s.MaxGrantTTL = 10 * time.Minute
		s.RequireSealed = false
	})
	m := expect(t, e.do("POST", "/v1/access-requests/"+id+"/approve", approverTok, `{"paths":["infra/b2/app-key"]}`), 200, "")
	exp, _ := time.Parse(time.RFC3339, m["expires_at"].(string))
	if d := exp.Sub(e.clock.Now()); d > 10*time.Minute {
		t.Fatalf("grant lasts %s, want <= 10m (current max_grant_ttl)", d)
	}
	if m["sealed_only"] != false {
		t.Fatalf("sealed_only = %v, want false from current require_sealed", m["sealed_only"])
	}
	w := e.do("GET", "/v1/secrets/infra/b2/app-key", vectorTok, "")
	if expect(t, w, 200, "")["value"] != "b2-secret-value" {
		t.Fatalf("plaintext grant read = %s", w.Body.String())
	}

	// require_sealed turned on later: an agent without a seal key is refused
	// at approval, so a human never approves something unusable.
	id2 := e.request(t, vectorTok, "infra/other2")
	e.set(func(s *config.AccessRequestsSettings) { s.RequireSealed = true })
	// Re-create vector's ACL entry without a seal key (same token).
	if err := e.srv.acl.UpdateAgent("vector", vectorTok, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.acl.RemoveAgent("vector"); err != nil {
		t.Fatal(err)
	}
	e.addVector(t, vectorTok)
	expect(t, e.do("POST", "/v1/access-requests/"+id2+"/approve", approverTok, ""), 400, CodeSealKeyNotRegistered)
}

// --- disabled / upgrade ------------------------------------------------------

func TestMissingConfigBlockMeansDisabled(t *testing.T) {
	// An upgraded config without access_requests: feature off.
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"server":{"listen":"127.0.0.1:9090"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AccessRequests != nil || cfg.AccessRequestsSettings().Enabled {
		t.Fatal("missing access_requests block must mean disabled")
	}

	e := newGrantEnv(t)
	// A grant made while enabled ...
	gid := e.approve(t, e.request(t, vectorTok, "infra/b2/app-key"), "")
	expect(t, e.sealedGet("infra/b2/app-key", vectorTok), 200, "")
	// ... stops working when the feature is turned off.
	e.srv.SetAccessRequests(cfg.AccessRequestsSettings())
	d := expect(t, e.sealedGet("infra/b2/app-key", vectorTok), 403, CodeACLDenied)
	if d["next_step"] != NextAskUser {
		t.Fatalf("disabled next_step = %v, want ask_user", d["next_step"])
	}
	expect(t, e.do("POST", "/v1/access-requests", vectorTok, `{"paths":["infra/x"],"reason":"r"}`), 501, CodeRequestsDisabled)
	// Listing and revoking still work.
	expect(t, e.do("GET", "/v1/grants", vectorTok, ""), 200, "")
	expect(t, e.do("POST", "/v1/grants/"+gid+"/revoke", vectorTok, ""), 200, "")

	// No grant store at all: the API is 501 and nothing else changes.
	srv, admin := setupTestServer(t)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/access-requests", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+admin)
	srv.ServeHTTP(w, req)
	expect(t, w, 501, CodeRequestsDisabled)
}

func TestRequestUseOnlyAdvertisedWhenRequestable(t *testing.T) {
	e := newGrantEnv(t)
	e.set(func(s *config.AccessRequestsSettings) { s.DenyPaths = []string{"infra/other"} })
	step := func(w *httptest.ResponseRecorder) any { return jsonBody(t, w)["next_step"] }
	if s := step(e.sealedGet("infra/b2/app-key", vectorTok)); s != NextRequestUse {
		t.Fatalf("requestable path next_step = %v", s)
	}
	if s := step(e.sealedGet("infra/other", vectorTok)); s != NextAskUser {
		t.Fatalf("deny_paths next_step = %v", s)
	}
	if s := step(e.do("PUT", "/v1/secrets/infra/b2/app-key", vectorTok, `{"value":"x"}`)); s != NextAskUser {
		t.Fatalf("write next_step = %v", s)
	}
	rm := expect(t, e.do("POST", "/v1/resolve", vectorTok, `{"refs":["phoenix://infra/b2/app-key","phoenix://infra/other"]}`), 200, "")
	codes := rm["error_codes"].(map[string]any)
	if codes["phoenix://infra/b2/app-key"].(map[string]any)["next_step"] != NextRequestUse ||
		codes["phoenix://infra/other"].(map[string]any)["next_step"] != NextAskUser {
		t.Fatalf("resolve error_codes = %v", codes)
	}
	e.set(func(s *config.AccessRequestsSettings) { s.Enabled = false })
	if s := step(e.sealedGet("infra/b2/app-key", vectorTok)); s != NextAskUser {
		t.Fatalf("disabled next_step = %v", s)
	}
}

// --- sessions and unseal -----------------------------------------------------

// addSessions turns on sessions with a non-elevated role covering infra/** and dev/**.
func (e *grantEnv) addSessions(t *testing.T) {
	t.Helper()
	ss, err := session.NewStore(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ss.Stop)
	e.srv.SetSessionStore(ss)
	e.srv.SetSessionRoles(map[string]config.RoleConfig{
		"wide": {Namespaces: []string{"infra/**", "dev/**"}, Actions: []string{"list", "read_value"}, BootstrapTrust: []string{"bearer"}},
	})
}

func (e *grantEnv) mintSession(t *testing.T, sealPub string) string {
	t.Helper()
	body := `{"role":"wide"}`
	if sealPub != "" {
		body = `{"role":"wide","seal_public_key":"` + sealPub + `"}`
	}
	m := expect(t, e.do("POST", "/v1/session/mint", vectorTok, body), 200, "")
	return m["session_token"].(string)
}

func TestSessionCannotUseOrRequestGrant(t *testing.T) {
	e := newGrantEnv(t)
	e.addSessions(t)
	e.approve(t, e.request(t, vectorTok, "infra/b2/app-key"), "")
	expect(t, e.sealedGet("infra/b2/app-key", vectorTok), 200, "") // grant is active

	// An ordinary session of the same agent, in scope, with an attacker-chosen
	// seal key, must not reach the grant.
	evil, _ := crypto.GenerateSealKeyPair()
	evilPub := crypto.EncodeSealKey(&evil.PublicKey)
	sess := e.mintSession(t, evilPub)
	d := expect(t, e.do("GET", "/v1/secrets/infra/b2/app-key", sess, "", "X-Phoenix-Seal-Key: "+evilPub), 403, CodeACLDenied)
	if d["next_step"] != NextRequestUse {
		t.Fatalf("session denial on requestable path next_step = %v", d["next_step"])
	}
	rm := expect(t, e.do("POST", "/v1/resolve", sess, `{"refs":["phoenix://infra/b2/app-key"]}`, "X-Phoenix-Seal-Key: "+evilPub), 200, "")
	if _, ok := rm["sealed_values"].(map[string]any)["phoenix://infra/b2/app-key"]; ok {
		t.Fatal("session resolved a grant-only secret")
	}

	// The sharpest case: a session presented together with the same mTLS
	// client certificate the grant is bound to. The session layer copies the
	// cert fingerprint into the auth info, so only the "sessions never
	// consult grants" rule keeps the caller-chosen seal key away.
	authority := setCA(t, e.srv)
	cert := issueCertPEM(t, authority, "vector")
	e.srv.SetSessionRoles(map[string]config.RoleConfig{
		"wide": {Namespaces: []string{"infra/**"}, Actions: []string{"read_value"}, BootstrapTrust: []string{"mtls"}},
	})
	mtls := func(method, path, tok, body string, hdr ...string) *httptest.ResponseRecorder {
		var b []byte
		if body != "" {
			b = []byte(body)
		}
		req := makeMTLSRequest(method, path, b, cert)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		for _, h := range hdr {
			k, v, _ := strings.Cut(h, ": ")
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		e.srv.ServeHTTP(w, req)
		return w
	}
	id := expect(t, mtls("POST", "/v1/access-requests", "", `{"paths":["infra/other"],"reason":"r"}`), 201, "")["id"].(string)
	e.approve(t, id, "")
	expect(t, mtls("GET", "/v1/secrets/infra/other", "", "", "X-Phoenix-Seal-Key: "+e.sealPub), 200, "")
	mtlsSess := expect(t, mtls("POST", "/v1/session/mint", "", `{"role":"wide","seal_public_key":"`+evilPub+`"}`), 200, "")["session_token"].(string)
	expect(t, mtls("GET", "/v1/secrets/infra/other", mtlsSess, "", "X-Phoenix-Seal-Key: "+evilPub), 403, CodeACLDenied)

	// Sessions cannot file requests or list grants; whoami says why.
	expect(t, e.do("POST", "/v1/access-requests", sess, `{"paths":["infra/x"],"reason":"r"}`), 403, CodeSessionCannotRequest)
	expect(t, e.do("GET", "/v1/grants", sess, ""), 403, CodeSessionCannotRequest)
	who := expect(t, e.do("GET", "/v1/whoami", sess, ""), 200, "")
	if who["auth_method"] != "session" || len(who["grants"].([]any)) != 0 || who["session"] == nil {
		t.Fatalf("session whoami = %v", who)
	}
}

func TestPolicyCheckUnsealTruthTable(t *testing.T) {
	e := newGrantEnv(t)
	e.addSessions(t)
	pe, err := policy.Load([]byte(`{"attestation":{"infra/*":{"allow_unseal":true},"dev/**":{"allow_unseal":true},"dev/locked":{"allow_unseal":false}}}`))
	if err != nil {
		t.Fatal(err)
	}
	e.srv.SetPolicy(pe)
	gid := e.approve(t, e.request(t, vectorTok, "infra/other"), "")
	w := e.sealedGet("infra/other", vectorTok)
	expect(t, w, 200, "") // an envelope the agent could have cached

	check := func(tok, path string) any {
		t.Helper()
		m := expect(t, e.do("GET", "/v1/policy/check?check=allow_unseal&path="+path, tok, ""), 200, "")
		return m["allowed"]
	}
	sess := e.mintSession(t, "")
	cases := []struct {
		name, tok, path string
		want            bool
	}{
		{"ACL + allow_unseal", vectorTok, "dev/db", true},
		{"ACL + allow_unseal false", vectorTok, "dev/locked", false},
		{"ACL + no rule", "admin-token", "elsewhere/x", false},
		{"active grant never unseals", vectorTok, "infra/other", false},
		{"no access", vectorTok, "prod/x", false},
		{"session in scope + ACL", sess, "dev/db", true},
		{"session in scope, ACL only via grant", sess, "infra/other", false},
		{"openclaw probe shape", vectorTok, "openclaw/startup-preflight-auth-probe", false},
		{"hermes session probe shape", sess, "hermes/startup-preflight-auth-probe", false},
	}
	for _, c := range cases {
		if got := check(c.tok, c.path); got != c.want {
			t.Errorf("%s: allowed = %v, want %v", c.name, got, c.want)
		}
	}
	// Still false after revoke and after expiry: a cached envelope stays closed.
	expect(t, e.do("POST", "/v1/grants/"+gid+"/revoke", approverTok, ""), 200, "")
	if check(vectorTok, "infra/other") != false {
		t.Fatal("unseal allowed after revoke")
	}
	gid2 := e.approve(t, e.request(t, vectorTok, "infra/b2/app-key"), `{"ttl":"1m"}`)
	e.clock.Advance(2 * time.Minute)
	if check(vectorTok, "infra/b2/app-key") != false {
		t.Fatalf("unseal allowed after expiry of %s", gid2)
	}
	expect(t, e.do("GET", "/v1/policy/check?check=allow_unseal&path=dev/db", "", ""), 401, "")
}

// --- agent delete and credential binding -------------------------------------

func TestAgentDeleteRevokesBeforeDelete(t *testing.T) {
	e := newGrantEnv(t)
	gid := e.approve(t, e.request(t, vectorTok, "infra/b2/app-key"), "")
	pending := e.request(t, vectorTok, "infra/other")

	expect(t, e.do("DELETE", "/v1/agents/vector", adminTok, ""), 200, "")
	g, _ := e.store.GetGrant(gid)
	if g.State(e.clock.Now()) != grant.GrantRevoked {
		t.Fatalf("grant state after delete = %s", g.State(e.clock.Now()))
	}
	if r, _ := e.store.GetRequest(pending); r.Status != grant.StatusExpired {
		t.Fatalf("pending request after delete = %s", r.Status)
	}
	expect(t, e.do("DELETE", "/v1/agents/vector", adminTok, ""), 404, "")

	// Recreated with a new token: the old token is gone, and the old grant
	// does not carry over.
	b, _ := json.Marshal(map[string]any{"name": "vector", "token": "vector-token-2", "permissions": []acl.Permission{}})
	expect(t, e.do("POST", "/v1/agents", adminTok, string(b)), 200, "")
	e.srv.acl.SetAgentSealKey("vector", e.sealPub)
	expect(t, e.sealedGet("infra/b2/app-key", vectorTok), 401, "")
	expect(t, e.sealedGet("infra/b2/app-key", "vector-token-2"), 403, CodeGrantRevoked)
}

func TestOldCredentialsCannotReachRecreatedAgentsGrants(t *testing.T) {
	t.Run("mtls", func(t *testing.T) {
		e := newGrantEnv(t)
		e.set(func(s *config.AccessRequestsSettings) { s.RequireSealed = false })
		authority := setCA(t, e.srv)
		oldCert := issueCertPEM(t, authority, "vector")

		e.delVector(t)
		e.addVector(t, "vector-token-2")
		newCert := issueCertPEM(t, authority, "vector")
		// The recreated agent requests over mTLS with its new cert.
		req := makeMTLSRequest("POST", "/v1/access-requests", []byte(`{"paths":["infra/other"],"reason":"r"}`), newCert)
		w := httptest.NewRecorder()
		e.srv.ServeHTTP(w, req)
		id := expect(t, w, 201, "")["id"].(string)
		e.approve(t, id, "")

		get := func(cert []byte) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			e.srv.ServeHTTP(w, makeMTLSRequest("GET", "/v1/secrets/infra/other", nil, cert))
			return w
		}
		expect(t, get(newCert), 200, "")
		expect(t, get(oldCert), 403, CodeACLDenied)
		// A bearer token of the same agent is a different credential kind.
		expect(t, e.do("GET", "/v1/secrets/infra/other", "vector-token-2", ""), 403, CodeACLDenied)
	})
	t.Run("short-lived token", func(t *testing.T) {
		e := newGrantEnv(t)
		e.clock = nil // tombstones use the real clock so they compare with token iat
		e.set(func(s *config.AccessRequestsSettings) { s.RequireSealed = false })
		st, err := grant.Open(grant.Options{
			Path:        filepath.Join(t.TempDir(), "grants.json"),
			AgentExists: func(n string) bool { _, err := e.srv.acl.GetAgent(n); return err == nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		e.store = st
		e.srv.SetGrantStore(st)
		e.srv.now = time.Now
		iss, _ := token.NewIssuer(time.Hour)
		e.srv.SetTokenIssuer(iss)

		oldTok, _, _ := iss.Mint("vector", nil, "")
		time.Sleep(2 * time.Millisecond)
		e.delVector(t)
		e.addVector(t, "vector-token-2")
		time.Sleep(2 * time.Millisecond)
		newTok, _, _ := iss.Mint("vector", nil, "")
		e.approve(t, e.request(t, newTok, "infra/other"), "")

		expect(t, e.do("GET", "/v1/secrets/infra/other", newTok, ""), 200, "")
		expect(t, e.do("GET", "/v1/secrets/infra/other", oldTok, ""), 403, CodeACLDenied)
	})
}

// setCA turns on mTLS with a fresh test CA.
func setCA(t *testing.T, srv *Server) *ca.CA {
	t.Helper()
	authority, err := ca.GenerateCA("TestOrg")
	if err != nil {
		t.Fatal(err)
	}
	srv.SetCA(authority)
	return authority
}

func issueCertPEM(t *testing.T, authority *ca.CA, agent string) []byte {
	t.Helper()
	b, err := authority.IssueAgentCert(agent)
	if err != nil {
		t.Fatal(err)
	}
	return b.CertPEM
}

func (e *grantEnv) delVector(t *testing.T) {
	t.Helper()
	expect(t, e.do("DELETE", "/v1/agents/vector", adminTok, ""), 200, "")
}

func (e *grantEnv) addVector(t *testing.T, tok string) {
	t.Helper()
	if err := e.srv.acl.AddAgent("vector", tok, nil); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentApproveDeleteCreate(t *testing.T) {
	for round := range 20 {
		e := newGrantEnv(t)
		e.set(func(s *config.AccessRequestsSettings) { s.RequireSealed = false })
		ids := []string{e.request(t, vectorTok, "infra/a"), e.request(t, vectorTok, "infra/b"), e.request(t, vectorTok, "infra/c")}
		var wg sync.WaitGroup
		for _, id := range ids {
			wg.Add(1)
			go func() {
				defer wg.Done()
				e.do("POST", "/v1/access-requests/"+id+"/approve", approverTok, "")
			}()
		}
		for i := range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				e.do("POST", "/v1/access-requests", vectorTok, fmt.Sprintf(`{"paths":["infra/n%d"],"reason":"r"}`, i))
				e.do("GET", "/v1/secrets/infra/a", vectorTok, "")
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.do("DELETE", "/v1/agents/vector", adminTok, "")
		}()
		wg.Wait()
		if _, err := e.srv.acl.GetAgent("vector"); err == nil {
			t.Fatalf("round %d: vector still in ACL", round)
		}
		if active := e.store.ListGrants("vector", false); len(active) != 0 {
			t.Fatalf("round %d: %d active grants survive agent delete", round, len(active))
		}
		if pend := e.store.ListRequests("vector", grant.StatusPending); len(pend) != 0 {
			t.Fatalf("round %d: %d pending requests survive agent delete", round, len(pend))
		}
	}
}

// --- whoami, docs ------------------------------------------------------------

func TestWhoami(t *testing.T) {
	e := newGrantEnv(t)
	gid := e.approve(t, e.request(t, vectorTok, "infra/other"), "")
	pid := e.request(t, vectorTok, "infra/b2/app-key")
	w := expect(t, e.do("GET", "/v1/whoami", vectorTok, ""), 200, "")
	if w["agent"] != "vector" || w["auth_method"] != "bearer" {
		t.Fatalf("whoami = %v", w)
	}
	if rules := w["acl"].([]any); len(rules) != 1 || rules[0].(map[string]any)["path"] != "dev/**" {
		t.Fatalf("acl = %v", w["acl"])
	}
	if gs := w["grants"].([]any); len(gs) != 1 || gs[0].(map[string]any)["id"] != gid {
		t.Fatalf("grants = %v", w["grants"])
	}
	if ps := w["pending_requests"].([]any); len(ps) != 1 || ps[0].(map[string]any)["id"] != pid {
		t.Fatalf("pending = %v", w["pending_requests"])
	}
	ar := w["access_requests"].(map[string]any)
	if ar["enabled"] != true || ar["sealed_required"] != true || ar["seal_key_registered"] != true {
		t.Fatalf("access_requests = %v", ar)
	}
}

func TestEveryDenialCodeIsDocumented(t *testing.T) {
	doc, err := os.ReadFile("../../docs/denial-codes.md")
	if err != nil {
		t.Fatal(err)
	}
	for code := range denialNextStep {
		if !bytes.Contains(doc, []byte("`"+code+"`")) {
			t.Errorf("code %s is missing from docs/denial-codes.md", code)
		}
	}
}

// R1 H2: a deleted approver's still-valid short-lived token or mTLS cert
// (both authenticate by name) must lose every approver power.
func TestDeletedApproverLosesApproverPowers(t *testing.T) {
	e := newGrantEnv(t)
	authority := setCA(t, e.srv)
	cert := issueCertPEM(t, authority, "approver")
	iss, _ := token.NewIssuer(time.Hour)
	e.srv.SetTokenIssuer(iss)
	tok, _, _ := iss.Mint("approver", nil, "")

	gid := e.approve(t, e.request(t, vectorTok, "infra/other"), "")
	pending := e.request(t, vectorTok, "infra/b2/app-key")
	expect(t, e.do("DELETE", "/v1/agents/approver", adminTok, ""), 200, "")

	viaCert := func(method, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		e.srv.ServeHTTP(w, makeMTLSRequest(method, path, nil, cert))
		return w
	}
	viaToken := func(method, path string) *httptest.ResponseRecorder { return e.do(method, path, tok, "") }
	for name, call := range map[string]func(string, string) *httptest.ResponseRecorder{"short-lived token": viaToken, "mtls cert": viaCert} {
		t.Run(name, func(t *testing.T) {
			expect(t, call("POST", "/v1/access-requests/"+pending+"/approve"), 403, CodeApproverRequired)
			expect(t, call("POST", "/v1/access-requests/"+pending+"/deny"), 403, CodeApproverRequired)
			expect(t, call("GET", "/v1/access-requests?agent=vector"), 403, CodeApproverRequired)
			expect(t, call("GET", "/v1/grants?agent=vector"), 403, CodeApproverRequired)
			expect(t, call("GET", "/v1/access-requests/"+pending), 404, CodeNotFound)
			if l := expect(t, call("GET", "/v1/access-requests"), 200, ""); len(l["requests"].([]any)) != 0 {
				t.Fatalf("deleted approver still sees other agents' requests: %v", l)
			}
			// Revoking another agent's grant looks like 404 (no existence oracle).
			expect(t, call("POST", "/v1/grants/"+gid+"/revoke"), 404, CodeNotFound)
		})
	}
	if g, _ := e.store.GetGrant(gid); g.State(e.clock.Now()) != grant.GrantActive {
		t.Fatal("deleted approver revoked another agent's grant")
	}
	if r, _ := e.store.GetRequest(pending); r.Status != grant.StatusPending {
		t.Fatalf("deleted approver decided a request: %s", r.Status)
	}
}

// R1 M1: every request_use the server emits follows the CURRENT rule
// (feature on, action grantable, path not in deny_paths).
func TestRequestUseFollowsCurrentSettingsEverywhere(t *testing.T) {
	e := newGrantEnv(t)
	ss, err := session.NewStore(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ss.Stop)
	e.srv.SetSessionStore(ss)
	// A narrow role: infra/** is out of scope for this session.
	e.srv.SetSessionRoles(map[string]config.RoleConfig{
		"narrow": {Namespaces: []string{"dev/**"}, Actions: []string{"read_value"}, BootstrapTrust: []string{"bearer"}},
	})
	sess := expect(t, e.do("POST", "/v1/session/mint", vectorTok, `{"role":"narrow"}`), 200, "")["session_token"].(string)

	// An approved grant that has expired: its request view says request_use
	// only while the path is still requestable.
	expired := e.request(t, vectorTok, "infra/b2/app-key")
	e.approve(t, expired, `{"ttl":"1m"}`)
	active := e.request(t, vectorTok, "infra/other")
	e.approve(t, active, "")
	e.clock.Advance(2 * time.Minute)

	type steps struct{ getScope, resolveScope, sessCreate, sessList, expiredView, activeView string }
	observe := func() steps {
		t.Helper()
		get := jsonBody(t, e.do("GET", "/v1/secrets/infra/b2/app-key", sess, ""))
		if get["code"] != CodeScopeExceeded {
			t.Fatalf("GET out of scope = %v", get)
		}
		rm := expect(t, e.do("POST", "/v1/resolve", sess, `{"refs":["phoenix://infra/b2/app-key"]}`), 200, "")
		rc := rm["error_codes"].(map[string]any)["phoenix://infra/b2/app-key"].(map[string]any)
		if rc["code"] != CodeScopeExceeded {
			t.Fatalf("resolve out of scope = %v", rc)
		}
		create := expect(t, e.do("POST", "/v1/access-requests", sess, `{"paths":["infra/b2/app-key"],"reason":"r"}`), 403, CodeSessionCannotRequest)
		list := expect(t, e.do("GET", "/v1/grants", sess, ""), 403, CodeSessionCannotRequest)
		ev := expect(t, e.do("GET", "/v1/access-requests/"+expired, vectorTok, ""), 200, "")
		av := expect(t, e.do("GET", "/v1/access-requests/"+active, vectorTok, ""), 200, "")
		return steps{get["next_step"].(string), rc["next_step"].(string), create["next_step"].(string),
			list["next_step"].(string), ev["next_step"].(string), av["next_step"].(string)}
	}

	if got, want := observe(), (steps{NextRequestUse, NextRequestUse, NextRequestUse, NextRequestUse, NextRequestUse, NextUseExec}); got != want {
		t.Fatalf("enabled: got %+v, want %+v", got, want)
	}
	e.set(func(s *config.AccessRequestsSettings) { s.DenyPaths = []string{"infra/b2/**"} })
	if got, want := observe(), (steps{NextRemintSession, NextRemintSession, NextAskUser, NextRequestUse, NextAskUser, NextUseExec}); got != want {
		t.Fatalf("deny-listed: got %+v, want %+v", got, want)
	}
	e.set(func(s *config.AccessRequestsSettings) { s.DenyPaths = nil; s.Enabled = false })
	if got, want := observe(), (steps{NextRemintSession, NextRemintSession, NextAskUser, NextAskUser, NextAskUser, NextAskUser}); got != want {
		t.Fatalf("disabled: got %+v, want %+v", got, want)
	}
}
