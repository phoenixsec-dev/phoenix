package dashboard

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/api"
	"github.com/phoenixsec/phoenix/internal/audit"
	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/crypto"
	"github.com/phoenixsec/phoenix/internal/grant"
	"github.com/phoenixsec/phoenix/internal/policy"
	"github.com/phoenixsec/phoenix/internal/store"

	"golang.org/x/crypto/bcrypt"
)

// switchFS is the real filesystem with a switch that makes every write fail
// (to provoke REVOKE_NOT_DURABLE).
type switchFS struct {
	grant.OSFS
	fail atomic.Bool
}

func (f *switchFS) WriteFileAtomic(name string, data []byte, perm os.FileMode) error {
	if f.fail.Load() {
		return errors.New("injected write failure")
	}
	return f.OSFS.WriteFileAtomic(name, data, perm)
}

// accessEnv is a dashboard wired to a real API server and grant store, with
// agent "vector" (dev/** only, seal key registered) and secrets
// infra/a and infra/b. access_requests has NO approvers: the dashboard
// approves on its own login.
type accessEnv struct {
	h      *Handler
	srv    *api.Server
	gs     *grant.Store
	fs     *switchFS
	acl    *acl.ACL
	cfg    config.AccessRequestsSettings
	cookie *http.Cookie
	csrf   string
}

func newAccessEnv(t *testing.T) *accessEnv {
	t.Helper()
	dir := t.TempDir()
	mk, err := crypto.GenerateAndSaveMasterKey(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.New(filepath.Join(dir, "store.json"), mk)
	if err != nil {
		t.Fatal(err)
	}
	backend := store.NewFileBackend(st)
	for _, p := range []string{"infra/a", "infra/b"} {
		if err := backend.Set(p, "value-"+p, "test", "", nil); err != nil {
			t.Fatal(err)
		}
	}
	a := acl.NewFromConfig(&acl.ACLConfig{Agents: map[string]acl.Agent{}})
	if err := a.AddAgent("vector", "vector-token", []acl.Permission{{Path: "dev/**", Actions: []acl.Action{acl.ActionList, acl.ActionReadValue}}}); err != nil {
		t.Fatal(err)
	}
	kp, _ := crypto.GenerateSealKeyPair()
	if err := a.SetAgentSealKey("vector", crypto.EncodeSealKey(&kp.PublicKey)); err != nil {
		t.Fatal(err)
	}
	al := audit.NewWriterLogger(io.Discard)
	srv := api.NewServer(backend, a, al, "")
	fs := &switchFS{}
	gs, err := grant.Open(grant.Options{
		Path:        filepath.Join(dir, "grants.json"),
		FS:          fs,
		AgentExists: func(n string) bool { _, err := a.GetAgent(n); return err == nil },
		Logf:        t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.SetGrantStore(gs)
	cfg := (&config.Config{AccessRequests: config.NewInstallAccessRequests()}).AccessRequestsSettings()
	srv.SetAccessRequests(cfg)

	hash, _ := bcrypt.GenerateFromPassword([]byte("testpass"), bcrypt.MinCost)
	h, err := New(config.DashboardConfig{Enabled: true, PasswordHash: string(hash)}, Deps{
		Backend: backend, ACL: a, StartTime: time.Now(), Audit: al, Grants: gs, Access: srv,
	})
	if err != nil {
		t.Fatal(err)
	}
	e := &accessEnv{h: h, srv: srv, gs: gs, fs: fs, acl: a, cfg: cfg}
	e.cookie = login(t, h)
	e.csrf = csrfFromCookie(t, h, e.cookie)
	return e
}

// request files a pending request from vector.
func (e *accessEnv) request(t *testing.T, reason string, ttl time.Duration, paths ...string) grant.Request {
	t.Helper()
	rq, _, err := e.gs.Create(grant.CreateInput{
		Agent: "vector", Paths: paths, Action: grant.ActionReadValue, Reason: reason, TTL: ttl,
		SourceIP: "10.0.0.5", AuthMethod: grant.AuthBearer, CredentialFP: "sha256:test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return rq
}

// get fetches a dashboard page as the logged-in operator.
func (e *accessEnv) get(t *testing.T, path string) string {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.AddCookie(e.cookie)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: %d", path, w.Code)
	}
	return w.Body.String()
}

// post submits a form; withCSRF=false leaves the token out. Returns the
// response (redirect location in Header "Location").
func (e *accessEnv) post(t *testing.T, path string, form url.Values, withCSRF bool) *httptest.ResponseRecorder {
	t.Helper()
	if form == nil {
		form = url.Values{}
	}
	if withCSRF {
		form.Set("_csrf", e.csrf)
	}
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.168.0.9:5555"
	req.AddCookie(e.cookie)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	return w
}

// redirectParam reads one query parameter from a 303 redirect.
func redirectParam(t *testing.T, w *httptest.ResponseRecorder, key string) string {
	t.Helper()
	if w.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d: %s", w.Code, w.Body.String())
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get(key)
}

func TestAccessCardShowsFactsAndApproveNarrows(t *testing.T) {
	e := newAccessEnv(t)
	rq := e.request(t, "backup job fails auth", 30*time.Minute, "infra/a", "infra/b", "dev/db", "infra/missing")

	page := e.get(t, "/dashboard/approvals")
	for _, want := range []string{
		`id="` + rq.ID + `"`,
		"Secret access requests",
		"Agent says (not verified)",
		"backup job fails auth",
		"Revoking later does not recall a value already used.",
		"10.0.0.5 (bearer)",
		`value="infra/a" checked`,
		"does not exist",         // infra/missing
		"hidden from this agent", // infra/* is outside vector's list rule
		"already allowed",        // dev/db
		"sealed only",            // require_sealed default
	} {
		if !strings.Contains(page, want) {
			t.Errorf("approval card missing %q", want)
		}
	}

	w := e.post(t, "/dashboard/access-requests/"+rq.ID+"/approve",
		url.Values{"path": {"infra/a"}, "ttl": {"15m"}}, true)
	if code := redirectParam(t, w, "error"); code != "" {
		t.Fatalf("approve failed: %s", code)
	}
	got, _ := e.gs.GetRequest(rq.ID)
	if got.Status != grant.StatusApproved || got.DecidedBy != "dashboard@192.168.0.9" {
		t.Fatalf("request = %s by %q", got.Status, got.DecidedBy)
	}
	g, _ := e.gs.GetGrant(got.GrantID)
	if !slices.Equal(g.Paths, []string{"infra/a"}) || g.ExpiresAt.Sub(g.CreatedAt) != 15*time.Minute || !g.SealedOnly {
		t.Fatalf("grant = %v ttl %s sealed %v", g.Paths, g.ExpiresAt.Sub(g.CreatedAt), g.SealedOnly)
	}
}

func TestAccessApproveOnlyLegalTTLs(t *testing.T) {
	e := newAccessEnv(t)
	rq := e.request(t, "why", 30*time.Minute, "infra/a")

	page := e.get(t, "/dashboard/approvals")
	var opts []string
	for _, part := range strings.Split(page, `<option value="`)[1:] {
		opts = append(opts, part[:strings.Index(part, `"`)])
	}
	if !slices.Equal(opts, []string{"5m", "15m", "30m"}) {
		t.Fatalf("TTL options = %v, want [5m 15m 30m]", opts)
	}
	for _, ttl := range []string{"1h", "10m", "30s", "", "forever"} {
		w := e.post(t, "/dashboard/access-requests/"+rq.ID+"/approve", url.Values{"path": {"infra/a"}, "ttl": {ttl}}, true)
		if code := redirectParam(t, w, "error"); code != "INVALID_TTL" {
			t.Errorf("ttl %q: error = %q, want INVALID_TTL", ttl, code)
		}
	}
	if got, _ := e.gs.GetRequest(rq.ID); got.Status != grant.StatusPending {
		t.Fatalf("request = %s after illegal TTLs", got.Status)
	}
}

func TestTTLChoices(t *testing.T) {
	m := time.Minute
	cases := []struct {
		req, max time.Duration
		want     []time.Duration
	}{
		{30 * m, 8 * time.Hour, []time.Duration{5 * m, 15 * m, 30 * m}},
		{2 * m, 8 * time.Hour, []time.Duration{2 * m}},
		{time.Hour, 8 * time.Hour, []time.Duration{5 * m, 15 * m, time.Hour}},
		{8 * time.Hour, 4 * time.Hour, []time.Duration{5 * m, 15 * m, time.Hour, 4 * time.Hour}},
	}
	for _, c := range cases {
		if got := ttlChoices(c.req, c.max); !slices.Equal(got, c.want) {
			t.Errorf("ttlChoices(%s, %s) = %v, want %v", c.req, c.max, got, c.want)
		}
	}
}

func TestAccessApproveRechecksCurrentConfig(t *testing.T) {
	e := newAccessEnv(t)
	rq := e.request(t, "why", 30*time.Minute, "infra/a")
	cfg := e.cfg
	cfg.DenyPaths = []string{"infra/**"}
	e.srv.SetAccessRequests(cfg)

	w := e.post(t, "/dashboard/access-requests/"+rq.ID+"/approve", url.Values{"path": {"infra/a"}, "ttl": {"15m"}}, true)
	if code := redirectParam(t, w, "error"); code != "NOT_REQUESTABLE" {
		t.Fatalf("error = %q, want NOT_REQUESTABLE", code)
	}
	// Widening is refused by the store even with a legal TTL.
	e.srv.SetAccessRequests(e.cfg)
	w = e.post(t, "/dashboard/access-requests/"+rq.ID+"/approve", url.Values{"path": {"infra/a", "infra/b"}, "ttl": {"15m"}}, true)
	if code := redirectParam(t, w, "error"); code != "WIDENING_NOT_ALLOWED" {
		t.Fatalf("error = %q, want WIDENING_NOT_ALLOWED", code)
	}
	w = e.post(t, "/dashboard/access-requests/"+rq.ID+"/approve", url.Values{"ttl": {"15m"}}, true)
	if code := redirectParam(t, w, "error"); code != "EMPTY_GRANT" {
		t.Fatalf("error = %q, want EMPTY_GRANT", code)
	}
	if got, _ := e.gs.GetRequest(rq.ID); got.Status != grant.StatusPending {
		t.Fatalf("request = %s", got.Status)
	}
}

func TestAccessDeny(t *testing.T) {
	e := newAccessEnv(t)
	rq := e.request(t, "why", 30*time.Minute, "infra/a")
	w := e.post(t, "/dashboard/access-requests/"+rq.ID+"/deny", url.Values{"note": {"not today"}}, true)
	if code := redirectParam(t, w, "error"); code != "" {
		t.Fatalf("deny failed: %s", code)
	}
	got, _ := e.gs.GetRequest(rq.ID)
	if got.Status != grant.StatusDenied || got.Note != "not today" || got.DecidedBy != "dashboard@192.168.0.9" {
		t.Fatalf("request = %+v", got)
	}
}

func TestAccessCSRFRejected(t *testing.T) {
	e := newAccessEnv(t)
	rq := e.request(t, "why", 30*time.Minute, "infra/a")
	for _, path := range []string{"/approve", "/deny"} {
		w := e.post(t, "/dashboard/access-requests/"+rq.ID+path, url.Values{"path": {"infra/a"}, "ttl": {"15m"}}, false)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s without CSRF: %d, want 403", path, w.Code)
		}
	}
	if got, _ := e.gs.GetRequest(rq.ID); got.Status != grant.StatusPending {
		t.Fatalf("request = %s after CSRF-less posts", got.Status)
	}
}

func TestAccessReasonEscaped(t *testing.T) {
	e := newAccessEnv(t)
	e.request(t, "<script>alert(1)</script> visit https://evil.example \u202Etxt.exe\u200B", 30*time.Minute, "infra/a")
	page := e.get(t, "/dashboard/approvals")
	if strings.ContainsAny(page, "\u202E\u200B") {
		t.Fatal("bidi / zero-width characters reached the page")
	}
	if strings.Contains(page, "<script>alert") {
		t.Fatal("reason rendered as raw HTML")
	}
	if !strings.Contains(page, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatal("escaped reason missing")
	}
	if strings.Contains(page, `href="https://evil`) {
		t.Fatal("reason rendered a link")
	}
}

func TestCleanDisplayText(t *testing.T) {
	in := "ok\u202Eevil\u200B\u2066x\x1b[31m" + strings.Repeat("y", 400)
	out := cleanDisplayText(in, maxReasonDisplay)
	for _, bad := range []string{"\u202E", "\u200B", "\u2066", "\x1b"} {
		if strings.Contains(out, bad) {
			t.Errorf("cleaned text still has %q", bad)
		}
	}
	if n := len([]rune(out)); n != maxReasonDisplay+3 { // + "..."
		t.Errorf("cleaned length = %d runes", n)
	}
}

func TestGrantRevokeAndRecent(t *testing.T) {
	e := newAccessEnv(t)
	rq := e.request(t, "why", 30*time.Minute, "infra/a")
	g, err := e.srv.ApproveAccessRequestAs(rq.ID, "dashboard@test", "127.0.0.1", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page := e.get(t, "/dashboard/grants"); !strings.Contains(page, "/dashboard/grants/"+g.ID+"/revoke") {
		t.Fatal("active grant missing a Revoke button")
	}
	if w := e.post(t, "/dashboard/grants/"+g.ID+"/revoke", nil, false); w.Code != http.StatusForbidden {
		t.Fatalf("revoke without CSRF: %d", w.Code)
	}
	w := e.post(t, "/dashboard/grants/"+g.ID+"/revoke", nil, true)
	if code := redirectParam(t, w, "error"); code != "" {
		t.Fatalf("revoke failed: %s", code)
	}
	got, _ := e.gs.GetGrant(g.ID)
	if got.State(time.Now()) != grant.GrantRevoked || got.RevokedBy != "dashboard@192.168.0.9" {
		t.Fatalf("grant state %s by %q", got.State(time.Now()), got.RevokedBy)
	}
	if page := e.get(t, "/dashboard/grants?view=recent"); !strings.Contains(page, "status-revoked") {
		t.Fatal("revoked grant not in the recent view")
	}
}

func TestGrantRevokeNotDurableShownInRed(t *testing.T) {
	e := newAccessEnv(t)
	rq := e.request(t, "why", 30*time.Minute, "infra/a")
	g, err := e.srv.ApproveAccessRequestAs(rq.ID, "dashboard@test", "127.0.0.1", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	e.fs.fail.Store(true)
	w := e.post(t, "/dashboard/grants/"+g.ID+"/revoke", nil, true)
	if code := redirectParam(t, w, "error"); code != "REVOKE_NOT_DURABLE" {
		t.Fatalf("error = %q, want REVOKE_NOT_DURABLE", code)
	}
	page := e.get(t, w.Header().Get("Location"))
	if !strings.Contains(page, `flash-error flash-sticky">REVOKE_NOT_DURABLE`) {
		t.Fatal("REVOKE_NOT_DURABLE warning not shown in red")
	}
	// Still denied in memory even though the save failed.
	if got, _ := e.gs.GetGrant(g.ID); got.State(time.Now()) != grant.GrantRevoked {
		t.Fatal("grant not revoked in memory")
	}
	// Overview shows the degraded state.
	if page := e.get(t, "/dashboard/"); !strings.Contains(page, "Access requests degraded") {
		t.Fatal("overview does not show degraded state")
	}
}

func TestUnknownErrorCodeNotEchoed(t *testing.T) {
	e := newAccessEnv(t)
	page := e.get(t, "/dashboard/approvals?error="+url.QueryEscape("Agent verified, safe to approve"))
	if strings.Contains(page, "safe to approve") {
		t.Fatal("arbitrary error text from the URL was rendered")
	}
}

func TestOverviewPendingAccessBadge(t *testing.T) {
	e := newAccessEnv(t)
	e.request(t, "why", 30*time.Minute, "infra/a")
	page := e.get(t, "/dashboard/")
	if !strings.Contains(page, "Access Requests") || !strings.Contains(page, `<span class="badge">1</span>`) {
		t.Fatal("overview missing access request count / nav badge")
	}
}

// R1 U2: a path pinned to one client certificate shows met / not met from
// the fingerprint the mTLS request was made with.
func TestAttestFactsCertPin(t *testing.T) {
	p, err := policy.Load([]byte(`{"attestation": {"infra/*": {"cert_fingerprint": "sha256:AA11"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{deps: Deps{Policy: p}}
	status := func(rq grant.Request) string {
		for _, f := range h.attestFacts(rq, "infra/a", true) {
			if f.Requirement == "specific client certificate" {
				return f.Status
			}
		}
		t.Fatal("no certificate fact")
		return ""
	}
	if got := status(grant.Request{AuthMethod: grant.AuthMTLS, CredentialFP: "sha256:aa11"}); got != "met" {
		t.Errorf("matching cert: %q", got)
	}
	if got := status(grant.Request{AuthMethod: grant.AuthMTLS, CredentialFP: "sha256:bb22"}); got != "not met" {
		t.Errorf("other cert: %q", got)
	}
	if got := status(grant.Request{AuthMethod: grant.AuthBearer, CredentialFP: "sha256:aa11"}); got != "not met" {
		t.Errorf("bearer: %q", got)
	}
}

// R2 U2: a path that needs a fresh short-lived token can never be used with
// a bearer token or cert, so the card says "not met" for those.
func TestAttestFactsFreshCredential(t *testing.T) {
	p, err := policy.Load([]byte(`{"attestation": {"infra/*": {"require_fresh_attestation": true}}}`))
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{deps: Deps{Policy: p}}
	status := func(method string) string {
		for _, f := range h.attestFacts(grant.Request{AuthMethod: method}, "infra/a", true) {
			if f.Requirement == "short-lived credential" {
				return f.Status
			}
		}
		t.Fatal("no freshness fact")
		return ""
	}
	if got := status(grant.AuthBearer); got != "not met" {
		t.Errorf("bearer: %q", got)
	}
	if got := status(grant.AuthMTLS); got != "not met" {
		t.Errorf("mtls: %q", got)
	}
	if got := status(grant.AuthToken); got != "checked at each use" {
		t.Errorf("token: %q", got)
	}
}
