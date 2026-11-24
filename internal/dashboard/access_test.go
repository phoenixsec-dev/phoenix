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
		Always:      api.NewAlwaysRules(a),
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
		SourceIP: "10.0.0.5", AuthMethod: grant.AuthBearer, CredentialFP: grant.BearerFingerprint(crypto.HashToken("vector-token")),
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
	req.RemoteAddr = "192.0.2.9:5555"
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

// P5 review S1: when a failed approval may still be on disk, the dashboard
// says so instead of "nothing changed".
func TestApprovalMaybeSavedShownHonestly(t *testing.T) {
	code := errCode(&grant.Error{Code: grant.CodeStoreWriteFailed, MaybeSaved: true})
	msg := accessErrorMessage(code)
	if strings.Contains(msg, "nothing changed") || !strings.Contains(msg, "revoke") {
		t.Fatalf("code %q -> %q", code, msg)
	}
	if got := accessErrorMessage(errCode(&grant.Error{Code: grant.CodeStoreWriteFailed})); !strings.Contains(got, "nothing changed") {
		t.Fatalf("plain write failure -> %q", got)
	}
}
