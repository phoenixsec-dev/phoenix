package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/audit"
	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/crypto"
	"github.com/phoenixsec/phoenix/internal/grant"
	"github.com/phoenixsec/phoenix/internal/session"
	"github.com/phoenixsec/phoenix/internal/store"
)

// credEnv is a server whose ACL, sessions, grants and audit log live in dir,
// so start can be called again for a restart. The agent under test is
// "worker", first with token "old-token".
type credEnv struct {
	t        *testing.T
	dir      string
	srv      *Server
	sessions *session.Store
}

const workerACL = `[{"path":"test/*","actions":["list","read_value","write","delete"]}]`

func newCredEnv(t *testing.T) *credEnv {
	t.Helper()
	e := &credEnv{t: t, dir: t.TempDir()}
	if err := os.Mkdir(filepath.Dir(e.sessionsPath()), 0700); err != nil {
		t.Fatal(err)
	}
	a, err := acl.New(filepath.Join(e.dir, "acl.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddAgent("admin", "admin-token", []acl.Permission{{Path: "*", Actions: []acl.Action{acl.ActionAdmin}}}); err != nil {
		t.Fatal(err)
	}
	e.start()
	e.create("old-token", false)
	seedSecret(t, e.srv, "admin-token", "test/a", "synthetic-value")
	return e
}

// start (re)starts the server from the files in dir, wired like phoenix-server.
func (e *credEnv) start() {
	t := e.t
	t.Helper()
	master := bytes.Repeat([]byte{1}, 32)
	st, err := store.New(filepath.Join(e.dir, "store.json"), master)
	if err != nil {
		t.Fatal(err)
	}
	a, err := acl.New(filepath.Join(e.dir, "acl.json"))
	if err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(e.dir, "audit.log")
	al, err := audit.NewLogger(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	e.srv = NewServer(store.NewFileBackend(st), a, al, auditPath)
	gs, err := grant.Open(grant.Options{Path: filepath.Join(e.dir, "grants.json"), Audit: NewGrantAuditSink(al), Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.SetGrantStore(gs)

	cfg := &config.Config{Session: config.SessionConfig{Roles: map[string]config.RoleConfig{
		"dev":   {Namespaces: []string{"test/*"}, Actions: []string{"list", "read_value", "write", "delete"}, BootstrapTrust: []string{"bearer"}},
		"local": {Namespaces: []string{"test/*"}, BootstrapTrust: []string{"local"}},
	}}}
	key, err := session.DeriveSigningKey(master)
	if err != nil {
		t.Fatal(err)
	}
	if e.sessions != nil {
		e.sessions.Stop()
	}
	e.sessions, err = session.OpenStore(session.Options{TTL: time.Hour, SigningKey: key, Path: e.sessionsPath(), RoleFingerprints: cfg.RoleFingerprints()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.sessions.Stop)
	if err := e.srv.SetSessionStore(e.sessions); err != nil {
		t.Fatal(err)
	}
	e.srv.SetSessionRoles(cfg.Session.Roles)
}

func (e *credEnv) sessionsPath() string {
	return filepath.Join(e.dir, "sessions", "role-sessions.json")
}

func (e *credEnv) savedSessions() string {
	e.t.Helper()
	b, err := os.ReadFile(e.sessionsPath())
	if err != nil {
		e.t.Fatal(err)
	}
	return string(b)
}

// do sends one request and returns status and body.
func (e *credEnv) do(method, path, tok, body string) (int, string) {
	return e.doReader(method, path, tok, strings.NewReader(body))
}

func (e *credEnv) doReader(method, path, tok string, body io.Reader) (int, string) {
	req := httptest.NewRequest(method, path, body)
	req.RemoteAddr = "127.0.0.1:1234"
	if tok == "admin-token" {
		req.RemoteAddr = "127.0.0.2:1234" // not rate limited by the worker's failures
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// create makes (or with force replaces) the worker agent with token tok.
func (e *credEnv) create(tok string, force bool) {
	e.t.Helper()
	path := "/v1/agents"
	if force {
		path += "?force=true"
	}
	if code, body := e.do("POST", path, "admin-token", `{"name":"worker","token":"`+tok+`","permissions":`+workerACL+`}`); code != 200 {
		e.t.Fatalf("create worker: %d %s", code, body)
	}
}

func (e *credEnv) remove() {
	e.t.Helper()
	if code, body := e.do("DELETE", "/v1/agents/worker", "admin-token", ""); code != 200 {
		e.t.Fatalf("delete worker: %d %s", code, body)
	}
}

func (e *credEnv) mint(tok string) string {
	e.t.Helper()
	return mintTestSession(e.t, e.srv, tok, "dev")
}

// wantDead fails unless reading, listing and renewing with sess all get 401
// SESSION_INVALID, the code clients recover from.
func (e *credEnv) wantDead(when, sess string) {
	e.t.Helper()
	for _, c := range [][2]string{{"GET", "/v1/secrets/test/a"}, {"GET", "/v1/whoami"}, {"POST", "/v1/session/renew"}} {
		code, body := e.do(c[0], c[1], sess, "{}")
		if code != 401 || !strings.Contains(body, `"SESSION_INVALID"`) || !strings.Contains(body, `"remint_session"`) {
			e.t.Errorf("%s: %s %s = %d %s, want 401 SESSION_INVALID", when, c[0], c[1], code, body)
		}
	}
}

func (e *credEnv) wantAlive(when, sess string) {
	e.t.Helper()
	if code, body := e.do("GET", "/v1/secrets/test/a", sess, ""); code != 200 {
		e.t.Errorf("%s: session read = %d %s, want 200", when, code, body)
	}
}

// wantEnded fails unless the audit log has a session.ended line by actor for a
// worker session with this cause.
func (e *credEnv) wantEnded(actor, cause string) {
	e.t.Helper()
	res, err := audit.Search(filepath.Join(e.dir, "audit.log"), audit.QueryOptions{Limit: 1000})
	if err != nil {
		e.t.Fatal(err)
	}
	for _, en := range res.Entries {
		if en.Action == "session.ended" && en.Agent == actor && en.Metadata["cause"] == cause &&
			en.Metadata["session.agent"] == "worker" && strings.HasPrefix(en.SessionID, "ses_") {
			return
		}
	}
	e.t.Errorf("no session.ended audit line by %q with cause %q", actor, cause)
}

// The sessions file holds the fingerprint and nothing that can log in.
func TestSessionRecordHoldsFingerprintNotToken(t *testing.T) {
	e := newCredEnv(t)
	sess := e.mint("old-token")
	saved := e.savedSessions()
	a, err := e.srv.acl.GetAgent("worker")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(saved, `"credential_fp": "`+sessionCredentialFP(a)+`"`) {
		t.Errorf("sessions file has no credential fingerprint: %s", saved)
	}
	for _, secret := range []string{"old-token", crypto.HashToken("old-token"), sess} {
		if strings.Contains(saved, secret) {
			t.Errorf("sessions file holds a token or its stored hash")
		}
	}
}

// Deleting an agent ends its sessions, for good: not after a restart, and not
// when the agent is created again, even with the very same token.
func TestDeletingAgentEndsItsSessions(t *testing.T) {
	for name, again := range map[string]string{"new token": "new-token", "same token": "old-token"} {
		t.Run(name, func(t *testing.T) {
			e := newCredEnv(t)
			sess := e.mint("old-token")
			e.wantAlive("before", sess)

			e.remove()
			if strings.Contains(e.savedSessions(), "worker") {
				t.Error("ended session still in the sessions file")
			}
			e.wantDead("after delete", sess)
			e.wantEnded("admin", "agent_deleted")

			e.create(again, false)
			e.wantDead("after create again", sess)
			e.start()
			e.wantDead("after restart", sess)
			e.wantAlive("a new session", e.mint(again))
		})
	}
}

// agent create --force with a new token ends the old token's sessions.
func TestReplacingTokenEndsItsSessions(t *testing.T) {
	e := newCredEnv(t)
	sess := e.mint("old-token")
	adminSess := e.mint("admin-token")

	e.create("new-token", true)
	if strings.Contains(e.savedSessions(), "worker") {
		t.Error("ended session still in the sessions file")
	}
	e.wantDead("after --force", sess)
	e.wantEnded("admin", "token_replaced")
	e.wantAlive("another agent's session", adminSess)

	fresh := e.mint("new-token")
	e.start()
	e.wantDead("after restart", sess)
	e.wantAlive("the new token's session after restart", fresh)

	// Back to the old token: its old session stays ended.
	e.create("old-token", true)
	e.wantDead("after --force back", sess)
	e.wantDead("after --force back", fresh)
}

// --force with the same token only changes permissions; sessions carry on.
func TestForceWithSameTokenKeepsSessions(t *testing.T) {
	e := newCredEnv(t)
	sess := e.mint("old-token")
	e.create("old-token", true)
	e.wantAlive("after --force with the same token", sess)
}

// Every endpoint a session reaches refuses one whose agent is gone or has
// another token, even if the change did not come through a route that ends
// sessions. Each endpoint gets a fresh session so none is spared the check.
func TestEveryEndpointChecksSessionCredential(t *testing.T) {
	endpoints := [][3]string{
		{"GET", "/v1/secrets/test/a", ""},
		{"GET", "/v1/secrets/test/", ""},
		{"PUT", "/v1/secrets/test/b", `{"value":"x"}`},
		{"DELETE", "/v1/secrets/test/a", ""},
		{"GET", "/v1/metadata/test/a", ""},
		{"POST", "/v1/resolve", `{"refs":["phoenix://test/a"]}`},
		{"GET", "/v1/policy/check?path=test/a&check=allow_unseal", ""},
		{"GET", "/v1/whoami", ""},
		{"POST", "/v1/session/mint", `{"role":"local"}`},
		{"POST", "/v1/session/renew", "{}"},
		{"GET", "/v1/sessions", ""},
		{"GET", "/v1/sessions/ses_x", ""},
		{"POST", "/v1/sessions/ses_x/revoke", "{}"},
		{"GET", "/v1/agents", ""},
		{"GET", "/v1/status", ""},
		{"GET", "/v1/audit", ""},
		{"POST", "/v1/access-requests", `{}`},
		{"GET", "/v1/access-requests", ""},
		{"GET", "/v1/grants", ""},
		{"POST", "/v1/ssh/sign", `{}`},
		{"GET", "/v1/ssh/machines", ""},
	}
	changes := map[string]func(e *credEnv) error{
		"deleted":  func(e *credEnv) error { return e.srv.acl.RemoveAgent("worker") },
		"replaced": func(e *credEnv) error { return e.srv.acl.UpdateAgent("worker", "new-token", nil) },
	}
	for name, change := range changes {
		for _, ep := range endpoints {
			t.Run(name+" "+ep[0]+" "+ep[1], func(t *testing.T) {
				e := newCredEnv(t)
				e.srv.SetSSHCA(nil, nil)
				sess := e.mint("old-token")
				if err := change(e); err != nil {
					t.Fatal(err)
				}
				code, body := e.do(ep[0], ep[1], sess, ep[2])
				if code != 401 || !strings.Contains(body, `"SESSION_INVALID"`) {
					t.Fatalf("%d %s, want 401 SESSION_INVALID", code, body)
				}
				if strings.Contains(e.savedSessions(), "worker") {
					t.Error("session not ended on use")
				}
				e.wantEnded("system", "credential_not_current")
			})
		}
	}
}

// A token changed in the ACL file while the server was down ends the old
// token's sessions at start.
func TestTokenChangedWhileDownEndsSessionsAtStart(t *testing.T) {
	e := newCredEnv(t)
	sess := e.mint("old-token")
	a, err := acl.New(filepath.Join(e.dir, "acl.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.UpdateAgent("worker", "new-token", []acl.Permission{{Path: "test/*", Actions: []acl.Action{acl.ActionReadValue}}}); err != nil {
		t.Fatal(err)
	}
	e.start()
	if strings.Contains(e.savedSessions(), "worker") {
		t.Error("stale session still saved after start")
	}
	e.wantEnded("system", "credential_not_current")
	e.wantDead("after restart", sess)
}

// Sessions saved by v0.23.0 have no fingerprint: they end at the first start,
// with a log line. One revoked before the upgrade keeps saying so.
func TestSessionsWithoutFingerprintEndAtStart(t *testing.T) {
	for name, value := range map[string]any{"missing": nil, "empty": ""} {
		t.Run(name, func(t *testing.T) {
			e := newCredEnv(t)
			sess, revoked := e.mint("old-token"), e.mint("old-token")
			_, id, _ := e.sessions.ParseClaimsInsecure(revoked)
			if err := e.sessions.Revoke(id); err != nil {
				t.Fatal(err)
			}
			var f map[string]any
			if err := json.Unmarshal([]byte(e.savedSessions()), &f); err != nil {
				t.Fatal(err)
			}
			for _, s := range f["sessions"].([]any) {
				m := s.(map[string]any)
				if delete(m, "credential_fp"); value != nil {
					m["credential_fp"] = value
				}
			}
			b, _ := json.Marshal(f)
			if err := os.WriteFile(e.sessionsPath(), b, 0600); err != nil {
				t.Fatal(err)
			}

			var logs bytes.Buffer
			log.SetOutput(&logs)
			defer log.SetOutput(os.Stderr)
			e.start()
			if !strings.Contains(logs.String(), "ended 1 saved by an older version") {
				t.Errorf("no upgrade log line in: %s", logs.String())
			}
			if n := strings.Count(e.savedSessions(), `"session_id"`); n != 1 {
				t.Errorf("%d sessions saved after start, want only the revoked one", n)
			}
			e.wantDead("after upgrade", sess)
			if code, body := e.do("GET", "/v1/whoami", revoked, ""); code != 401 || !strings.Contains(body, "SESSION_REVOKED") {
				t.Errorf("revoked session after upgrade: %d %s, want SESSION_REVOKED", code, body)
			}
		})
	}
}

// A session cannot mint another one, even for a role that trusts "local": the
// new one would shed its scope and seal key and could outlive it.
func TestSessionCannotMintSession(t *testing.T) {
	e := newCredEnv(t)
	sess := e.mint("old-token")
	for _, role := range []string{"local", "dev"} {
		code, body := e.do("POST", "/v1/session/mint", sess, `{"role":"`+role+`"}`)
		if code != 403 || !strings.Contains(body, "BOOTSTRAP_FAILED") {
			t.Errorf("mint %s with a session: %d %s, want 403 BOOTSTRAP_FAILED", role, code, body)
		}
	}
	if code, body := e.do("POST", "/v1/session/mint", "old-token", `{"role":"local"}`); code != 200 {
		t.Errorf("mint local with the bearer token: %d %s", code, body)
	}
}

// hookBody runs hook on the first read. Handlers log the caller in before they
// read the body, so the hook runs in the middle of the request.
type hookBody struct {
	io.Reader
	hook func()
	once sync.Once
}

func (h *hookBody) Read(p []byte) (int, error) {
	h.once.Do(h.hook)
	return h.Reader.Read(p)
}

// A mint that logged in before the agent was deleted or its token replaced
// must not produce a session afterwards.
func TestMintDuringCredentialChange(t *testing.T) {
	changes := map[string]func(e *credEnv){
		"delete":            func(e *credEnv) { e.remove() },
		"replace":           func(e *credEnv) { e.create("new-token", true) },
		"delete and create": func(e *credEnv) { e.remove(); e.create("new-token", false) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			e := newCredEnv(t)
			// The change is an HTTP call of its own and the mint holds no
			// lock while reading its body, so this cannot deadlock.
			code, body := e.doReader("POST", "/v1/session/mint", "old-token",
				&hookBody{Reader: strings.NewReader(`{"role":"dev"}`), hook: func() { change(e) }})
			if code != 401 || !strings.Contains(body, `"unauthorized"`) {
				t.Errorf("mint = %d %s, want 401", code, body)
			}
			if live := e.sessions.List(); len(live) != 0 {
				t.Errorf("%d live sessions left for the old credential", len(live))
			}
		})
	}
}

// A session with a bound seal key that is ended mid-request must not be served
// as if it had no seal key.
func TestSealBoundSessionEndedDuringRequest(t *testing.T) {
	e := newCredEnv(t)
	kp, err := crypto.GenerateSealKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	code, body := e.do("POST", "/v1/session/mint", "old-token", `{"role":"dev","seal_public_key":"`+crypto.EncodeSealKey(&kp.PublicKey)+`"}`)
	var m struct {
		Tok string `json:"session_token"`
	}
	if json.Unmarshal([]byte(body), &m); code != 200 {
		t.Fatalf("mint: %d %s", code, body)
	}
	code, body = e.doReader("POST", "/v1/resolve", m.Tok, &hookBody{
		Reader: strings.NewReader(`{"refs":["phoenix://test/a"]}`),
		hook:   func() { e.create("new-token", true) },
	})
	if code != 401 || strings.Contains(body, "synthetic-value") {
		t.Errorf("resolve = %d %s, want 401 and no value", code, body)
	}
}

// Under load, replacing the token leaves no live session for the old one:
// every mint, use and renewal either came first and was ended, or is refused.
func TestCredentialChangeRaces(t *testing.T) {
	e := newCredEnv(t)
	var mu sync.Mutex
	var old []string
	for i := 0; i < 20; i++ {
		e.srv.authRL = newRateLimiter() // refused old tokens must not block the admin
		oldTok, newTok := fmt.Sprintf("token-%d", i), fmt.Sprintf("token-%d", i+1)
		e.create(oldTok, true)
		first := e.mint(oldTok)
		old = append(old, first)

		var wg sync.WaitGroup
		for w := 0; w < 4; w++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				for j := 0; j < 5; j++ {
					if code, body := e.do("POST", "/v1/session/mint", oldTok, `{"role":"dev"}`); code == 200 {
						var m struct {
							Tok string `json:"session_token"`
						}
						json.Unmarshal([]byte(body), &m)
						mu.Lock()
						old = append(old, m.Tok)
						mu.Unlock()
					}
				}
			}()
			go func() {
				defer wg.Done()
				tok := first
				for j := 0; j < 5; j++ {
					e.do("GET", "/v1/whoami", tok, "")
					if code, body := e.do("POST", "/v1/session/renew", tok, "{}"); code == 200 {
						var m struct {
							Tok string `json:"session_token"`
						}
						json.Unmarshal([]byte(body), &m)
						tok = m.Tok
						mu.Lock()
						old = append(old, tok)
						mu.Unlock()
					} else if code != 401 || !strings.Contains(body, "SESSION_INVALID") {
						t.Errorf("renew during replace: %d %s, want 401 SESSION_INVALID", code, body)
					}
				}
			}()
		}
		if i%2 == 0 {
			e.create(newTok, true)
		} else {
			e.remove()
			e.create(newTok, false)
		}
		wg.Wait()
		// No live record may be left once everything has settled: no mint
		// with the new token has happened.
		if live := e.sessions.List(); len(live) != 0 {
			t.Fatalf("round %d: %d live sessions left for a replaced token", i, len(live))
		}
	}
	for _, tok := range old {
		if code, body := e.do("GET", "/v1/whoami", tok, ""); code != 401 || !strings.Contains(body, "SESSION_INVALID") {
			t.Fatalf("old session: %d %s, want 401 SESSION_INVALID", code, body)
		}
	}
}

// breakSessionsFile makes every save of the sessions file fail until the
// returned func is called, which also puts the file back as it was.
func (e *credEnv) breakSessionsFile() (repair func()) {
	e.t.Helper()
	dir := filepath.Dir(e.sessionsPath())
	if err := errors.Join(os.Rename(dir, dir+".away"), os.WriteFile(dir, nil, 0600)); err != nil {
		e.t.Fatal(err)
	}
	return func() {
		e.t.Helper()
		if err := errors.Join(os.Remove(dir), os.Rename(dir+".away", dir)); err != nil {
			e.t.Fatal(err)
		}
	}
}

// A session made with a token that was taken away stays dead when the very
// same token is given out again, even if its old record is still in the
// sessions file at the next start.
func TestReissuedTokenDoesNotReviveSessions(t *testing.T) {
	cases := map[string]struct {
		change        func(e *credEnv, sessionID string)
		saveFails     bool
		sessionsOffTo bool // the change happens while sessions are disabled
	}{
		"delete, save fails":               {saveFails: true, change: func(e *credEnv, _ string) { e.remove(); e.create("old-token", false) }},
		"delete, save fails, force create": {saveFails: true, change: func(e *credEnv, _ string) { e.remove(); e.create("old-token", true) }},
		"replace and back, save fails":     {saveFails: true, change: func(e *credEnv, _ string) { e.create("new-token", true); e.create("old-token", true) }},
		"revoke not saved, then delete": {saveFails: true, change: func(e *credEnv, id string) {
			if err := e.sessions.Revoke(id); err == nil {
				e.t.Error("revoke should report the failed save")
			}
			e.remove()
			e.create("old-token", false)
		}},
		"delete while sessions are off":           {sessionsOffTo: true, change: func(e *credEnv, _ string) { e.remove(); e.create("old-token", false) }},
		"replace and back while sessions are off": {sessionsOffTo: true, change: func(e *credEnv, _ string) { e.create("new-token", true); e.create("old-token", true) }},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newCredEnv(t)
			sess := e.mint("old-token")
			_, id, _ := e.sessions.ParseClaimsInsecure(sess)
			saved := e.savedSessions()
			repair := func() {}
			if c.saveFails {
				repair = e.breakSessionsFile()
			}
			if c.sessionsOffTo {
				e.srv.sessions = nil
			}
			c.change(e, id)
			repair()
			if e.savedSessions() != saved {
				t.Fatal("test setup: the old record should still be in the sessions file")
			}
			e.start()
			e.wantDead("after restart", sess)
			e.wantEnded("system", "credential_not_current")
			e.wantAlive("a new session", e.mint("old-token"))
		})
	}
}

// pausedBackend runs hook in the middle of a request, after login.
type pausedBackend struct {
	store.SecretBackend
	hook func()
}

func (p *pausedBackend) List(prefix string) ([]string, error) {
	p.hook()
	return p.SecretBackend.List(prefix)
}

func (p *pausedBackend) Get(path string) (*store.Secret, error) {
	defer p.hook()
	return p.SecretBackend.Get(path)
}

// wideRole lets the "dev" role reach everything, so only the ACL limits it.
func (e *credEnv) wideRole() {
	e.srv.sessionRoles["dev"] = config.RoleConfig{Namespaces: []string{"**"}, BootstrapTrust: []string{"bearer"}}
	seedSecret(e.t, e.srv, "admin-token", "other/b", "other-value")
}

// widen replaces the worker's token with one that may read everything.
func (e *credEnv) widen() {
	e.t.Helper()
	code, body := e.do("POST", "/v1/agents?force=true", "admin-token",
		`{"name":"worker","token":"new-token","permissions":[{"path":"**","actions":["list","read_value"]}]}`)
	if code != 200 {
		e.t.Errorf("replace: %d %s", code, body)
	}
}

// createWide makes the worker agent anew with what widen gives it.
func (e *credEnv) createWide() {
	e.t.Helper()
	code, body := e.do("POST", "/v1/agents", "admin-token",
		`{"name":"worker","token":"new-token","permissions":[{"path":"**","actions":["list","read_value"]}]}`)
	if code != 200 {
		e.t.Errorf("create: %d %s", code, body)
	}
}

// A request already running with an old session never uses permissions that
// only the replacement token was given, and is told its session ended.
func TestRunningRequestCannotUseReplacementPermissions(t *testing.T) {
	for _, path := range []string{"/v1/secrets/other/", "/v1/metadata/other/", "/v1/secrets/empty/", "/v1/metadata/empty/"} {
		for how, change := range map[string]func(*credEnv){"replace": (*credEnv).widen, "delete": (*credEnv).remove} {
			t.Run(path+" "+how, func(t *testing.T) {
				e := newCredEnv(t)
				e.wideRole()
				sess := e.mint("old-token")
				var once sync.Once
				ran := false
				e.srv.backend = &pausedBackend{e.srv.backend, func() { once.Do(func() { ran = true; change(e) }) }}
				code, body := e.do("GET", path, sess, "")
				if !ran || code != 401 || !strings.Contains(body, "SESSION_INVALID") || strings.Contains(body, "other/b") {
					t.Errorf("ran %v, %d %s, want 401 SESSION_INVALID", ran, code, body)
				}
			})
		}
	}
	t.Run("resolve", func(t *testing.T) {
		e := newCredEnv(t)
		e.wideRole()
		sess := e.mint("old-token")
		var once sync.Once
		e.srv.backend = &pausedBackend{e.srv.backend, func() { once.Do(e.widen) }}
		code, body := e.do("POST", "/v1/resolve", sess, `{"refs":["phoenix://test/a","phoenix://other/b"]}`)
		if code != 200 || !strings.Contains(body, "synthetic-value") || !strings.Contains(body, "SESSION_INVALID") || strings.Contains(body, "other-value") {
			t.Errorf("%d %s, want the first value and SESSION_INVALID for the second", code, body)
		}
	})
}

// The access check passes on why the session stopped being valid: a client
// must not replace a revoked session, so it may not look like an ended one.
func TestAccessCheckSaysWhySessionEnded(t *testing.T) {
	cases := map[string]struct {
		want string
		end  func(e *credEnv, id string)
	}{
		"token replaced": {"SESSION_INVALID", func(e *credEnv, _ string) { e.widen() }},
		"replaced past the routes": {"SESSION_INVALID", func(e *credEnv, _ string) {
			e.srv.acl.UpdateAgent("worker", "new-token", []acl.Permission{{Path: "**", Actions: []acl.Action{acl.ActionReadValue}}})
		}},
		"revoked": {"SESSION_REVOKED", func(e *credEnv, id string) { e.sessions.Revoke(id) }},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			want := c.want
			e := newCredEnv(t)
			e.wideRole()
			sess, err := e.sessions.Validate(e.mint("old-token"))
			if err != nil {
				t.Fatal(err)
			}
			info := &authInfo{Agent: "worker", UsedSession: true, SessionID: sess.ID, SessionNamespaces: sess.Namespaces, SessionActions: sess.Actions}
			c.end(e, sess.ID)
			if got := e.srv.baseAccessReason(info, "test/a", "read_value", acl.ActionReadValue); got != want {
				t.Errorf("reason = %q, want %q", got, want)
			}
			if code, _ := resolveDenial(want); code != want {
				t.Errorf("resolve code = %q, want %q", code, want)
			}
			w := httptest.NewRecorder()
			e.srv.writeDataDenial(w, httptest.NewRequest("GET", "/v1/secrets/test/a", nil), info, "read_value", "test/a", "", want)
			if w.Code != 401 || !strings.Contains(w.Body.String(), want) {
				t.Errorf("denial = %d %s, want 401 %s", w.Code, w.Body.String(), want)
			}
		})
	}
}

// Deleting an unknown agent is still a plain 404.
func TestDeleteUnknownAgent(t *testing.T) {
	e := newCredEnv(t)
	if code, _ := e.do("DELETE", "/v1/agents/nobody", "admin-token", ""); code != http.StatusNotFound {
		t.Errorf("delete unknown agent = %d, want 404", code)
	}
	if names := e.srv.acl.ListAgents(); !slices.Contains(names, "worker") {
		t.Errorf("agents = %v", names)
	}
}

// A bearer request that logged in before its token was replaced never uses
// permissions that only the replacement token was given. The hook runs after
// login and before the permission check.
func TestRunningBearerRequestCannotUseReplacementPermissions(t *testing.T) {
	changes := map[string]func(*credEnv){
		"replace":           (*credEnv).widen,
		"delete and create": func(e *credEnv) { e.remove(); e.createWide() },
	}
	for how, change := range changes {
		for _, path := range []string{"/v1/secrets/other/", "/v1/metadata/other/", "/v1/secrets/empty/", "/v1/metadata/empty/"} {
			t.Run(path+" "+how, func(t *testing.T) {
				e := newCredEnv(t)
				e.wideRole()
				var once sync.Once
				ran := false
				e.srv.backend = &pausedBackend{e.srv.backend, func() { once.Do(func() { ran = true; change(e) }) }}
				code, body := e.do("GET", path, "old-token", "")
				if !ran || code != 401 || strings.Contains(body, "other/b") {
					t.Errorf("ran %v, %d %s, want 401", ran, code, body)
				}
			})
		}
		t.Run("resolve "+how, func(t *testing.T) {
			e := newCredEnv(t)
			e.wideRole()
			code, body := e.doReader("POST", "/v1/resolve", "old-token", &hookBody{
				Reader: strings.NewReader(`{"refs":["phoenix://other/b"]}`), hook: func() { change(e) }})
			if code != 401 || strings.Contains(body, "other-value") {
				t.Errorf("resolve = %d %s, want 401 and no value", code, body)
			}
		})
	}
}

// Every permission decision made from a login, admin and approver ones
// included, stops counting once that login's token was replaced. The same
// token written again (--force) is still the same credential.
func TestReplacedTokenLoginLosesEveryPermission(t *testing.T) {
	e := newCredEnv(t)
	e.srv.SetAccessRequests(config.AccessRequestsSettings{Enabled: true, Approvers: []string{"worker"}})
	login := func(tok string) *authInfo {
		r := httptest.NewRequest("GET", "/v1/whoami", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		info, err := e.srv.authenticateInfo(r)
		if err != nil {
			t.Fatal(err)
		}
		return info
	}
	allowed := func(info *authInfo) []bool {
		return []bool{
			e.srv.baseAccessReason(info, "test/a", "read_value", acl.ActionReadValue) == "",
			e.srv.authorize(info, "agents", acl.ActionAdmin) == nil,
			e.srv.isApprover(info),
		}
	}
	old := login("old-token")
	if got := allowed(old); !slices.Equal(got, []bool{true, false, true}) {
		t.Fatalf("before: %v", got)
	}
	e.create("old-token", true)
	if got := allowed(old); !slices.Equal(got, []bool{true, false, true}) {
		t.Errorf("same token written again: %v", got)
	}
	all := []acl.Permission{{Path: "*", Actions: []acl.Action{acl.ActionAdmin}}}
	if err := e.srv.acl.UpdateAgent("worker", "new-token", all); err != nil {
		t.Fatal(err)
	}
	if got := allowed(old); !slices.Equal(got, []bool{false, false, false}) {
		t.Errorf("old login after replace: %v, want nothing allowed", got)
	}
	if got := allowed(login("new-token")); !slices.Equal(got, []bool{true, true, true}) {
		t.Errorf("new login: %v", got)
	}
}

// A request that logged in and then takes its time sending its body does
// nothing once its token is replaced: no new agent, no secret, no approval.
func TestSlowBodyAfterTokenReplaced(t *testing.T) {
	admin := []acl.Permission{{Path: "*", Actions: []acl.Action{acl.ActionAdmin}}}
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/v1/agents", `{"name":"backdoor","token":"fake","permissions":[]}`},
		{"POST", "/v1/agents?force=true", `{"name":"admin","token":"fake","permissions":[]}`},
		{"PUT", "/v1/secrets/test/b", `{"value":"x"}`},
		{"POST", "/v1/keypair", `{"agent_name":"admin","seal_public_key":"` + strings.Repeat("A", 43) + `="}`},
		{"POST", "/v1/access-requests", `{"paths":["test/a"],"reason":"x"}`},
		{"POST", "/v1/access-requests/req_x/approve", `{}`},
		{"POST", "/v1/access-requests/req_x/deny", `{}`},
		{"POST", "/v1/resolve", `{"refs":["phoenix://test/a"]}`},
	} {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			e := newCredEnv(t)
			e.srv.SetAccessRequests(config.AccessRequestsSettings{Enabled: true, Approvers: []string{"worker"},
				GrantableActions: []string{"read_value"}, RequestTTL: time.Minute, DefaultGrantTTL: time.Minute, MaxGrantTTL: time.Hour})
			if err := e.srv.acl.UpdateAgent("worker", "old-token", admin); err != nil {
				t.Fatal(err)
			}
			code, body := e.doReader(c.method, c.path, "old-token", &hookBody{Reader: strings.NewReader(c.body), hook: func() {
				if err := e.srv.acl.UpdateAgent("worker", "new-token", admin); err != nil {
					t.Error(err)
				}
			}})
			if code != 401 {
				t.Errorf("%d %s, want 401", code, body)
			}
			if _, err := e.srv.acl.GetAgent("backdoor"); err == nil {
				t.Error("an agent was created")
			}
			if _, err := e.srv.backend.Get("test/b"); err == nil {
				t.Error("a secret was written")
			}
		})
	}
}
