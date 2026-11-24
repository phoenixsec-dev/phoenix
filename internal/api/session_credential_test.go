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
	if !strings.Contains(saved, grant.BearerFingerprint(crypto.HashToken("old-token"))) {
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

// When the ended sessions cannot be saved, the change still happens, the
// sessions are dead, the operator gets a 500, and a restart changes nothing.
func TestCredentialChangeWhenSessionsCannotBeSaved(t *testing.T) {
	changes := map[string][2]string{
		"delete":  {"DELETE", "/v1/agents/worker"},
		"replace": {"POST", "/v1/agents?force=true"},
	}
	for name, c := range changes {
		t.Run(name, func(t *testing.T) {
			e := newCredEnv(t)
			sess := e.mint("old-token")
			dir := filepath.Dir(e.sessionsPath())
			if err := os.Rename(dir, dir+".away"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dir, nil, 0600); err != nil { // a file where the directory was
				t.Fatal(err)
			}
			code, body := e.do(c[0], c[1], "admin-token", `{"name":"worker","token":"new-token","permissions":`+workerACL+`}`)
			if code != 500 || !strings.Contains(body, "could not be saved") {
				t.Errorf("%d %s, want 500 saying it was not saved", code, body)
			}
			if code, _ := e.do("GET", "/v1/whoami", "old-token", ""); code != 401 {
				t.Errorf("old bearer still works: %d", code)
			}
			e.wantDead("after failed save", sess)

			// The old token may not come back while its ended session is
			// still on disk; any other token is fine.
			for _, path := range []string{"/v1/agents", "/v1/agents?force=true"} {
				if name == "replace" && path == "/v1/agents" {
					continue // the agent exists: 409 either way
				}
				code, body = e.do("POST", path, "admin-token", `{"name":"worker","token":"old-token","permissions":`+workerACL+`}`)
				if code != 500 || !strings.Contains(body, "not changed") {
					t.Errorf("old token back via %s: %d %s, want 500 not changed", path, code, body)
				}
			}
			if code, body = e.do("POST", "/v1/agents?force=true", "admin-token", `{"name":"worker","token":"third-token","permissions":`+workerACL+`}`); code != 200 {
				t.Errorf("another token while the save is failing: %d %s, want 200", code, body)
			}

			if err := errors.Join(os.Remove(dir), os.Rename(dir+".away", dir)); err != nil {
				t.Fatal(err)
			}
			// Saving works again: the old token may come back, its session not.
			e.create("old-token", true)
			e.wantDead("after the old token is back", sess)
			e.start()
			e.wantDead("after restart", sess)
		})
	}
}

// Replacing one agent's token reports only its own sessions: a save that
// failed earlier for another agent is not blamed on it.
func TestFailedSaveIsNotReportedForAnotherAgent(t *testing.T) {
	e := newCredEnv(t)
	e.mint("old-token")
	dir := filepath.Dir(e.sessionsPath())
	if err := errors.Join(os.Rename(dir, dir+".away"), os.WriteFile(dir, nil, 0600)); err != nil {
		t.Fatal(err)
	}
	if code, body := e.do("DELETE", "/v1/agents/worker", "admin-token", ""); code != 500 {
		t.Fatalf("delete: %d %s, want 500", code, body)
	}
	for _, tok := range []string{"other-1", "other-2"} {
		if code, body := e.do("POST", "/v1/agents?force=true", "admin-token", `{"name":"other","token":"`+tok+`","permissions":`+workerACL+`}`); code != 200 {
			t.Errorf("another agent's token: %d %s, want 200", code, body)
		}
	}
}

// Sessions saved before a start with sessions disabled do not come back when
// they are enabled again, whatever happened to the token in between.
func TestDisablingSessionsEndsSavedOnes(t *testing.T) {
	e := newCredEnv(t)
	sess, revoked := e.mint("old-token"), e.mint("old-token")
	_, id, _ := e.sessions.ParseClaimsInsecure(revoked)
	if err := e.sessions.Revoke(id); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.EndSavedSessions(e.sessionsPath()); err != nil { // what a disabled start does
		t.Fatal(err)
	}
	e.wantEnded("system", "sessions_disabled")
	e.start()
	e.wantDead("after enabling again", sess)
	if code, body := e.do("GET", "/v1/whoami", revoked, ""); code != 401 || !strings.Contains(body, "SESSION_REVOKED") {
		t.Errorf("revoked session: %d %s, want SESSION_REVOKED", code, body)
	}

	// Anything else at that path is left alone.
	other := filepath.Join(e.dir, "acl.json")
	before, _ := os.ReadFile(other)
	for _, path := range []string{other, filepath.Join(e.dir, "missing.json")} {
		if err := e.srv.EndSavedSessions(path); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
	if after, _ := os.ReadFile(other); !bytes.Equal(before, after) {
		t.Error("a file that is not a sessions file was changed")
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

// A request already running with an old session never uses permissions that
// only the replacement token was given.
func TestRunningRequestCannotUseReplacementPermissions(t *testing.T) {
	cases := map[string][3]string{
		"list":     {"GET", "/v1/secrets/other/", ""},
		"metadata": {"GET", "/v1/metadata/other/", ""},
		"resolve":  {"POST", "/v1/resolve", `{"refs":["phoenix://test/a","phoenix://other/b"]}`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newCredEnv(t)
			e.srv.sessionRoles["dev"] = config.RoleConfig{Namespaces: []string{"**"}, BootstrapTrust: []string{"bearer"}}
			seedSecret(t, e.srv, "admin-token", "other/b", "other-value")
			sess := e.mint("old-token")
			var once sync.Once
			e.srv.backend = &pausedBackend{e.srv.backend, func() {
				once.Do(func() {
					code, body := e.do("POST", "/v1/agents?force=true", "admin-token",
						`{"name":"worker","token":"new-token","permissions":[{"path":"**","actions":["list","read_value"]}]}`)
					if code != 200 {
						t.Errorf("replace: %d %s", code, body)
					}
				})
			}}
			code, body := e.do(c[0], c[1], sess, c[2])
			if strings.Contains(body, "other-value") || strings.Contains(body, `"other/b"`) {
				t.Errorf("%d %s: used the new token's permissions", code, body)
			}
			if name == "resolve" && (!strings.Contains(body, "synthetic-value") || !strings.Contains(body, "SESSION_INVALID")) {
				t.Errorf("resolve = %d %s, want the first value and SESSION_INVALID for the second", code, body)
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
