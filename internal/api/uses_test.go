package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/grant"
	"github.com/phoenixsec/phoenix/internal/policy"
	"github.com/phoenixsec/phoenix/internal/store"
)

// resolve sends one sealed resolve as vector.
func (e *grantEnv) resolve(query, body string) *httptest.ResponseRecorder {
	return e.do("POST", "/v1/resolve"+query, vectorTok, body, "X-Phoenix-Seal-Key: "+e.sealPub)
}

func (e *grantEnv) left(t *testing.T, gid, path string) int64 {
	t.Helper()
	g, ok := e.store.GetGrant(gid)
	if !ok {
		t.Fatal("grant gone")
	}
	return g.UsesLeft(path)
}

// Nothing that does not deliver the value costs the one use.
func TestOnlyDeliverySpendsAUse(t *testing.T) {
	e := newGrantEnv(t)
	id := e.request(t, vectorTok, "infra/b2/app-key", "infra/missing")
	gid := e.approve(t, id, `{"uses":1}`)
	const path = "infra/b2/app-key"
	want := func(step string, left int64) {
		t.Helper()
		if got := e.left(t, gid, path); got != left {
			t.Fatalf("%s: %d uses left, want %d", step, got, left)
		}
	}
	expect(t, e.do("GET", "/v1/secrets/"+path, vectorTok, ""), http.StatusForbidden, CodeSealedRequired)
	want("plaintext refused", 1)
	expect(t, e.do("GET", "/v1/secrets/"+path, approverTok, ""), http.StatusForbidden, CodeACLDenied)
	want("another agent", 1)
	expect(t, e.resolve("?dry_run=true", `{"refs":["phoenix://infra/b2/app-key"]}`), http.StatusOK, "")
	want("dry run", 1)
	e.sealedGet("infra/missing", vectorTok)
	if got := e.left(t, gid, "infra/missing"); got != 1 {
		t.Fatalf("a missing secret cost a use")
	}
	pe, err := policy.Load([]byte(`{"attestation": {"infra/b2/*": {"source_ip": ["10.9.9.9"]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	e.srv.SetPolicy(pe)
	expect(t, e.sealedGet(path, vectorTok), http.StatusForbidden, CodeAttestationRequired)
	want("attestation refused", 1)
	e.srv.SetPolicy(nil)
	// exec's batch with one bad ref: nothing is delivered, nothing is spent.
	body := jsonBody(t, e.resolve("", `{"refs":["phoenix://infra/b2/app-key","phoenix://infra/other"],"all_or_nothing":true}`))
	if len(body["sealed_values"].(map[string]any)) != 0 {
		t.Fatal("all_or_nothing delivered part")
	}
	want("all_or_nothing", 1)

	if got := e.openSealed(t, e.sealedGet(path, vectorTok)); got != "b2-secret-value" {
		t.Fatalf("value = %q", got)
	}
	want("delivered", 0)
	m := expect(t, e.sealedGet(path, vectorTok), http.StatusForbidden, CodeGrantExpired)
	if m["next_step"] != NextRequestUse {
		t.Fatalf("after the one use: %v", m)
	}
	v := expect(t, e.do("GET", "/v1/access-requests/"+id, vectorTok, ""), http.StatusOK, "")
	if v["max_uses"] != float64(1) || v["uses_left"].(map[string]any)[path] != float64(0) {
		t.Fatalf("status view = %v", v)
	}
}

// Many reads at once of a grant with three uses: exactly three get the value.
func TestUsesExactOverHTTP(t *testing.T) {
	e := newGrantEnv(t)
	e.approve(t, e.request(t, vectorTok, "infra/b2/app-key"), `{"uses":3}`)
	var ok atomic.Int64
	var wg sync.WaitGroup
	for i := range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i%2 == 0 {
				if e.sealedGet("infra/b2/app-key", vectorTok).Code == http.StatusOK {
					ok.Add(1)
				}
				return
			}
			var body struct {
				Sealed map[string]any `json:"sealed_values"`
			}
			json.Unmarshal(e.resolve("", `{"refs":["phoenix://infra/b2/app-key"]}`).Body.Bytes(), &body)
			ok.Add(int64(len(body.Sealed)))
		}()
	}
	wg.Wait()
	if ok.Load() != 3 {
		t.Fatalf("%d reads got the value, want 3", ok.Load())
	}
}

func TestApproveUsesValidation(t *testing.T) {
	e := newGrantEnv(t)
	id := e.request(t, vectorTok, "infra/b2/app-key")
	post := func(op, body string) *httptest.ResponseRecorder {
		return e.do("POST", "/v1/access-requests/"+id+"/"+op, approverTok, body)
	}
	for _, body := range []string{`{"uses":-1}`, `{"uses":1001}`, `{"uses":0}`, `{}`, ``} {
		expect(t, post("approve-limited", body), http.StatusBadRequest, CodeInvalidRequest)
	}
	// Never on the address older servers have, where they would ignore it.
	expect(t, post("approve", `{"uses":1}`), http.StatusBadRequest, CodeInvalidRequest)
	if rq, _ := e.store.GetRequest(id); rq.Status != grant.StatusPending {
		t.Fatalf("request %s", rq.Status)
	}
	// Double tap: the same grant, not a second use. A different answer is too late.
	a := e.approve(t, id, `{"uses":1}`)
	if b := e.approve(t, id, `{"uses":1}`); a != b {
		t.Fatalf("repeat made another grant: %s %s", a, b)
	}
	expect(t, post("approve", `{}`), http.StatusConflict, "NOT_PENDING")
	expect(t, e.do("POST", "/v1/access-requests/"+id+"/approve-limited", vectorTok, `{"uses":1}`), http.StatusForbidden, CodeApproverRequired)
}

func TestApproveAfterTokenChange(t *testing.T) {
	e := newGrantEnv(t)
	id := e.request(t, vectorTok, "infra/b2/app-key")
	if err := e.srv.acl.UpdateAgent("vector", "replacement", nil); err != nil {
		t.Fatal(err)
	}
	expect(t, e.do("POST", "/v1/access-requests/"+id+"/approve", approverTok, `{}`), http.StatusConflict, CodeCredentialChanged)
	if _, _, err := e.srv.ApproveAccessRequestAs(id, "dashboard@x", "", grant.Approval{Always: true}); err == nil {
		t.Fatal("always went to the replacement token")
	}
	if e.srv.acl.Authorize("vector", "infra/b2/app-key", acl.ActionReadValue) == nil {
		t.Fatal("replacement token can read")
	}
}

// Always: the agent reads through its own access list, is told so, and a
// removal counts on the very next read.
func TestAlwaysOverHTTP(t *testing.T) {
	e := newGrantEnv(t)
	st, err := grant.Open(grant.Options{
		Path: e.dir + "/always.json", Audit: NewGrantAuditSink(e.srv.audit), Now: e.clock.Now,
		Always: NewAlwaysRules(e.srv.acl), Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.store = st
	e.srv.SetGrantStore(st)
	id := e.request(t, vectorTok, "infra/b2/app-key")
	if _, _, err := e.srv.ApproveAccessRequestAs(id, "dashboard@x", "10.0.0.1", grant.Approval{Always: true}); err != nil {
		t.Fatal(err)
	}
	v := expect(t, e.do("GET", "/v1/access-requests/"+id, vectorTok, ""), http.StatusOK, "")
	if v["always"] != true || v["next_step"] != NextUseExec {
		t.Fatalf("view = %v", v)
	}
	if got := e.openSealed(t, e.sealedGet("infra/b2/app-key", vectorTok)); got != "b2-secret-value" {
		t.Fatal("cannot read")
	}
	expect(t, e.do("GET", "/v1/secrets/infra/other", vectorTok, ""), http.StatusForbidden, CodeACLDenied)
	// It is standing access: turning requests off does not take it away.
	e.set(func(s *config.AccessRequestsSettings) { s.Enabled = false })
	expect(t, e.sealedGet("infra/b2/app-key", vectorTok), http.StatusOK, "")

	if err := e.srv.RemoveAlwaysAs("vector", "infra/b2/app-key", "req_other", "dashboard@x", ""); err == nil {
		t.Fatal("removed by the wrong request")
	}
	if err := e.srv.RemoveAlwaysAs("vector", "infra/b2/app-key", id, "dashboard@x", "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	expect(t, e.sealedGet("infra/b2/app-key", vectorTok), http.StatusForbidden, CodeACLDenied)
	v = expect(t, e.do("GET", "/v1/access-requests/"+id, vectorTok, ""), http.StatusOK, "")
	if v["next_step"] != NextAskUser {
		t.Fatalf("after removal: %v", v)
	}
	if err := e.srv.RemoveAlwaysAs("vector", "infra/b2/app-key", id, "dashboard@x", ""); err == nil {
		t.Fatal("removing twice should say it is gone")
	}
}

// slowFS lets a test look around while the grants file is being written.
type slowFS struct {
	grant.OSFS
	during func() error
}

func (f *slowFS) WriteFileAtomic(name string, data []byte, perm os.FileMode) error {
	if f.during != nil {
		if err := f.during(); err != nil {
			return err
		}
	}
	return f.OSFS.WriteFileAtomic(name, data, perm)
}

// Nothing can be read through an "always" before the answer is saved: not as
// the agent, and not if the save then fails.
func TestAlwaysNotReadableBeforeSaved(t *testing.T) {
	fs := &slowFS{}
	e := newGrantEnv(t, func(o *grant.Options) { o.FS = fs })
	e.store = nil
	st, err := grant.Open(grant.Options{
		Path: e.dir + "/always.json", FS: fs, Audit: NewGrantAuditSink(e.srv.audit), Now: e.clock.Now,
		Always: NewAlwaysRules(e.srv.acl), Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.SetGrantStore(st)
	id := e.request(t, vectorTok, "infra/b2/app-key")
	reads := 0
	fs.during = func() error {
		reads++
		expect(t, e.sealedGet("infra/b2/app-key", vectorTok), http.StatusForbidden, CodeACLDenied)
		body := jsonBody(t, e.resolve("", `{"refs":["phoenix://infra/b2/app-key"]}`))
		if len(body["sealed_values"].(map[string]any)) != 0 {
			t.Error("resolved before the answer was saved")
		}
		return errors.New("disk full")
	}
	if _, _, err := e.srv.ApproveAccessRequestAs(id, "dashboard@x", "", grant.Approval{Always: true}); err == nil || reads == 0 {
		t.Fatalf("err=%v reads=%d", err, reads)
	}
	fs.during = nil
	expect(t, e.sealedGet("infra/b2/app-key", vectorTok), http.StatusForbidden, CodeACLDenied)
}

// HEAD runs the GET handler. It must not cost the one use.
func TestHeadSpendsNothing(t *testing.T) {
	e := newGrantEnv(t)
	e.approve(t, e.request(t, vectorTok, "infra/b2/app-key"), `{"uses":1}`)
	srv := httptest.NewServer(e.srv)
	defer srv.Close()
	head, _ := http.NewRequest("HEAD", srv.URL+"/v1/secrets/infra/b2/app-key", nil)
	head.Header.Set("Authorization", "Bearer "+vectorTok)
	head.Header.Set("X-Phoenix-Seal-Key", e.sealPub)
	resp, err := http.DefaultClient.Do(head)
	if err != nil || resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("HEAD: %v %v", resp, err)
	}
	if got := e.openSealed(t, e.sealedGet("infra/b2/app-key", vectorTok)); got != "b2-secret-value" {
		t.Fatal("HEAD spent the use")
	}
}

// A repeated ref is one lookup, one entry and one use.
func TestRepeatedRefs(t *testing.T) {
	e := newGrantEnv(t)
	gid := e.approve(t, e.request(t, vectorTok, "infra/b2/app-key"), `{"uses":2}`)
	counted := &getCounter{SecretBackend: e.srv.backend}
	e.srv.backend = counted
	body := jsonBody(t, e.resolve("", `{"refs":["phoenix://infra/b2/app-key","phoenix://infra/b2/app-key","phoenix://infra/b2/app-key"]}`))
	if len(body["sealed_values"].(map[string]any)) != 1 || counted.gets != 1 || e.left(t, gid, "infra/b2/app-key") != 1 {
		t.Fatalf("gets=%d left=%d %v", counted.gets, e.left(t, gid, "infra/b2/app-key"), body)
	}
}

type getCounter struct {
	store.SecretBackend
	gets int
}

func (b *getCounter) Get(path string) (*store.Secret, error) {
	b.gets++
	return b.SecretBackend.Get(path)
}

// resolve-approved uses nothing but the approval, even where the agent's own
// access list allows the path.
func TestResolveApprovedIgnoresOtherAccess(t *testing.T) {
	e := newGrantEnv(t)
	// The agent may read everything under infra by itself, and has a "once"
	// on one of those paths beside one it may not read.
	gid := e.approve(t, e.request(t, vectorTok, "infra/b2/app-key", "infra/other"), `{"uses":1}`)
	wide := []acl.Permission{{Path: "infra/b2/**", Actions: []acl.Action{acl.ActionReadValue}}}
	if err := e.srv.acl.UpdateAgent("vector", vectorTok, wide); err != nil {
		t.Fatal(err)
	}
	approved := func(tok, ip string, seal bool) (int, map[string]any) {
		hdr := []string{"RemoteAddr: " + ip}
		if seal {
			hdr = append(hdr, "X-Phoenix-Seal-Key: "+e.sealPub)
		}
		w := e.do("POST", "/v1/resolve-approved", tok, `{"refs":["phoenix://infra/b2/app-key"]}`, hdr...)
		body := jsonBody(t, w)
		m, _ := body["sealed_values"].(map[string]any)
		if v, ok := body["values"].(map[string]any); ok {
			m = v
		}
		return len(m), body
	}
	const ip = "192.0.2.1" // httptest's address, where the request came from
	if n, b := approved(vectorTok, "192.0.2.99", true); n != 0 {
		t.Fatalf("from another address: %v", b)
	}
	if n, b := approved(vectorTok, ip, false); n != 0 {
		t.Fatalf("unsealed: %v", b)
	}
	if n, b := approved(vectorTok, ip, true); n != 1 {
		t.Fatalf("the approval itself: %v", b)
	}
	if e.left(t, gid, "infra/b2/app-key") != 0 {
		t.Fatal("no use was spent")
	}
	if n, b := approved(vectorTok, ip, true); n != 0 {
		t.Fatalf("spent path read through ordinary access: %v", b)
	}
	if n, b := approved(approverTok, ip, false); n != 0 {
		t.Fatalf("another agent: %v", b)
	}
	e.addSessions(t)
	if n, b := approved(e.mintSession(t, e.sealPub), ip, true); n != 0 {
		t.Fatalf("a session: %v", b)
	}
	// Ordinary reads are not affected.
	expect(t, e.sealedGet("infra/b2/app-key", vectorTok), http.StatusOK, "")
	// Always counts, until it is removed.
	stage := acl.AlwaysOrigin{RequestID: "req_x"}
	ok := func(acl.Agent) error { return nil }
	e.srv.acl.StageAlways("vector", stage, []string{"infra/b2/app-key"}, ok)
	if n, _ := approved(vectorTok, ip, true); n != 0 {
		t.Fatal("a staged always was used")
	}
	e.srv.acl.FinishAlways("vector", "req_x", ok)
	if n, b := approved(vectorTok, ip, true); n != 1 {
		t.Fatalf("always: %v", b)
	}
	e.srv.acl.RemoveAlways("vector", "infra/b2/app-key", "req_x")
	if n, _ := approved(vectorTok, ip, true); n != 0 {
		t.Fatal("a removed always was used")
	}
}

// Token A, then B, then A again: what the first A asked for and was given stays
// with the first A.
func TestReissuedTokenOverHTTP(t *testing.T) {
	e := newGrantEnv(t)
	keep := []acl.Permission{{Path: "dev/**", Actions: []acl.Action{acl.ActionReadValue}}}
	e.approve(t, e.request(t, vectorTok, "infra/b2/app-key"), "")
	waiting := e.request(t, vectorTok, "infra/other")
	for _, tok := range []string{"token-b", vectorTok} {
		if err := e.srv.acl.UpdateAgent("vector", tok, keep); err != nil {
			t.Fatal(err)
		}
	}
	if code := e.sealedGet("infra/b2/app-key", vectorTok).Code; code != http.StatusForbidden {
		t.Fatalf("old grant came back with the token: %d", code)
	}
	expect(t, e.do("POST", "/v1/access-requests/"+waiting+"/approve", approverTok, `{}`), http.StatusConflict, CodeCredentialChanged)
	if _, _, err := e.srv.ApproveAccessRequestAs(waiting, "dashboard@x", "", grant.Approval{Always: true}); err == nil {
		t.Fatal("always for an old request")
	}
	// Asking again works.
	fresh := e.request(t, vectorTok, "infra/other")
	if fresh == waiting {
		t.Fatal("got the old request back")
	}
	e.approve(t, fresh, "")
	expect(t, e.sealedGet("infra/other", vectorTok), http.StatusOK, "")
}

// The token is replaced while the secret is being fetched: no value, no use.
func TestTokenReplacedDuringRead(t *testing.T) {
	e := newGrantEnv(t)
	gid := e.approve(t, e.request(t, vectorTok, "infra/b2/app-key"), `{"uses":1}`)
	e.srv.backend = &hookBackend{e.srv.backend, func() { e.srv.acl.UpdateAgent("vector", "token-b", nil) }}
	if code := e.sealedGet("infra/b2/app-key", vectorTok).Code; code != http.StatusForbidden {
		t.Fatalf("status %d", code)
	}
	if e.left(t, gid, "infra/b2/app-key") != 1 {
		t.Fatal("use spent")
	}
}

type hookBackend struct {
	store.SecretBackend
	hook func()
}

func (b *hookBackend) Get(path string) (*store.Secret, error) {
	b.hook()
	return b.SecretBackend.Get(path)
}

// The status hint names a path that can still be used.
func TestStatusHintSkipsSpentPath(t *testing.T) {
	e := newGrantEnv(t)
	id := e.request(t, vectorTok, "infra/b2/app-key", "infra/other")
	e.approve(t, id, `{"uses":1}`)
	expect(t, e.sealedGet("infra/b2/app-key", vectorTok), http.StatusOK, "")
	v := expect(t, e.do("GET", "/v1/access-requests/"+id, vectorTok, ""), http.StatusOK, "")
	if msg := v["message"].(string); !strings.Contains(msg, "phoenix://infra/other") {
		t.Fatalf("message = %q", msg)
	}
}

func TestSSHOnceIsOneCertificate(t *testing.T) {
	e := newSSHEnv(t)
	const ip = "192.0.2.30"
	b, _ := json.Marshal(map[string]any{"paths": []string{"ssh/build-1"}, "action": grant.ActionSSHLogin, "reason": "x"})
	rq := expect(t, e.do("POST", "/v1/access-requests", vectorTok, string(b), "RemoteAddr: "+ip), http.StatusCreated, "")
	id := rq["id"].(string)
	if _, _, err := e.srv.ApproveAccessRequestAs(id, "dashboard@x", "", grant.Approval{Always: true}); grant.CodeOf(err) != grant.CodeAlwaysNotAllowed {
		t.Fatalf("always for a login: %v", err)
	}
	gid := e.approve(t, id, `{"uses":1}`)
	// A bad key is not a login.
	e.do("POST", "/v1/ssh/sign", vectorTok, `{"host":"build-1","public_key":"nope"}`, "RemoteAddr: "+ip)
	if code, m := e.sign(t, vectorTok, "build-1", ip); code != http.StatusOK {
		t.Fatalf("first login: %d %v", code, m)
	}
	if !e.windowOpen(t, "build-1", gid) {
		t.Fatal("the certificate must keep working until its time ends")
	}
	if code, m := e.sign(t, vectorTok, "build-1", ip); code != http.StatusForbidden || m["code"] != CodeGrantExpired || m["next_step"] != NextRequestUse {
		t.Fatalf("second login: %d %v", code, m)
	}
	expect(t, e.do("POST", "/v1/grants/"+gid+"/revoke", approverTok, ""), http.StatusOK, "")
	if e.windowOpen(t, "build-1", gid) {
		t.Fatal("revoke must end it")
	}
}
