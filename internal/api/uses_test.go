package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/grant"
	"github.com/phoenixsec/phoenix/internal/policy"
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
	for _, uses := range []string{"-1", "1001"} {
		expect(t, e.do("POST", "/v1/access-requests/"+id+"/approve", approverTok, `{"uses":`+uses+`}`), http.StatusBadRequest, CodeInvalidRequest)
	}
	// Double tap: the same grant, not a second use. A different answer is too late.
	a := e.approve(t, id, `{"uses":1}`)
	if b := e.approve(t, id, `{"uses":1}`); a != b {
		t.Fatalf("repeat made another grant: %s %s", a, b)
	}
	expect(t, e.do("POST", "/v1/access-requests/"+id+"/approve", approverTok, `{}`), http.StatusConflict, "NOT_PENDING")
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

	still, err := e.srv.RemoveAlwaysAs("vector", "infra/b2/app-key", "dashboard@x", "10.0.0.1")
	if err != nil || still {
		t.Fatalf("remove: %v %v", still, err)
	}
	expect(t, e.sealedGet("infra/b2/app-key", vectorTok), http.StatusForbidden, CodeACLDenied)
	v = expect(t, e.do("GET", "/v1/access-requests/"+id, vectorTok, ""), http.StatusOK, "")
	if v["next_step"] != NextAskUser {
		t.Fatalf("after removal: %v", v)
	}
	if _, err := e.srv.RemoveAlwaysAs("vector", "infra/b2/app-key", "dashboard@x", ""); err == nil {
		t.Fatal("removing twice should say it is gone")
	}
	// A wider rule still lets it read: the caller is told.
	e.srv.acl.UpdateAgent("vector", vectorTok, []acl.Permission{{Path: "infra/**", Actions: []acl.Action{acl.ActionReadValue}}})
	e.srv.acl.AddAlways("vector", acl.AlwaysOrigin{RequestID: "req_x"}, []string{"infra/other"}, func(acl.Agent) error { return nil })
	if still, err := e.srv.RemoveAlwaysAs("vector", "infra/other", "dashboard@x", ""); err != nil || !still {
		t.Fatalf("still = %v %v", still, err)
	}
}

func TestSSHOnceOpensOneLogin(t *testing.T) {
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
		t.Fatal("the opened login must stay open")
	}
	if code, m := e.sign(t, vectorTok, "build-1", ip); code != http.StatusForbidden || m["code"] != CodeGrantExpired || m["next_step"] != NextRequestUse {
		t.Fatalf("second login: %d %v", code, m)
	}
	expect(t, e.do("POST", "/v1/grants/"+gid+"/revoke", approverTok, ""), http.StatusOK, "")
	if e.windowOpen(t, "build-1", gid) {
		t.Fatal("revoke must end the opened login")
	}
}
