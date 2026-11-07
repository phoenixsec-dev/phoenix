package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/grant"
	"github.com/phoenixsec/phoenix/internal/sshca"
)

// newSSHEnv is the grant fixture plus a CA for one machine, with deny_paths set
// to everything: the setting that keeps secrets out of the request flow while
// logins still work.
func newSSHEnv(t *testing.T) *grantEnv {
	t.Helper()
	e := newGrantEnv(t)
	ca, _, err := sshca.LoadOrCreate(filepath.Join(e.dir, "ssh_ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	e.srv.SetSSHCA(ca, map[string]config.SSHHost{
		"arch-omen": {Address: "192.168.0.99", User: "agent"},
		"vm204":     {Address: "192.168.0.204", User: "agent"},
	})
	e.set(func(s *config.AccessRequestsSettings) { s.DenyPaths = []string{"*"} })
	return e
}

func newPublicKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(sshPub))
}

func (e *grantEnv) sign(t *testing.T, tok, host, ip string) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(sshSignBody{Host: host, PublicKey: newPublicKey(t)})
	w := e.do("POST", "/v1/ssh/sign", tok, string(b), "RemoteAddr: "+ip)
	return w.Code, jsonBody(t, w)
}

func (e *grantEnv) windowOpen(t *testing.T, host, grantID string) bool {
	t.Helper()
	return expect(t, e.do("GET", "/v1/ssh/window/"+host+"/"+grantID, "", ""), http.StatusOK, "")["open"].(bool)
}

// loginGrant asks for and approves a login, returning the grant id.
func (e *grantEnv) loginGrant(t *testing.T, tok, host, ip string) string {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"paths": []string{"ssh/" + host}, "action": grant.ActionSSHLogin, "reason": "x", "ttl": "15m"})
	req := expect(t, e.do("POST", "/v1/access-requests", tok, string(b), "RemoteAddr: "+ip), http.StatusCreated, "")
	return e.approve(t, req["id"].(string), "")
}

func TestSSHLoginFlow(t *testing.T) {
	e := newSSHEnv(t)
	const ip = "192.168.0.155"
	if e.windowOpen(t, "arch-omen", "gnt_nope") {
		t.Fatal("window open for a grant that does not exist")
	}
	code, m := e.sign(t, vectorTok, "arch-omen", ip)
	if code != http.StatusForbidden || m["code"] != CodeSSHGrantRequired || m["next_step"] != NextRequestUse {
		t.Fatalf("before approval: %d %v", code, m)
	}

	b, _ := json.Marshal(map[string]any{"paths": []string{"ssh/arch-omen"}, "action": grant.ActionSSHLogin, "reason": "deploy firewall", "ttl": "15m"})
	req := expect(t, e.do("POST", "/v1/access-requests", vectorTok, string(b), "RemoteAddr: "+ip), http.StatusCreated, "")
	gid := e.approve(t, req["id"].(string), "")
	if !e.windowOpen(t, "arch-omen", gid) || e.windowOpen(t, "vm204", gid) {
		t.Fatal("window must be open on the approved machine only")
	}

	code, m = e.sign(t, vectorTok, "arch-omen", ip)
	if code != http.StatusOK {
		t.Fatalf("after approval: %d %v", code, m)
	}
	if m["address"] != "192.168.0.99" || m["user"] != "agent" {
		t.Fatalf("target = %v", m)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(m["certificate"].(string)))
	if err != nil {
		t.Fatal(err)
	}
	cert := parsed.(*ssh.Certificate)
	if cert.ValidPrincipals[0] != "arch-omen" || cert.CriticalOptions["source-address"] != ip {
		t.Fatalf("principals=%v options=%v", cert.ValidPrincipals, cert.CriticalOptions)
	}
	if !strings.HasPrefix(cert.KeyId, "grant="+gid+",") || !strings.Contains(cert.KeyId, "agent=vector") {
		t.Fatalf("key id %q must start with the grant and name the agent", cert.KeyId)
	}
	if g, ok := e.store.GetGrant(gid); !ok || cert.ValidBefore != uint64(g.ExpiresAt.Unix()) {
		t.Fatalf("certificate must end with the grant: %d vs %+v", cert.ValidBefore, g)
	}

	// Approval for one machine is not approval for another.
	if code, _ := e.sign(t, vectorTok, "vm204", ip); code != http.StatusForbidden {
		t.Fatalf("other machine: %d", code)
	}
	// Nor does it work from another IP, or for another agent.
	if code, _ := e.sign(t, vectorTok, "arch-omen", "192.168.0.120"); code != http.StatusForbidden {
		t.Fatalf("other ip: %d", code)
	}
	if code, _ := e.sign(t, approverTok, "arch-omen", ip); code != http.StatusForbidden {
		t.Fatalf("other agent: %d", code)
	}

	// Revoke closes the window at once and the agent is sent to the human.
	expect(t, e.do("POST", "/v1/grants/"+gid+"/revoke", approverTok, ""), http.StatusOK, "")
	if e.windowOpen(t, "arch-omen", gid) {
		t.Fatal("window open after revoke")
	}
	code, m = e.sign(t, vectorTok, "arch-omen", ip)
	if code != http.StatusForbidden || m["code"] != CodeGrantRevoked || m["next_step"] != NextAskUser {
		t.Fatalf("after revoke: %d %v", code, m)
	}
}

func TestSSHGrantExpiryClosesTheWindow(t *testing.T) {
	e := newSSHEnv(t)
	const ip = "192.0.2.1"
	b, _ := json.Marshal(map[string]any{"paths": []string{"ssh/arch-omen"}, "action": grant.ActionSSHLogin, "reason": "x", "ttl": "5m"})
	req := expect(t, e.do("POST", "/v1/access-requests", vectorTok, string(b), "RemoteAddr: "+ip), http.StatusCreated, "")
	gid := e.approve(t, req["id"].(string), "")
	e.clock.Advance(6 * time.Minute)
	if e.windowOpen(t, "arch-omen", gid) {
		t.Fatal("window open after expiry")
	}
	code, m := e.sign(t, vectorTok, "arch-omen", ip)
	if code != http.StatusForbidden || m["code"] != CodeGrantExpired {
		t.Fatalf("after expiry: %d %v", code, m)
	}
}

// A "*" ACL can read every secret. It must still get no login without approval,
// and it must still be able to ask, which ALREADY_ALLOWED would otherwise stop.
func TestSSHBroadACLStillNeedsApproval(t *testing.T) {
	e := newSSHEnv(t)
	if err := e.srv.acl.AddAgent("wide", "wide-token", []acl.Permission{{Path: "*", Actions: []acl.Action{acl.ActionList, acl.ActionReadValue, acl.ActionWrite}}}); err != nil {
		t.Fatal(err)
	}
	if code, m := e.sign(t, "wide-token", "arch-omen", "192.0.2.1"); code != http.StatusForbidden || m["code"] != CodeSSHGrantRequired {
		t.Fatalf("wide ACL signed without approval: %d %v", code, m)
	}
	b, _ := json.Marshal(map[string]any{"paths": []string{"ssh/arch-omen"}, "action": grant.ActionSSHLogin, "reason": "x"})
	// No seal key is registered for this agent either: a login is not a secret.
	req := expect(t, e.do("POST", "/v1/access-requests", "wide-token", string(b), "RemoteAddr: 192.0.2.1"), http.StatusCreated, "")
	e.approve(t, req["id"].(string), "")
	if code, m := e.sign(t, "wide-token", "arch-omen", "192.0.2.1"); code != http.StatusOK {
		t.Fatalf("after approval: %d %v", code, m)
	}
}

func TestSSHRequestRules(t *testing.T) {
	e := newSSHEnv(t)
	post := func(paths ...string) *struct {
		code int
		body map[string]any
	} {
		b, _ := json.Marshal(map[string]any{"paths": paths, "action": grant.ActionSSHLogin, "reason": "x"})
		w := e.do("POST", "/v1/access-requests", vectorTok, string(b))
		return &struct {
			code int
			body map[string]any
		}{w.Code, jsonBody(t, w)}
	}
	for name, paths := range map[string][]string{
		"unknown machine":    {"ssh/nope"},
		"two machines":       {"ssh/arch-omen", "ssh/vm204"},
		"login and a secret": {"ssh/arch-omen", "infra/other"},
	} {
		if r := post(paths...); r.code != http.StatusForbidden || r.body["code"] != CodeNotRequestable {
			t.Errorf("%s: %d %v", name, r.code, r.body)
		}
	}
	// deny_paths ["*"] keeps secrets out of this flow.
	if r := post("infra/other"); r.body["code"] != CodeNotRequestable {
		t.Errorf("secret under deny-all: %v", r.body)
	}
	// A denied secret read does not advertise request_use.
	w := e.do("GET", "/v1/secrets/infra/other", vectorTok, "")
	if m := jsonBody(t, w); m["next_step"] == NextRequestUse {
		t.Errorf("secret denial advertised request_use: %v", m)
	}
}

// A login grant never opens a secret, and a secret grant never opens a login,
// even at the same path. This is why logins have their own action.
func TestSSHLoginAndSecretGrantsNeverCross(t *testing.T) {
	e := newSSHEnv(t)
	seedSecret(t, e.srv, adminTok, "ssh/arch-omen", "planted")
	const ip = "192.0.2.1"
	e.loginGrant(t, vectorTok, "arch-omen", ip)
	if w := e.do("GET", "/v1/secrets/ssh/arch-omen", vectorTok, "", "RemoteAddr: "+ip); w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "planted") {
		t.Fatalf("read through a login grant: %d %s", w.Code, w.Body.String())
	}

	// Same path as a login, approved for reading only, as an older server would
	// have stored it. It must not sign.
	e.set(func(s *config.AccessRequestsSettings) { s.DenyPaths = nil })
	if err := e.srv.acl.AddAgent("secret-reader", "secret-reader-token", nil); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.acl.SetAgentSealKey("secret-reader", e.sealPub); err != nil {
		t.Fatal(err)
	}
	secret, _ := json.Marshal(map[string]any{"paths": []string{"ssh/arch-omen"}, "action": "read_value", "reason": "x"})
	req := expect(t, e.do("POST", "/v1/access-requests", "secret-reader-token", string(secret), "RemoteAddr: "+ip), http.StatusCreated, "")
	gid := e.approve(t, req["id"].(string), "")
	if code, m := e.sign(t, "secret-reader-token", "arch-omen", ip); code != http.StatusForbidden || m["code"] != CodeSSHGrantRequired {
		t.Fatalf("a secret grant signed a login: %d %v", code, m)
	}
	if e.windowOpen(t, "arch-omen", gid) {
		t.Fatal("a secret grant must not count as an open window")
	}
}

// One agent's approval must not keep another agent's session alive.
func TestSSHWindowIsPerGrant(t *testing.T) {
	e := newSSHEnv(t)
	if err := e.srv.acl.AddAgent("second", "second-token", nil); err != nil {
		t.Fatal(err)
	}
	first := e.loginGrant(t, vectorTok, "arch-omen", "192.0.2.1")
	second := e.loginGrant(t, "second-token", "arch-omen", "192.0.2.2")
	expect(t, e.do("POST", "/v1/grants/"+first+"/revoke", approverTok, ""), http.StatusOK, "")
	if e.windowOpen(t, "arch-omen", first) {
		t.Fatal("the revoked grant's window is still open")
	}
	if !e.windowOpen(t, "arch-omen", second) {
		t.Fatal("revoking one grant closed another")
	}
}

// Removing a machine or the whole feature must close the window, not error,
// or the machine's timer would leave open sessions running.
func TestSSHWindowClosesWhenSwitchedOff(t *testing.T) {
	e := newSSHEnv(t)
	gid := e.loginGrant(t, vectorTok, "arch-omen", "192.0.2.1")
	if !e.windowOpen(t, "arch-omen", gid) {
		t.Fatal("window should be open")
	}
	if e.windowOpen(t, "nope", gid) {
		t.Fatal("unknown machine")
	}
	ca := e.srv.sshCA
	e.srv.SetSSHCA(ca, map[string]config.SSHHost{"vm204": {Address: "192.168.0.204", User: "agent"}})
	if e.windowOpen(t, "arch-omen", gid) {
		t.Fatal("machine removed from config")
	}
	e.srv.SetSSHCA(nil, nil)
	if e.windowOpen(t, "arch-omen", gid) {
		t.Fatal("feature removed from config")
	}
}

// With no ssh_ca block, secrets stored under ssh/ behave like any other secret.
func TestSSHPrefixIsOrdinaryWhenOff(t *testing.T) {
	e := newGrantEnv(t)
	seedSecret(t, e.srv, adminTok, "ssh/deploy-key", "deploy-value")
	b, _ := json.Marshal(sshSignBody{Host: "arch-omen", PublicKey: newPublicKey(t)})
	expect(t, e.do("POST", "/v1/ssh/sign", vectorTok, string(b)), http.StatusNotFound, CodeNotFound)
	expect(t, e.do("GET", "/v1/ssh/ca", "", ""), http.StatusNotFound, CodeNotFound)
	if m := expect(t, e.do("GET", "/v1/ssh/window/arch-omen/gnt_x", "", ""), http.StatusOK, ""); m["open"] != false {
		t.Fatalf("window = %v", m)
	}
	login, _ := json.Marshal(map[string]any{"paths": []string{"ssh/arch-omen"}, "action": grant.ActionSSHLogin, "reason": "x"})
	expect(t, e.do("POST", "/v1/access-requests", vectorTok, string(login)), http.StatusForbidden, CodeNotRequestable)

	id := e.request(t, vectorTok, "ssh/deploy-key")
	e.approve(t, id, "")
	if w := e.sealedGet("ssh/deploy-key", vectorTok); w.Code != http.StatusOK {
		t.Fatalf("granted secret under ssh/: %d %s", w.Code, w.Body.String())
	}
}

// A login stays tied to the IP that asked, even when secret grants are not.
func TestSSHGrantAlwaysBindsSourceIP(t *testing.T) {
	e := newSSHEnv(t)
	e.set(func(s *config.AccessRequestsSettings) { s.BindSourceIP = false })
	gid := e.loginGrant(t, vectorTok, "arch-omen", "192.0.2.1")
	if g, _ := e.store.GetGrant(gid); g.BoundSourceIP != "192.0.2.1" {
		t.Fatalf("bound ip = %q", g.BoundSourceIP)
	}
	if code, _ := e.sign(t, vectorTok, "arch-omen", "192.0.2.9"); code != http.StatusForbidden {
		t.Fatalf("signed from another IP: %d", code)
	}
}

// Under deny_paths * a secret stored under ssh/ gets the normal secret denial.
func TestSSHDenialHintsForSecretsAreUnchanged(t *testing.T) {
	e := newSSHEnv(t)
	seedSecret(t, e.srv, adminTok, "ssh/arch-omen", "planted")
	m := jsonBody(t, e.do("GET", "/v1/secrets/ssh/arch-omen", vectorTok, ""))
	if m["next_step"] == NextRequestUse {
		t.Fatalf("deny_paths * but a secret read still offers a request: %v", m)
	}
}

func TestSSHSignRejectsSessionsAndBadKeys(t *testing.T) {
	e := newSSHEnv(t)
	expect(t, e.do("POST", "/v1/ssh/sign", "", `{"host":"arch-omen"}`), http.StatusUnauthorized, "")
	const ip = "192.0.2.1"
	b, _ := json.Marshal(map[string]any{"paths": []string{"ssh/arch-omen"}, "action": grant.ActionSSHLogin, "reason": "x"})
	req := expect(t, e.do("POST", "/v1/access-requests", vectorTok, string(b), "RemoteAddr: "+ip), http.StatusCreated, "")
	e.approve(t, req["id"].(string), "")
	bad, _ := json.Marshal(sshSignBody{Host: "arch-omen", PublicKey: "not a key"})
	expect(t, e.do("POST", "/v1/ssh/sign", vectorTok, string(bad), "RemoteAddr: "+ip), http.StatusBadRequest, CodeInvalidRequest)
	if pk := expect(t, e.do("GET", "/v1/ssh/ca", "", ""), http.StatusOK, "")["public_key"].(string); !strings.HasPrefix(pk, "ssh-ed25519 ") {
		t.Fatalf("ca = %q", pk)
	}
}

// The bare server address goes to the dashboard when there is one, and stays a
// 404 when there isn't. Not SSH, but this file already has the fixture.
func TestRootGoesToDashboard(t *testing.T) {
	e := newGrantEnv(t)
	if w := e.do("GET", "/", "", ""); w.Code != http.StatusNotFound {
		t.Fatalf("no dashboard: / = %d, want 404", w.Code)
	}
	e.srv.SetDashboard(http.NotFoundHandler())
	w := e.do("GET", "/", "", "")
	if w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != "/dashboard/" {
		t.Fatalf("/ = %d to %q", w.Code, w.Header().Get("Location"))
	}
	if w := e.do("GET", "/v1/nope", "", ""); w.Code == http.StatusMovedPermanently {
		t.Fatal("only the exact root may redirect")
	}
}
