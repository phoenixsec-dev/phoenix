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

func (e *grantEnv) windowOpen(t *testing.T, host string) bool {
	t.Helper()
	return expect(t, e.do("GET", "/v1/ssh/window/"+host, "", ""), http.StatusOK, "")["open"].(bool)
}

func TestSSHLoginFlow(t *testing.T) {
	e := newSSHEnv(t)
	const ip = "192.168.0.155"
	if e.windowOpen(t, "arch-omen") {
		t.Fatal("window open before any approval")
	}
	code, m := e.sign(t, vectorTok, "arch-omen", ip)
	if code != http.StatusForbidden || m["code"] != CodeSSHGrantRequired || m["next_step"] != NextRequestUse {
		t.Fatalf("before approval: %d %v", code, m)
	}

	b, _ := json.Marshal(map[string]any{"paths": []string{"ssh/arch-omen"}, "reason": "deploy firewall", "ttl": "15m"})
	req := expect(t, e.do("POST", "/v1/access-requests", vectorTok, string(b), "RemoteAddr: "+ip), http.StatusCreated, "")
	gid := e.approve(t, req["id"].(string), "")
	if !e.windowOpen(t, "arch-omen") || e.windowOpen(t, "vm204") {
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
	if !strings.Contains(cert.KeyId, "agent=vector") || !strings.Contains(cert.KeyId, gid) {
		t.Fatalf("key id %q must name the agent and grant", cert.KeyId)
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
	if e.windowOpen(t, "arch-omen") {
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
	b, _ := json.Marshal(map[string]any{"paths": []string{"ssh/arch-omen"}, "reason": "x", "ttl": "5m"})
	req := expect(t, e.do("POST", "/v1/access-requests", vectorTok, string(b), "RemoteAddr: "+ip), http.StatusCreated, "")
	e.approve(t, req["id"].(string), "")
	e.clock.Advance(6 * time.Minute)
	if e.windowOpen(t, "arch-omen") {
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
	b, _ := json.Marshal(map[string]any{"paths": []string{"ssh/arch-omen"}, "reason": "x"})
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
		b, _ := json.Marshal(map[string]any{"paths": paths, "reason": "x"})
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

// A login grant must not read a secret that happens to sit at the same path.
func TestSSHGrantNeverOpensASecret(t *testing.T) {
	e := newSSHEnv(t)
	seedSecret(t, e.srv, adminTok, "ssh/arch-omen", "planted")
	const ip = "192.0.2.1"
	b, _ := json.Marshal(map[string]any{"paths": []string{"ssh/arch-omen"}, "reason": "x"})
	req := expect(t, e.do("POST", "/v1/access-requests", vectorTok, string(b), "RemoteAddr: "+ip), http.StatusCreated, "")
	e.approve(t, req["id"].(string), "")
	if w := e.do("GET", "/v1/secrets/ssh/arch-omen", vectorTok, "", "RemoteAddr: "+ip); w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "planted") {
		t.Fatalf("read through a login grant: %d %s", w.Code, w.Body.String())
	}
}

func TestSSHEndpointsWhenOff(t *testing.T) {
	e := newGrantEnv(t)
	b, _ := json.Marshal(sshSignBody{Host: "arch-omen", PublicKey: newPublicKey(t)})
	expect(t, e.do("POST", "/v1/ssh/sign", vectorTok, string(b)), http.StatusNotFound, CodeNotFound)
	expect(t, e.do("GET", "/v1/ssh/ca", "", ""), http.StatusNotFound, CodeNotFound)
	expect(t, e.do("GET", "/v1/ssh/window/arch-omen", "", ""), http.StatusNotFound, CodeNotFound)
	bb, _ := json.Marshal(map[string]any{"paths": []string{"ssh/arch-omen"}, "reason": "x"})
	expect(t, e.do("POST", "/v1/access-requests", vectorTok, string(bb)), http.StatusForbidden, CodeNotRequestable)
}

func TestSSHSignRejectsSessionsAndBadKeys(t *testing.T) {
	e := newSSHEnv(t)
	expect(t, e.do("POST", "/v1/ssh/sign", "", `{"host":"arch-omen"}`), http.StatusUnauthorized, "")
	const ip = "192.0.2.1"
	b, _ := json.Marshal(map[string]any{"paths": []string{"ssh/arch-omen"}, "reason": "x"})
	req := expect(t, e.do("POST", "/v1/access-requests", vectorTok, string(b), "RemoteAddr: "+ip), http.StatusCreated, "")
	e.approve(t, req["id"].(string), "")
	bad, _ := json.Marshal(sshSignBody{Host: "arch-omen", PublicKey: "not a key"})
	expect(t, e.do("POST", "/v1/ssh/sign", vectorTok, string(bad), "RemoteAddr: "+ip), http.StatusBadRequest, CodeInvalidRequest)
	if pk := expect(t, e.do("GET", "/v1/ssh/ca", "", ""), http.StatusOK, "")["public_key"].(string); !strings.HasPrefix(pk, "ssh-ed25519 ") {
		t.Fatalf("ca = %q", pk)
	}
}
