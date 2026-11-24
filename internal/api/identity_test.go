package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/phoenixsec/phoenix/internal/audit"
)

// lines returns the audit lines matching o, oldest first.
func (e *credEnv) lines(o audit.QueryOptions) []audit.Entry {
	e.t.Helper()
	es, err := audit.Query(filepath.Join(e.dir, "audit.log"), o)
	if err != nil {
		e.t.Fatal(err)
	}
	return es
}

// label sets the worker's labels as an admin does.
func (e *credEnv) label(body string) {
	e.t.Helper()
	if code, out := e.do("PATCH", "/v1/agents/worker/identity", "admin-token", body); code != 200 {
		e.t.Fatalf("set identity: %d %s", code, out)
	}
}

// Setting labels on an identity in use ends no session, changes no token or
// permission, shows in whoami and survives a restart.
func TestSetIdentityKeepsTokenAndSessions(t *testing.T) {
	e := newCredEnv(t)
	sess := e.mint("old-token")
	e.label(`{"who":"robin","authority":"night-desk","kind":"agent","formerly":["helper"]}`)
	e.wantAlive("after set", sess)
	e.start()
	e.wantAlive("after a restart", sess)
	for _, tok := range []string{"old-token", sess} {
		_, body := e.do("GET", "/v1/whoami", tok, "")
		var w map[string]any
		json.Unmarshal([]byte(body), &w)
		if w["who"] != "robin" || w["authority"] != "night-desk" || w["kind"] != "agent" || w["host"] != "" || w["attested"] != false {
			t.Errorf("whoami = %s", body)
		}
	}
	if strings.Contains(fmt.Sprint(e.do("GET", "/v1/agents", "admin-token", "")), "serial") {
		t.Error("the serial is shown")
	}
	set := e.lines(audit.QueryOptions{Path: "worker"})
	last := set[len(set)-1]
	if last.Action != "set-identity" || last.Agent != "admin" || last.Metadata["identity.who"] != "robin" || last.Metadata["identity.changed"] != "who,authority,kind,formerly" {
		t.Errorf("set-identity line = %+v", last)
	}

	// Only an admin's own token may, and nothing outside the four fields.
	for _, c := range []struct {
		tok, name, body string
		code            int
	}{
		{"old-token", "worker", `{"who":"eve"}`, 403},
		{sess, "worker", `{"who":"eve"}`, 401},
		{"admin-token", "nobody", `{"who":"x"}`, 404},
		{"admin-token", "worker", `{"host":"x"}`, 400},
		{"admin-token", "worker", `{"who":"x","token":"y"}`, 400},
		{"admin-token", "worker", `{}`, 400},
		{"admin-token", "worker", `{"who":"a\u202eb"}`, 400},
	} {
		if code, body := e.do("PATCH", "/v1/agents/"+c.name+"/identity", c.tok, c.body); code != c.code {
			t.Errorf("%s by %s = %d %s, want %d", c.body, c.tok, code, body, c.code)
		}
	}
	if a, _ := e.srv.acl.GetAgent("worker"); a.Who != "robin" {
		t.Errorf("who = %q after refused changes", a.Who)
	}
}

// Every line about an authenticated caller carries its labels, allowed or
// denied, token or session, and a line about nobody in particular does not.
func TestAuditLinesCarryIdentity(t *testing.T) {
	e := newCredEnv(t)
	e.label(`{"who":"robin","authority":"night-desk"}`)
	sess := e.mint("old-token")
	for _, tok := range []string{"old-token", sess} {
		e.do("GET", "/v1/secrets/test/a", tok, "")
		e.do("GET", "/v1/secrets/other/x", tok, "")
		e.do("GET", "/v1/metadata/test/", tok, "")
		e.do("POST", "/v1/resolve", tok, `{"refs":["phoenix://test/a","phoenix://other/x"]}`)
		e.do("PUT", "/v1/secrets/test/b", tok, `{"value":"synthetic"}`)
		e.do("DELETE", "/v1/secrets/test/b", tok, "")
		e.do("GET", "/v1/ssh/machines", tok, "")
	}
	e.do("POST", "/v1/session/mint", "old-token", `{"role":"nope"}`)
	e.do("POST", "/v1/session/renew", sess, "{}")
	want := audit.Caller{Who: "robin", Authority: "night-desk"}
	got := e.lines(audit.QueryOptions{Agent: "worker"})
	if len(got) < 14 {
		t.Fatalf("only %d lines", len(got))
	}
	for _, l := range got {
		if l.Caller != want {
			t.Errorf("%s %s %s: caller %+v", l.Action, l.Path, l.Status, l.Caller)
		}
	}

	// A refused credential proves nothing, so its line borrows no labels. Nor
	// does a line by another actor about this identity.
	e.create("new-token", true)
	e.do("GET", "/v1/whoami", sess, "")
	for _, l := range e.lines(audit.QueryOptions{}) {
		if (l.Agent != "worker" || l.Action == "session.auth") && l.Caller != (audit.Caller{}) {
			t.Errorf("%s by %s: caller %+v", l.Action, l.Agent, l.Caller)
		}
	}
	// The labels outlived the token change.
	e.do("GET", "/v1/secrets/test/a", "new-token", "")
	got = e.lines(audit.QueryOptions{Agent: "worker", Limit: 1})
	if got[0].Caller != want {
		t.Errorf("after a token change: %+v", got[0])
	}
}

// Grant events go through the grant store's audit sink, not a request.
func TestGrantLinesCarryIdentity(t *testing.T) {
	e := newGrantEnv(t)
	for name, body := range map[string]string{"vector": `{"who":"robin"}`, "approver": `{"who":"sam","authority":"boss"}`} {
		expect(t, e.do("PATCH", "/v1/agents/"+name+"/identity", adminTok, body), 200, "")
	}
	id := e.request(t, vectorTok, "infra/b2/app-key")
	expect(t, e.do("POST", "/v1/access-requests/"+id+"/approve", approverTok, "{}"), 200, "")
	seen := map[string]audit.Caller{}
	es, err := audit.Query(e.srv.auditPath, audit.QueryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range es {
		seen[l.Action] = l.Caller
	}
	if seen["access_request.created"] != (audit.Caller{Who: "robin"}) || seen["access_request.approved"] != (audit.Caller{Who: "sam", Authority: "boss"}) {
		t.Fatalf("grant lines = %v", seen)
	}
}

// sessionIDs matches what differs between two runs.
var sessionIDs = regexp.MustCompile(`ses_[0-9a-f]+`)

// Attack: a caller that states its own who, host, authority or attested, in
// headers, query or body, changes nothing. Every answer and every audit line
// is the same as without.
func TestCallerCannotSetItsOwnIdentity(t *testing.T) {
	names := []string{"who", "host", "authority", "kind", "attested", "identity", "agent", "formerly"}
	run := func(attack bool) string {
		e := newCredEnv(t)
		e.label(`{"who":"robin","authority":"night-desk"}`)
		sess := e.mint("old-token")
		var out strings.Builder
		send := func(tok, method, path, body string) {
			req := httptest.NewRequest(method, path, strings.NewReader(body))
			req.RemoteAddr = "127.0.0.1:1234"
			req.Header.Set("Authorization", "Bearer "+tok)
			if attack {
				for _, n := range names {
					for _, h := range []string{n, "X-" + n, "X-Phoenix-" + n} {
						req.Header.Set(h, "evil")
					}
				}
				req.Header.Set("X-Forwarded-Host", "evil")
				req.Header.Set("X-Forwarded-For", "6.6.6.6")
				req.Host = "evil"
				q := req.URL.Query()
				for _, n := range names {
					q.Set(n, "evil")
				}
				req.URL.RawQuery = q.Encode()
				if body != "" {
					extra := `"who":"evil","host":"evil","authority":"evil","attested":true,"identity":{"who":"evil"},`
					req.Body = io.NopCloser(strings.NewReader(strings.Replace(body, "{", "{"+extra, 1)))
				}
			}
			w := httptest.NewRecorder()
			e.srv.ServeHTTP(w, req)
			b := ""
			if path == "/v1/whoami" { // the other answers hold times, values or tokens
				b = w.Body.String()
			}
			fmt.Fprintln(&out, method, path, w.Code, b)
		}
		for _, tok := range []string{"old-token", sess} {
			send(tok, "GET", "/v1/whoami", "")
			send(tok, "GET", "/v1/secrets/test/a", "")
			send(tok, "GET", "/v1/secrets/other/x", "")
			send(tok, "PUT", "/v1/secrets/test/b", `{"value":"synthetic"}`)
			send(tok, "POST", "/v1/resolve", `{"refs":["phoenix://test/a","phoenix://other/x"]}`)
			send(tok, "POST", "/v1/session/mint", `{"role":"dev"}`)
			send(tok, "GET", "/v1/agents", "")
		}
		send("bad-token", "GET", "/v1/whoami", "")
		for _, l := range e.lines(audit.QueryOptions{}) {
			fmt.Fprintf(&out, "%s|%s|%s|%s|%s|%s|%+v|%v\n", l.Agent, l.Action, l.Path, l.Status, l.IP, l.Reason, l.Caller, l.Metadata)
		}
		return sessionIDs.ReplaceAllString(out.String(), "ses_")
	}
	plain, attacked := run(false), run(true)
	if plain != attacked {
		t.Fatalf("the caller's own words changed something.\nwithout:\n%s\nwith:\n%s", plain, attacked)
	}
	if strings.Contains(attacked, "evil") || !strings.Contains(attacked, "robin") {
		t.Fatalf("unexpected log:\n%s", attacked)
	}
}

// GET /v1/audit filters by the new fields, and by name finds former names.
func TestAuditQueryByIdentity(t *testing.T) {
	e := newCredEnv(t)
	e.do("GET", "/v1/secrets/test/a", "old-token", "") // before any label
	if code, body := e.do("POST", "/v1/agents", "admin-token",
		`{"name":"desk","token":"desk-token","permissions":`+workerACL+`,"who":"robin","authority":"night-desk","formerly":["worker"]}`); code != 200 {
		t.Fatalf("create: %d %s", code, body)
	}
	e.do("GET", "/v1/secrets/test/a", "desk-token", "")
	count := func(q string) int {
		_, body := e.do("GET", "/v1/audit?"+q, "admin-token", "")
		var r struct{ Entries []audit.Entry }
		if err := json.Unmarshal([]byte(body), &r); err != nil {
			t.Fatal(err)
		}
		return len(r.Entries)
	}
	for q, want := range map[string]int{
		"who=robin": 1, "who=nobody": 0, "authority=night-desk&who=robin": 1, "host=x": 0,
		"agent=worker": 1, "agent=desk": 2, "agent=desk&who=robin": 1,
	} {
		if got := count(q); got != want {
			t.Errorf("%s = %d lines, want %d", q, got, want)
		}
	}
}
