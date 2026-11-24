package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/audit"
	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/grant"
	"github.com/phoenixsec/phoenix/internal/session"
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
		if w["who"] != "robin" || w["authority"] != "night-desk" || w["kind"] != "agent" || w["host"] != "" || w["attested"] != false || fmt.Sprint(w["formerly"]) != "[helper]" {
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
	for i, c := range []struct {
		as, tok, name, body string // as, not tok, is what a failure prints
		code                int
	}{
		{"worker", "old-token", "worker", `{"who":"eve"}`, 403},
		{"session", sess, "worker", `{"who":"eve"}`, 401},
		{"admin", "admin-token", "nobody", `{"who":"x"}`, 404},
		{"admin", "admin-token", "worker", `{"host":"x"}`, 400},
		{"admin", "admin-token", "worker", `{"who":"x","token":"y"}`, 400},
		{"admin", "admin-token", "worker", `{}`, 400},
		{"admin", "admin-token", "worker", `{"who":"a\u202eb"}`, 400},
		{"admin", "admin-token", "worker", `{"who":"x"} {"who":"y"}`, 400},
		{"admin", "admin-token", "worker", `{"who":"x"} junk`, 400},
	} {
		if code, _ := e.do("PATCH", "/v1/agents/"+c.name+"/identity", c.tok, c.body); code != c.code {
			t.Errorf("case %d as %s = %d, want %d", i, c.as, code, c.code)
		}
	}
	if code, _ := e.do("PATCH", "/v1/agents/worker/identity", "admin-token", "{\"kind\":\"agent\"}\n \n"); code != 200 {
		t.Errorf("trailing white space refused: %d", code)
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

// A describe line is as full as any other: labels, session and changed fields.
func TestDescribeLineIsFull(t *testing.T) {
	e := newCredEnv(t)
	e.label(`{"who":"robin","authority":"night-desk"}`)
	sess := e.mint("old-token")
	for i, tok := range []string{"old-token", sess} {
		if code, _ := e.do("PATCH", "/v1/metadata/test/a", tok, `{"username":"u","tags":["x"]}`); code != 200 {
			t.Fatalf("describe %d: %d", i, code)
		}
		l := e.lines(audit.QueryOptions{Limit: 1})[0]
		if l.Caller != (audit.Caller{Who: "robin", Authority: "night-desk"}) || l.Agent != "worker" || l.Action != "describe" || l.Path != "test/a" ||
			l.Status != "allowed" || (l.SessionID != "") != (i == 1) || l.Metadata["changed"] != "tags,username" {
			t.Errorf("describe line %d = %+v", i, l)
		}
	}
}

// A refused identity change leaves exactly one denied line, saying who tried.
func TestRefusedSetIdentityIsAudited(t *testing.T) {
	e := newCredEnv(t)
	e.label(`{"who":"robin","authority":"night-desk"}`)
	sess := e.mint("old-token")
	for i, c := range []struct {
		tok, reason string
		code        int
	}{{"old-token", "acl", 403}, {sess, "session", 401}} {
		before := len(e.lines(audit.QueryOptions{}))
		if code, _ := e.do("PATCH", "/v1/agents/admin/identity", c.tok, `{"who":"eve"}`); code != c.code {
			t.Fatalf("%s: %d, want %d", c.reason, code, c.code)
		}
		got := e.lines(audit.QueryOptions{})[before:]
		if len(got) != 1 {
			t.Fatalf("%s: %d lines, want 1", c.reason, len(got))
		}
		l := got[0]
		if l.Action != "set-identity" || l.Status != "denied" || l.Reason != c.reason || l.Agent != "worker" || l.Path != "admin" || l.IP == "" ||
			l.Caller != (audit.Caller{Who: "robin", Authority: "night-desk"}) || (l.SessionID != "") != (i == 1) {
			t.Errorf("%s: line = %+v", c.reason, l)
		}
	}
	if a, _ := e.srv.acl.GetAgent("admin"); a.Who != "" {
		t.Error("a refused change was made")
	}
}

// Grant events go through the grant store's audit sink, not a request. They
// carry the labels the actor had when it acted, also when the line is written
// later, after a restart, with another identity under that name.
func TestGrantLinesCarryIdentity(t *testing.T) {
	var e *grantEnv
	full := false
	opts := func(o *grant.Options) {
		sink := o.Audit
		o.Audit = sinkFunc(func(ev grant.Event) error {
			if full && ev.Phase == grant.PhaseCommitted {
				return errors.New("disk full")
			}
			return sink.Append(ev)
		})
	}
	e = newGrantEnv(t, opts)
	label := func(name, body string) {
		expect(t, e.do("PATCH", "/v1/agents/"+name+"/identity", adminTok, body), 200, "")
	}
	// Real identities may have names like Phoenix's own actors.
	for _, n := range []string{"system", "dashboard@desk"} {
		if err := e.srv.acl.AddAgent(n, n+"-token", nil); err != nil {
			t.Fatal(err)
		}
	}
	label("courier", `{"who":"robin"}`)
	label("approver", `{"who":"sam","authority":"boss"}`)
	label("system", `{"who":"sys"}`)
	label("dashboard@desk", `{"who":"desk"}`)
	e.set(func(s *config.AccessRequestsSettings) {
		s.Approvers = []string{"approver", "dashboard@desk"}
		s.RequireSealed = false
	})

	full = true
	first := e.request(t, courierTok, "infra/b2/app-key")
	e.approve(t, first, "{}")
	label("courier", `{"who":"eve"}`)
	if err := e.srv.acl.RemoveAgent("approver"); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.acl.AddAgentLabeled("approver", approverTok, nil, acl.LabelChange{Who: &[]string{"mallory"}[0]}); err != nil {
		t.Fatal(err)
	}
	full = false
	o := grant.Options{Path: filepath.Join(e.dir, "grants.json"), Audit: NewGrantAuditSink(e.srv.audit), Now: e.clock.Now, Logf: t.Logf}
	opts(&o)
	st, err := grant.Open(o) // a restart: the queued lines are written now
	if err != nil {
		t.Fatal(err)
	}
	e.store = st
	e.srv.SetGrantStore(st)
	st.Tick()

	byName := e.request(t, "system-token", "infra/other")
	expect(t, e.do("POST", "/v1/access-requests/"+byName+"/approve", "dashboard@desk-token", "{}"), 200, "")
	late := e.request(t, courierTok, "infra/other")
	if _, _, err := e.srv.ApproveAccessRequestAs(late, "dashboard@10.0.0.9", "10.0.0.9", grant.Approval{}); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(24 * time.Hour)
	st.Tick() // expires the grants, as "system" itself

	got := map[string]map[audit.Caller]bool{}
	es, err := audit.Query(e.srv.auditPath, audit.QueryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range es {
		if k := l.Agent + " " + l.Action; strings.HasPrefix(l.Action, "access_request.") || strings.HasPrefix(l.Action, "grant.") {
			if got[k] == nil {
				got[k] = map[audit.Caller]bool{}
			}
			got[k][l.Caller] = true
		}
	}
	for k, want := range map[string][]audit.Caller{
		"courier access_request.created":             {{Who: "robin"}, {Who: "eve"}},
		"approver access_request.approved":           {{Who: "sam", Authority: "boss"}},
		"system access_request.created":              {{Who: "sys"}},
		"dashboard@desk access_request.approved":     {{Who: "desk"}},
		"dashboard@10.0.0.9 access_request.approved": {{}},
		"system grant.expired":                       {{}},
	} {
		set := map[audit.Caller]bool{}
		for _, c := range want {
			set[c] = true
		}
		if !reflect.DeepEqual(got[k], set) {
			t.Errorf("%s = %v, want %v", k, got[k], set)
		}
	}
}

// A grant line has the labels its caller was authenticated with, whatever
// happens to the identity while the request is handled, and every line of one
// deletion has the same. A bearer identity called exactly what the dashboard
// is called keeps its own.
func TestGrantLinesUseAuthenticatedLabels(t *testing.T) {
	e := newGrantEnv(t)
	set := func(name, who string) {
		if _, err := e.srv.acl.SetLabels(name, acl.LabelChange{Who: &who}); err != nil {
			t.Fatal(err)
		}
	}
	// slow sends a request whose identity is relabeled while the body is read.
	slow := func(tok, name, method, path, body string) {
		t.Helper()
		set(name, "before")
		read := false
		req := httptest.NewRequest(method, path, readerFunc(func(p []byte) (int, error) {
			if read {
				return 0, io.EOF
			}
			read = true
			set(name, "after")
			return copy(p, body), nil
		}))
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		e.srv.ServeHTTP(w, req)
		if w.Code >= 300 || !read {
			t.Fatalf("%s %s = %d, body read %v", method, path, w.Code, read)
		}
	}
	twin := "dashboard@192.0.2.1" // httptest's client address
	if err := e.srv.acl.AddAgent(twin, "twin-token", nil); err != nil {
		t.Fatal(err)
	}
	e.set(func(s *config.AccessRequestsSettings) {
		s.Approvers = []string{"approver", twin}
		s.RequireSealed = false
	})
	slow(courierTok, "courier", "POST", "/v1/access-requests", `{"paths":["infra/b2/app-key"],"reason":"r","ttl":"30m"}`)
	id := e.store.ListRequests("courier", grant.StatusPending)[0].ID
	slow(approverTok, "approver", "POST", "/v1/access-requests/"+id+"/approve", "{}")
	slow(approverTok, "approver", "POST", "/v1/access-requests/"+e.request(t, courierTok, "infra/other")+"/deny", "{}")

	set(twin, "desk")
	asked := e.request(t, courierTok, "infra/x")
	expect(t, e.do("POST", "/v1/access-requests/"+asked+"/approve", "twin-token", "{}"), 200, "")
	asked = e.request(t, courierTok, "infra/y")
	if _, _, err := e.srv.ApproveAccessRequestAs(asked, twin, "192.0.2.1", grant.Approval{}); err != nil {
		t.Fatal(err)
	}
	e.request(t, courierTok, "infra/z") // pending, so deleting writes all three kinds
	set("admin", "boss")
	expect(t, e.do("DELETE", "/v1/agents/courier", adminTok, ""), 200, "")

	es, err := audit.Query(e.srv.auditPath, audit.QueryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var twins, deleted []string
	for _, l := range es {
		switch {
		case l.Metadata["request_id"] == id || l.Action == "access_request.denied":
			if l.Agent != "admin" && l.Who != "before" {
				t.Errorf("%s by %s: who %q", l.Action, l.Agent, l.Who)
			}
		case l.Agent == twin && l.Action == "access_request.approved":
			twins = append(twins, l.Who)
		}
		if l.Agent == "admin" && l.Metadata["event_id"] != "" {
			deleted = append(deleted, l.Action+" "+l.Who)
		}
	}
	if fmt.Sprint(twins) != "[desk ]" {
		t.Errorf("bearer then dashboard = %q", twins)
	}
	if len(deleted) < 6 {
		t.Errorf("deletion lines = %q", deleted)
	}
	for _, d := range deleted {
		if !strings.HasSuffix(d, " boss") {
			t.Errorf("deletion line %q", d)
		}
	}
}

// readerFunc is an io.Reader made of a function.
type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// sinkFunc is a grant.AuditSink made of a function.
type sinkFunc func(grant.Event) error

func (f sinkFunc) Append(e grant.Event) error { return f(e) }

// A line Phoenix writes as "system" never borrows the labels of an identity
// that happens to be called system.
func TestSystemLineBorrowsNoLabels(t *testing.T) {
	e := newCredEnv(t)
	r := withRequestCaller(httptest.NewRequest("POST", "/v1/session/renew", nil))
	identifyCaller(r, &authInfo{Agent: "system"}, acl.Labels{Who: "sys"})
	e.srv.auditEndedSessions(r, systemActor, "1.1.1.1", "credential_not_current", []*session.Session{{ID: "ses_0", Agent: "system"}})
	if got := e.lines(audit.QueryOptions{Path: "ses_0"}); len(got) != 1 || got[0].Agent != "system" || got[0].Caller != (audit.Caller{}) {
		t.Fatalf("lines = %+v", got)
	}
}

// A change that is in use but whose save was not synced answers 500 and is
// still in the log.
func TestUnsyncedLabelChangeIsAudited(t *testing.T) {
	e := newCredEnv(t)
	if os.Geteuid() == 0 {
		t.Skip("root can read any directory")
	}
	// Files in a directory that cannot be read can be replaced, but the last
	// step of a save, syncing the directory, fails.
	if err := os.Chmod(e.dir, 0300); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(e.dir, 0700)
	if code, _ := e.do("PATCH", "/v1/agents/worker/identity", "admin-token", `{"who":"robin"}`); code != 500 {
		t.Errorf("set-identity = %d, want 500", code)
	}
	es := e.lines(audit.QueryOptions{Agent: "admin", Limit: 1})
	if es[0].Action != "set-identity" || es[0].Reason != "saved_not_synced" || es[0].Metadata["identity.who"] == "" {
		t.Errorf("line = %+v", es[0])
	}
}

// The log keeps one former name with a comma apart from two names.
func TestFormerNamesUnambiguousInLog(t *testing.T) {
	e := newCredEnv(t)
	e.label(`{"formerly":["a,b"]}`)
	one := e.lines(audit.QueryOptions{Agent: "admin", Limit: 1})[0].Metadata["identity.formerly"]
	e.label(`{"formerly":["a","b"]}`)
	two := e.lines(audit.QueryOptions{Agent: "admin", Limit: 1})[0].Metadata["identity.formerly"]
	if one != `["a,b"]` || two != `["a","b"]` {
		t.Fatalf("one = %s, two = %s", one, two)
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
		var r struct {
			Entries         []audit.Entry
			IdentityFilters bool `json:"identity_filters"`
		}
		if err := json.Unmarshal([]byte(body), &r); err != nil {
			t.Fatal(err)
		}
		if !r.IdentityFilters {
			t.Errorf("%s: identity_filters missing", q)
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
