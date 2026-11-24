package grant

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"
)

// fakeACL is an access list in memory that survives a "restart" (reopen).
type fakeACL struct {
	mu    sync.Mutex
	rules map[string][]string // request -> paths
	tok   map[string]string   // agent -> credential fingerprint now
	fail  error               // Add fails with this
	clear error               // Clear fails with this, rules gone from memory
	hook  func()              // runs inside Add after the rules landed
}

func newFakeACL() *fakeACL {
	return &fakeACL{rules: map[string][]string{}, tok: map[string]string{"vector": "fp-vector"}}
}

func (f *fakeACL) Add(agent, fp, requestID, by string, at time.Time, paths []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	if f.tok[agent] != fp {
		return newErr(CodeCredentialChanged, "token changed")
	}
	f.rules[requestID] = slices.Clone(paths)
	if f.hook != nil {
		f.hook()
	}
	return nil
}

func (f *fakeACL) Clear(requestID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.rules, requestID)
	return f.clear
}

func (f *fakeACL) RequestIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for id := range f.rules {
		out = append(out, id)
	}
	return out
}

func alwaysEnv(t *testing.T) (*env, *fakeACL) {
	e, a := newEnv(t), newFakeACL()
	e.always = a
	e.reopen()
	return e, a
}

func alwaysIn(id string) AlwaysInput {
	return AlwaysInput{RequestID: id, Approver: "dashboard@10.0.0.9", ApproverIP: "10.0.0.9"}
}

func TestApproveAlways(t *testing.T) {
	e, acl := alwaysEnv(t)
	r := e.create("vector", "infra/a", "infra/b")
	in := alwaysIn(r.ID)
	in.Paths = []string{"infra/a"}
	got, err := e.s.ApproveAlways(in)
	if err != nil || got.Status != StatusApproved || !got.Always || !slices.Equal(got.GrantedPaths, []string{"infra/a"}) {
		t.Fatalf("%+v %v", got, err)
	}
	if !slices.Equal(acl.rules[r.ID], []string{"infra/a"}) || len(e.s.ListGrants("", true)) != 0 {
		t.Fatalf("rules = %v", acl.rules)
	}
	e.reopen()
	if len(acl.rules) != 1 {
		t.Fatal("restart dropped approved access")
	}
	// Repeated: same answer, nothing added (even if it was removed since).
	delete(acl.rules, r.ID)
	if _, err := e.s.ApproveAlways(in); err != nil || len(acl.rules) != 0 {
		t.Fatalf("repeat: %v rules %v", err, acl.rules)
	}
	// Any other answer is too late.
	in.Paths = nil
	_, err = e.s.ApproveAlways(in)
	wantCode(t, err, CodeNotPending)
	_, _, err = e.s.Approve(approveIn(r.ID))
	wantCode(t, err, CodeNotPending)
	if e.sink.count(EventRequestApproved) == 0 {
		t.Fatal("not audited")
	}
}

func TestApproveAlwaysRefusals(t *testing.T) {
	e, acl := alwaysEnv(t)
	r := e.create("vector", "infra/a")
	try := func(want Code, in AlwaysInput) {
		t.Helper()
		_, err := e.s.ApproveAlways(in)
		wantCode(t, err, want)
		if len(acl.rules) != 0 {
			t.Fatalf("%s left access behind", want)
		}
	}
	wide := alwaysIn(r.ID)
	wide.Paths = []string{"infra/b"}
	try(CodeWideningNotAllowed, wide)
	glob := alwaysIn(r.ID)
	glob.Paths = []string{"infra/*"}
	try(CodeInvalidRequest, glob)
	self := alwaysIn(r.ID)
	self.Approver = "vector"
	try(CodeSelfApproval, self)
	acl.tok["vector"] = "fp-other"
	try(CodeCredentialChanged, alwaysIn(r.ID))
	acl.tok["vector"] = "fp-vector"
	acl.fail = errors.New("disk full")
	try(CodeACLWriteFailed, alwaysIn(r.ID))
	acl.fail = nil
	e.setGone("vector", true)
	try(CodeUnknownAgent, alwaysIn(r.ID))
	e.setGone("vector", false)
	if _, err := e.s.Deny(DenyInput{RequestID: r.ID, Denier: "dashboard@x"}); err != nil {
		t.Fatal(err)
	}
	try(CodeNotPending, alwaysIn(r.ID))

	login := bearerIn("vector", "ssh/build-1")
	login.Action = ActionSSHLogin
	lr, _, err := e.s.Create(login)
	if err != nil {
		t.Fatal(err)
	}
	try(CodeAlwaysNotAllowed, alwaysIn(lr.ID))
	late := e.create("vector", "infra/late")
	e.clock.Advance(DefaultRequestTTL)
	try(CodeNotPending, alwaysIn(late.ID))
}

// grants.json cannot be saved after the access list was: the access goes again.
func TestApproveAlwaysSaveFailureTakesAccessBack(t *testing.T) {
	for _, step := range []string{"write", "fsync", "rename", "dirsync"} {
		e, acl := alwaysEnv(t)
		r := e.create("vector", "infra/a")
		acl.hook = func() { e.fs.failOnce(step) }
		_, err := e.s.ApproveAlways(alwaysIn(r.ID))
		wantCode(t, err, CodeStoreWriteFailed)
		acl.hook = nil
		if len(acl.rules) != 0 {
			t.Fatalf("%s: access stayed after a failed answer", step)
		}
		e.reopen()
		if got, _ := e.s.GetRequest(r.ID); got.Status != StatusPending {
			t.Fatalf("%s: request %s", step, got.Status)
		}
		if _, err := e.s.ApproveAlways(alwaysIn(r.ID)); err != nil {
			t.Fatalf("%s: answering again: %v", step, err)
		}
	}
}

// The server dies after the access list was saved and before grants.json.
func TestRestartBetweenAccessListAndGrants(t *testing.T) {
	e, acl := alwaysEnv(t)
	r := e.create("vector", "infra/a")
	gone := e.create("vector", "infra/b")
	acl.rules[r.ID] = []string{"infra/a"}
	acl.rules["req_pruned"] = []string{"infra/z"} // answered long ago
	if _, err := e.s.Deny(DenyInput{RequestID: gone.ID, Denier: "dashboard@x"}); err != nil {
		t.Fatal(err)
	}
	acl.rules[gone.ID] = []string{"infra/b"} // came back with an old acl.json
	e.reopen()
	if acl.rules[r.ID] != nil || acl.rules[gone.ID] != nil || acl.rules["req_pruned"] == nil {
		t.Fatalf("rules after restart: %v", acl.rules)
	}
	if got, _ := e.s.GetRequest(r.ID); got.Status != StatusPending {
		t.Fatalf("request %s", got.Status)
	}
	// A lost or unreadable grants.json proves nothing, so access stays.
	acl.rules[r.ID] = []string{"infra/a"}
	e.path += ".other"
	e.reopen()
	if acl.rules[r.ID] == nil {
		t.Fatal("access removed on no evidence")
	}
}

// Access left by a half-done "always" goes with every narrower outcome.
func TestLeftoverAccessGoesWithAnyOtherAnswer(t *testing.T) {
	e, acl := alwaysEnv(t)
	left := func(path string) Request {
		r := e.create("vector", path)
		acl.rules[r.ID] = []string{path}
		return r
	}
	r := left("infra/a")
	if _, err := e.s.Deny(DenyInput{RequestID: r.ID, Denier: "dashboard@x"}); err != nil || len(acl.rules) != 0 {
		t.Fatalf("deny: %v %v", err, acl.rules)
	}
	r = left("infra/b")
	if _, _, err := e.s.Approve(approveIn(r.ID)); err != nil || len(acl.rules) != 0 {
		t.Fatalf("approve: %v %v", err, acl.rules)
	}
	// A narrower yes must not count while the wider access might return.
	r = left("infra/c")
	acl.clear = errors.New("disk full")
	_, _, err := e.s.Approve(approveIn(r.ID))
	wantCode(t, err, CodeACLWriteFailed)
	acl.clear = nil
	acl.rules[r.ID] = []string{"infra/c"}
	e.clock.Advance(DefaultRequestTTL)
	e.s.Tick()
	if len(acl.rules) != 0 {
		t.Fatalf("expiry left %v", acl.rules)
	}
}
