package grant

import (
	"errors"
	"maps"
	"slices"
	"sync"
	"testing"
	"time"
)

// fakeACL is an access list in memory that survives a "restart" (reopen).
// staged rules allow nothing; live ones are what an agent could read.
type fakeACL struct {
	mu     sync.Mutex
	staged map[string][]string // request -> paths
	live   map[string][]string
	tok    map[string]string // agent -> credential fingerprint now
	fail   error             // Stage fails with this
	drop   error             // Drop fails with this and drops nothing
	finish error             // Finish fails with this
	hook   func()            // runs inside Stage after the rules landed
}

func newFakeACL() *fakeACL {
	return &fakeACL{staged: map[string][]string{}, live: map[string][]string{}, tok: map[string]string{"courier": "fp-courier"}}
}

func (f *fakeACL) check(r Request) error {
	if f.tok[r.Agent] != r.CredentialFP {
		return newErr(CodeCredentialChanged, "token changed")
	}
	return nil
}

func (f *fakeACL) Stage(r Request, by string, at time.Time, paths []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	if err := f.check(r); err != nil {
		return err
	}
	f.staged[r.ID] = slices.Clone(paths)
	if f.hook != nil {
		f.hook()
	}
	return nil
}

func (f *fakeACL) Finish(r Request) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(r); err != nil {
		return err
	}
	if f.finish != nil {
		return f.finish
	}
	if paths, ok := f.staged[r.ID]; ok {
		f.live[r.ID] = paths
		delete(f.staged, r.ID)
	}
	return nil
}

func (f *fakeACL) Drop(requestID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.drop != nil {
		return f.drop
	}
	delete(f.staged, requestID)
	return nil
}

func (f *fakeACL) Staged() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Collect(maps.Keys(f.staged))
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
	r := e.create("courier", "infra/a", "infra/b")
	in := alwaysIn(r.ID)
	in.Paths = []string{"infra/a"}
	got, err := e.s.ApproveAlways(in)
	if err != nil || got.Status != StatusApproved || !got.Always || !slices.Equal(got.GrantedPaths, []string{"infra/a"}) {
		t.Fatalf("%+v %v", got, err)
	}
	if !slices.Equal(acl.live[r.ID], []string{"infra/a"}) || len(acl.staged) != 0 || len(e.s.ListGrants("", true)) != 0 {
		t.Fatalf("live = %v staged = %v", acl.live, acl.staged)
	}
	e.reopen()
	if len(acl.live) != 1 {
		t.Fatal("restart dropped approved access")
	}
	// Repeated: same answer, nothing added (even if it was removed since).
	delete(acl.live, r.ID)
	if _, err := e.s.ApproveAlways(in); err != nil || len(acl.live)+len(acl.staged) != 0 {
		t.Fatalf("repeat: %v live %v", err, acl.live)
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
	r := e.create("courier", "infra/a")
	try := func(want Code, in AlwaysInput) {
		t.Helper()
		_, err := e.s.ApproveAlways(in)
		wantCode(t, err, want)
		if len(acl.live)+len(acl.staged) != 0 {
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
	self.Approver = "courier"
	try(CodeSelfApproval, self)
	acl.tok["courier"] = "fp-other"
	try(CodeCredentialChanged, alwaysIn(r.ID))
	acl.tok["courier"] = "fp-courier"
	acl.fail = errors.New("disk full")
	try(CodeACLWriteFailed, alwaysIn(r.ID))
	acl.fail = nil
	e.setGone("courier", true)
	try(CodeUnknownAgent, alwaysIn(r.ID))
	e.setGone("courier", false)
	if _, err := e.s.Deny(DenyInput{RequestID: r.ID, Denier: "dashboard@x"}); err != nil {
		t.Fatal(err)
	}
	try(CodeNotPending, alwaysIn(r.ID))

	login := bearerIn("courier", "ssh/build-1")
	login.Action = ActionSSHLogin
	lr, _, err := e.s.Create(login)
	if err != nil {
		t.Fatal(err)
	}
	try(CodeAlwaysNotAllowed, alwaysIn(lr.ID))
	late := e.create("courier", "infra/late")
	e.clock.Advance(DefaultRequestTTL)
	try(CodeNotPending, alwaysIn(late.ID))
}

// grants.json cannot be saved after the rules were staged: nothing was ever
// readable, and the request is still there to answer.
func TestApproveAlwaysSaveFailureGivesNothing(t *testing.T) {
	for _, step := range []string{"write", "fsync", "rename", "dirsync"} {
		for _, dropErr := range []error{nil, errors.New("disk full")} {
			e, acl := alwaysEnv(t)
			r := e.create("courier", "infra/a")
			acl.hook = func() {
				e.fs.failOnce(step)
				if len(acl.live) != 0 {
					t.Error("readable before the answer was saved")
				}
			}
			acl.drop = dropErr
			_, err := e.s.ApproveAlways(alwaysIn(r.ID))
			wantCode(t, err, CodeStoreWriteFailed)
			acl.hook = nil
			if len(acl.live) != 0 {
				t.Fatalf("%s: access after a failed answer", step)
			}
			// A narrower answer, a restart: the leftover never becomes access.
			once := approveIn(r.ID)
			once.MaxUses = 1
			if _, _, err := e.s.Approve(once); err != nil {
				t.Fatalf("%s: once after a failed always: %v", step, err)
			}
			acl.drop = nil
			e.reopen()
			if len(acl.live)+len(acl.staged) != 0 {
				t.Fatalf("%s: live %v staged %v after a restart", step, acl.live, acl.staged)
			}
		}
	}
}

// Both writes of the grants file fail after the rules were staged, so disk may
// hold the answer. A restart must not give more than that answer.
func TestApproveAlwaysDoubleFault(t *testing.T) {
	e, acl := alwaysEnv(t)
	r := e.create("courier", "infra/a")
	acl.hook = func() { e.fs.fail("dirsync") }
	_, err := e.s.ApproveAlways(alwaysIn(r.ID))
	wantCode(t, err, CodeStoreWriteFailed)
	if len(acl.live) != 0 {
		t.Fatal("access after a failed answer")
	}
	e.fs.fail("")
	e.reopen()
	if len(acl.live)+len(acl.staged) != 0 {
		t.Fatal("access appeared after the restart")
	}
}

// The server dies between the steps. Only a saved "always" is finished.
func TestRestartBetweenSteps(t *testing.T) {
	e, acl := alwaysEnv(t)
	done := e.create("courier", "infra/done")
	acl.finish = errors.New("died here")
	if _, err := e.s.ApproveAlways(alwaysIn(done.ID)); err != nil || len(acl.live) != 0 {
		t.Fatalf("%v live %v", err, acl.live)
	}
	acl.finish = nil
	pending := e.create("courier", "infra/pending")
	denied := e.create("courier", "infra/denied")
	once := e.create("courier", "infra/once")
	if _, err := e.s.Deny(DenyInput{RequestID: denied.ID, Denier: "dashboard@x"}); err != nil {
		t.Fatal(err)
	}
	e.approve(once.ID)
	for _, id := range []string{pending.ID, denied.ID, once.ID, "req_pruned"} {
		acl.staged[id] = []string{"infra/x"}
	}
	acl.live["req_old"] = []string{"infra/old"} // answered long ago; not staged, not touched
	e.reopen()
	if len(acl.staged) != 0 || len(acl.live) != 2 || !slices.Equal(acl.live[done.ID], []string{"infra/done"}) {
		t.Fatalf("after restart: live %v staged %v", acl.live, acl.staged)
	}
	// Removed since: no later restart brings it back.
	delete(acl.live, done.ID)
	e.reopen()
	if len(acl.live) != 1 {
		t.Fatalf("removed access came back: %v", acl.live)
	}
}

// The token changed while the server was down, before the last step.
func TestRestartFinishChecksTheToken(t *testing.T) {
	e, acl := alwaysEnv(t)
	r := e.create("courier", "infra/a")
	acl.finish = errors.New("died here")
	if _, err := e.s.ApproveAlways(alwaysIn(r.ID)); err != nil {
		t.Fatal(err)
	}
	acl.finish = nil
	acl.tok["courier"] = "fp-other"
	e.reopen()
	if len(acl.live)+len(acl.staged) != 0 {
		t.Fatalf("live %v staged %v", acl.live, acl.staged)
	}
}
