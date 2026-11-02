package grant

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/phoenixsec/phoenix/internal/fsutil"
)

var (
	t0          = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	errInjected = errors.New("injected fault")
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}
func (c *fakeClock) Advance(d time.Duration) { c.Set(c.Now().Add(d)) }

// recSink records audit events; fail, when set, makes matching appends fail.
type recSink struct {
	mu     sync.Mutex
	events []Event
	fail   func(Event) bool
}

func (r *recSink) Append(e Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil && r.fail(e) {
		return errInjected
	}
	r.events = append(r.events, e)
	return nil
}

func (r *recSink) setFail(f func(Event) bool) { r.mu.Lock(); r.fail = f; r.mu.Unlock() }

func (r *recSink) count(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.events {
		if e.Name == name {
			n++
		}
	}
	return n
}

// faultFS is the real filesystem with one switchable failing step:
// "write", "fsync", "rename", "dirsync". quarantineErr fails the
// corrupt-file rename.
type faultFS struct {
	OSFS
	mu            sync.Mutex
	step          string
	once          bool // clear step after it fires once
	quarantineErr error
}

func newFaultFS() *faultFS {
	f := &faultFS{}
	f.Ops = fsutil.AtomicOps{
		Write: func(fl *os.File, b []byte) error {
			if f.failing("write") {
				return errInjected
			}
			_, err := fl.Write(b)
			return err
		},
		SyncFile: func(fl *os.File) error {
			if f.failing("fsync") {
				return errInjected
			}
			return fl.Sync()
		},
		Rename: func(a, b string) error {
			if f.failing("rename") {
				return errInjected
			}
			return os.Rename(a, b)
		},
		SyncDir: func(dir string) error {
			if f.failing("dirsync") {
				return errInjected
			}
			return fsutil.SyncDir(dir)
		},
	}
	return f
}

func (f *faultFS) failing(step string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	hit := f.step == step
	if hit && f.once {
		f.step = ""
	}
	return hit
}

func (f *faultFS) fail(step string)     { f.mu.Lock(); f.step, f.once = step, false; f.mu.Unlock() }
func (f *faultFS) failOnce(step string) { f.mu.Lock(); f.step, f.once = step, true; f.mu.Unlock() }

func (f *faultFS) Rename(a, b string) error {
	if f.quarantineErr != nil {
		return f.quarantineErr
	}
	return os.Rename(a, b)
}

// env bundles a store with its fake clock, sink, filesystem and ACL view.
type env struct {
	t     *testing.T
	s     *Store
	clock *fakeClock
	sink  *recSink
	fs    *faultFS
	path  string

	aclMu sync.Mutex
	gone  map[string]bool   // agents removed from the ACL
	hook  func(name string) // optional; runs inside AgentExists before the answer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{
		t:     t,
		clock: &fakeClock{t: t0},
		sink:  &recSink{},
		fs:    newFaultFS(),
		path:  filepath.Join(t.TempDir(), "grants.json"),
		gone:  map[string]bool{},
	}
	e.reopen()
	return e
}

// reopen simulates a server restart on the same grants.json.
func (e *env) reopen() *Store {
	e.t.Helper()
	s, err := Open(Options{
		Path: e.path, FS: e.fs, Audit: e.sink, Now: e.clock.Now,
		AgentExists: e.exists, Logf: e.t.Logf,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	e.s = s
	return s
}

func (e *env) exists(name string) bool {
	e.aclMu.Lock()
	hook := e.hook
	e.aclMu.Unlock()
	if hook != nil {
		hook(name)
	}
	e.aclMu.Lock()
	defer e.aclMu.Unlock()
	return !e.gone[name]
}

func (e *env) setHook(h func(string)) { e.aclMu.Lock(); e.hook = h; e.aclMu.Unlock() }

func (e *env) setGone(name string, gone bool) {
	e.aclMu.Lock()
	e.gone[name] = gone
	e.aclMu.Unlock()
}

func bearerIn(agent string, paths ...string) CreateInput {
	return CreateInput{
		Agent: agent, Paths: paths, Action: ActionReadValue, Reason: "backup job needs it",
		SourceIP: "10.0.0.5", AuthMethod: AuthBearer, CredentialFP: "fp-" + agent,
	}
}

func bearerCaller(agent string) Caller {
	return Caller{Agent: agent, SourceIP: "10.0.0.5", AuthMethod: AuthBearer, CredentialFP: "fp-" + agent}
}

func (e *env) create(agent string, paths ...string) Request {
	e.t.Helper()
	r, created, err := e.s.Create(bearerIn(agent, paths...))
	if err != nil || !created {
		e.t.Fatalf("create %v: created=%v err=%v", paths, created, err)
	}
	return r
}

func approveIn(id string) ApproveInput {
	return ApproveInput{RequestID: id, Approver: "dashboard@10.0.0.9", ApproverIP: "10.0.0.9",
		SealedOnly: true, BindSourceIP: true}
}

func (e *env) approve(id string) Grant {
	e.t.Helper()
	_, g, err := e.s.Approve(approveIn(id))
	if err != nil {
		e.t.Fatalf("approve %s: %v", id, err)
	}
	return g
}

func wantCode(t *testing.T, err error, code Code) {
	t.Helper()
	if CodeOf(err) != code {
		t.Fatalf("error = %v, want code %s", err, code)
	}
}
