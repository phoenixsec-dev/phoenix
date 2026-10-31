package grant

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/phoenixsec/phoenix/internal/fsutil"
)

var fsSteps = []string{"write", "fsync", "rename", "dirsync"}

// A failed approve at any step publishes nothing: no grant, request still
// pending, Match denies. A dir fsync failure (rename already happened, so
// disk may hold the unpublished grant) degrades the store until Tick saves
// memory back over it, so a restart never resurrects a phantom grant.
func TestApproveFaultsPublishNothing(t *testing.T) {
	for _, step := range append([]string{"audit"}, fsSteps...) {
		t.Run(step, func(t *testing.T) {
			e := newEnv(t)
			r := e.create("vector", "infra/key")
			if step == "audit" {
				e.sink.setFail(func(ev Event) bool { return ev.Phase == PhaseAttempt })
			} else {
				e.fs.fail(step)
			}
			_, _, err := e.s.Approve(approveIn(r.ID))
			want := CodeStoreWriteFailed
			if step == "audit" {
				want = CodeAuditWriteFailed
			}
			wantCode(t, err, want)

			if got, _ := e.s.GetRequest(r.ID); got.Status != StatusPending || got.GrantID != "" {
				t.Fatalf("request after failed approve: %+v", got)
			}
			if len(e.s.ListGrants("", true)) != 0 {
				t.Fatal("grant published after failed save")
			}
			if e.s.Match(bearerCaller("vector"), "infra/key", ActionReadValue).Grant != nil {
				t.Fatal("Match allowed after failed approve")
			}
			if e.sink.count(EventRequestApproved) != 0 {
				t.Fatal("committed line written for a failed approve")
			}
			if got := e.s.Health().Degraded; got != (step == "dirsync") {
				t.Fatalf("degraded = %v", got)
			}

			// Clear the fault; one tick heals and the reloaded file matches memory.
			e.fs.fail("")
			e.sink.setFail(nil)
			e.s.Tick()
			if e.s.Health().Degraded {
				t.Fatal("still degraded after a successful save")
			}
			e.reopen()
			if got, _ := e.s.GetRequest(r.ID); got.Status != StatusPending || len(e.s.ListGrants("", true)) != 0 {
				t.Fatalf("after reload: %+v grants=%d", got, len(e.s.ListGrants("", true)))
			}
		})
	}
}

// A one-off dir fsync failure on approve: the store writes the published
// state straight back, so the file never keeps the unacknowledged grant and
// the store is not degraded.
func TestApproveDirSyncRollback(t *testing.T) {
	e := newEnv(t)
	r := e.create("vector", "infra/key")
	e.fs.failOnce("dirsync")
	_, _, err := e.s.Approve(approveIn(r.ID))
	wantCode(t, err, CodeStoreWriteFailed)
	if e.s.Health().Degraded {
		t.Fatal("degraded although the rollback save worked")
	}
	data, err := os.ReadFile(e.path)
	if err != nil || bytes.Contains(data, []byte("gnt_")) {
		t.Fatalf("grants file still holds the failed grant (err %v)", err)
	}
}

// A failed revoke still denies immediately, is never reported as success,
// degrades the store (no new requests/approvals), and heals when a save works.
func TestRevokeFaults(t *testing.T) {
	for _, step := range fsSteps {
		t.Run(step, func(t *testing.T) {
			e := newEnv(t)
			g := e.approve(e.create("vector", "infra/key").ID)
			e.fs.fail(step)

			got, err := e.s.Revoke(RevokeInput{GrantID: g.ID, By: "dashboard@x"})
			wantCode(t, err, CodeRevokeNotDurable)
			if got.RevokedAt.IsZero() {
				t.Fatal("grant not revoked in memory")
			}
			if e.s.Match(bearerCaller("vector"), "infra/key", ActionReadValue).Grant != nil {
				t.Fatal("revoked grant still matched")
			}
			if h := e.s.Health(); !h.Degraded || h.WritesRefused {
				t.Fatalf("health = %+v", h)
			}
			_, _, err = e.s.Create(bearerIn("echo", "infra/x"))
			wantCode(t, err, CodeRequestsDegraded)
			if e.sink.count(EventGrantRevoked) != 0 {
				t.Fatal("grant.revoked committed line written before the revoke was durable")
			}

			// Retrying the revoke while the disk is still bad: same error.
			_, err = e.s.Revoke(RevokeInput{GrantID: g.ID, By: "dashboard@x"})
			wantCode(t, err, CodeRevokeNotDurable)

			// Disk fixed: the retry succeeds and the revoke survives a restart.
			e.fs.fail("")
			if _, err := e.s.Revoke(RevokeInput{GrantID: g.ID, By: "dashboard@x"}); err != nil {
				t.Fatalf("retry after fix: %v", err)
			}
			if e.s.Health().Degraded || e.sink.count(EventGrantRevoked) != 1 {
				t.Fatalf("health %+v revoked lines %d", e.s.Health(), e.sink.count(EventGrantRevoked))
			}
			e.reopen()
			if v, _ := e.s.GetGrant(g.ID); v.RevokedAt.IsZero() {
				t.Fatal("revoke lost on reload")
			}
		})
	}
}

// The cleanup tick also heals a failed revoke without anyone retrying.
func TestTickHealsFailedRevoke(t *testing.T) {
	e := newEnv(t)
	g := e.approve(e.create("vector", "infra/key").ID)
	e.fs.fail("rename")
	if _, err := e.s.Revoke(RevokeInput{GrantID: g.ID, By: "dashboard@x"}); CodeOf(err) != CodeRevokeNotDurable {
		t.Fatal(err)
	}
	e.s.Tick() // still failing
	if !e.s.Health().Degraded {
		t.Fatal("healed while the disk still fails")
	}
	e.fs.fail("")
	e.s.Tick()
	if e.s.Health().Degraded {
		t.Fatal("tick did not heal")
	}
	e.reopen()
	if v, _ := e.s.GetGrant(g.ID); v.RevokedAt.IsZero() {
		t.Fatal("revoke lost after tick save")
	}
}

// A broken audit log never keeps a grant alive: the revoke goes through, and
// its committed line is delivered later from audit_pending.
func TestRevokeWithAuditDown(t *testing.T) {
	e := newEnv(t)
	g := e.approve(e.create("vector", "infra/key").ID)
	e.sink.setFail(func(Event) bool { return true })
	if _, err := e.s.Revoke(RevokeInput{GrantID: g.ID, By: "dashboard@x"}); err != nil {
		t.Fatalf("revoke with audit down: %v", err)
	}
	if h := e.s.Health(); h.AuditPending != 1 {
		t.Fatalf("audit pending = %d, want 1", h.AuditPending)
	}
	e.reopen()
	if v, _ := e.s.GetGrant(g.ID); v.RevokedAt.IsZero() {
		t.Fatal("revoke not durable")
	}
	e.sink.setFail(nil)
	e.s.Tick()
	if e.sink.count(EventGrantRevoked) != 1 || e.s.Health().AuditPending != 0 {
		t.Fatalf("revoked lines %d pending %d", e.sink.count(EventGrantRevoked), e.s.Health().AuditPending)
	}
}

// Committed-line failure: the change stands; audit_pending survives a
// restart and is re-emitted (at-least-once); once delivered and saved it is
// not emitted again.
func TestCommittedAuditRetry(t *testing.T) {
	e := newEnv(t)
	e.sink.setFail(func(ev Event) bool { return ev.Phase == PhaseCommitted })
	r := e.create("vector", "infra/key")
	if e.s.Health().AuditPending != 1 {
		t.Fatal("committed event not queued")
	}
	e.sink.setFail(nil)
	e.reopen() // start-up emits audit_pending
	if e.sink.count(EventRequestCreated) != 1 {
		t.Fatalf("created lines after restart = %d", e.sink.count(EventRequestCreated))
	}
	e.s.Tick() // saves the cleared queue
	e.reopen()
	if e.sink.count(EventRequestCreated) != 1 {
		t.Fatal("delivered event emitted again after it was cleared")
	}
	if got, _ := e.s.GetRequest(r.ID); got.Status != StatusPending {
		t.Fatal("request lost")
	}
}

// DeleteAgent save failure: grants revoked in memory, ACL not touched.
func TestDeleteAgentSaveFailure(t *testing.T) {
	e := newEnv(t)
	g := e.approve(e.create("vector", "infra/key").ID)
	e.fs.fail("fsync")
	called := false
	_, err := e.s.DeleteAgent("vector", "admin", "", func() error { called = true; return nil })
	wantCode(t, err, CodeRevokeNotDurable)
	if called {
		t.Fatal("ACL entry removed although the revoke was not saved")
	}
	if e.s.Match(bearerCaller("vector"), "infra/key", ActionReadValue).Grant != nil {
		t.Fatal("grant usable after failed delete")
	}
	if v, _ := e.s.GetGrant(g.ID); v.RevokedAt.IsZero() {
		t.Fatal("not revoked in memory")
	}
}

// File on disk is 0600 and survives a save/reload round trip.
func TestSaveReloadAfterRevoke(t *testing.T) {
	e := newEnv(t)
	g := e.approve(e.create("vector", "infra/key").ID)
	if _, err := e.s.Revoke(RevokeInput{GrantID: g.ID, By: "dashboard@x"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(e.path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("grants file mode: %v %v", info.Mode(), err)
	}
	e.reopen()
	m := e.s.Match(bearerCaller("vector"), "infra/key", ActionReadValue)
	if m.Grant != nil || m.Reason != ReasonGrantRevoked {
		t.Fatalf("after reload: %+v", m)
	}
}

func TestCorruptFileQuarantined(t *testing.T) {
	e := newEnv(t)
	if err := os.WriteFile(e.path, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	e.reopen()
	want := e.path + ".corrupt-" + strconv.FormatInt(t0.Unix(), 10)
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("corrupt file not moved to %s: %v", want, err)
	}
	if _, err := os.Stat(e.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("original still present: %v", err)
	}
	h := e.s.Health()
	if !h.Degraded || h.WritesRefused || h.QuarantinedTo != want {
		t.Fatalf("health = %+v", h)
	}
	if len(e.s.ListGrants("", true)) != 0 || len(e.s.ListRequests("", "")) != 0 {
		t.Fatal("expected zero records")
	}
	_, _, err := e.s.Create(bearerIn("vector", "infra/key"))
	wantCode(t, err, CodeRequestsDegraded)
}

func TestFailedQuarantineRefusesWrites(t *testing.T) {
	e := newEnv(t)
	g := e.approve(e.create("vector", "infra/key").ID)
	garbage := []byte(`{"version": 99}`)
	if err := os.WriteFile(e.path, garbage, 0600); err != nil {
		t.Fatal(err)
	}
	e.fs.quarantineErr = errInjected
	e.reopen()

	h := e.s.Health()
	if !h.Degraded || !h.WritesRefused {
		t.Fatalf("health = %+v", h)
	}
	if e.s.Match(bearerCaller("vector"), "infra/key", ActionReadValue).Grant != nil {
		t.Fatal("grant usable while quarantine failed")
	}
	_, _, err := e.s.Create(bearerIn("echo", "infra/key"))
	wantCode(t, err, CodeRequestsDegraded)
	_, err = e.s.DeleteAgent("vector", "admin", "", nil)
	wantCode(t, err, CodeRequestsDegraded)
	_, err = e.s.Revoke(RevokeInput{GrantID: g.ID, By: "x"})
	wantCode(t, err, CodeNotFound) // zero grants loaded
	e.clock.Advance(time.Hour)
	e.s.Tick()

	got, err := os.ReadFile(e.path)
	if err != nil || !bytes.Equal(got, garbage) {
		t.Fatalf("original file changed: %q %v", got, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(e.path))
	for _, ent := range entries {
		if strings.Contains(ent.Name(), "corrupt") || strings.Contains(ent.Name(), ".tmp") {
			t.Fatalf("unexpected file %s", ent.Name())
		}
	}
}

// The strict writer is what makes dir-fsync failures visible.
func TestOSFSUsesStrictWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "g.json")
	err := OSFS{Ops: fsutil.AtomicOps{SyncDir: func(string) error { return errInjected }}}.WriteFileAtomic(path, []byte("x"), 0600)
	if !errors.Is(err, fsutil.ErrDirSyncFailed) {
		t.Fatalf("err = %v, want ErrDirSyncFailed", err)
	}
}
