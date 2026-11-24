package acl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/phoenixsec/phoenix/internal/fsutil"
)

func alwaysACL(t *testing.T) (*ACL, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "acl.json")
	a, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddAgent("courier", "tok", []Permission{{Path: "dev/**", Actions: []Action{ActionReadValue}}}); err != nil {
		t.Fatal(err)
	}
	return a, p
}

func from(id string) AlwaysOrigin {
	return AlwaysOrigin{RequestID: id, By: "dashboard@x", At: time.Unix(1, 0).UTC()}
}

func anyAgent(Agent) error { return nil }

func reads(a *ACL, path string) bool { return a.Authorize("courier", path, ActionReadValue) == nil }

// add stages and finishes, as an answered "always" does.
func add(t *testing.T, a *ACL, id string, paths ...string) {
	t.Helper()
	if err := a.StageAlways("courier", from(id), paths, anyAgent); err != nil {
		t.Fatal(err)
	}
	if err := a.FinishAlways("courier", id, anyAgent); err != nil {
		t.Fatal(err)
	}
}

func TestAlwaysAddRemoveSurvivesRestart(t *testing.T) {
	a, p := alwaysACL(t)
	add(t, a, "req_1", "infra/a", "infra/b")
	a, err := New(p) // restart
	if err != nil {
		t.Fatal(err)
	}
	if !reads(a, "infra/a") || !reads(a, "infra/b") || reads(a, "infra/a/x") || reads(a, "infra/c") || a.Authorize("courier", "infra/a", ActionWrite) == nil {
		t.Fatal("not exactly read_value on the two paths")
	}
	if !a.HasAlways("courier", "infra/a") || a.HasAlways("courier", "dev/x") || a.HasAlways("nobody", "infra/a") {
		t.Fatal("HasAlways is not exactly the always rules")
	}
	// A page from an older answer cannot remove this one.
	if ok, _ := a.RemoveAlways("courier", "infra/a", "req_0"); ok || !reads(a, "infra/a") {
		t.Fatal("removed by the wrong request")
	}
	if ok, err := a.RemoveAlways("courier", "infra/a", "req_1"); !ok || err != nil || reads(a, "infra/a") {
		t.Fatalf("remove: %v %v", ok, err)
	}
	if ok, _ := a.RemoveAlways("courier", "dev/**", ""); ok || !reads(a, "dev/x") {
		t.Fatal("remove touched a rule the operator wrote")
	}
	// Finishing again (a replay, a restart) brings nothing back.
	if err := a.FinishAlways("courier", "req_1", anyAgent); err != nil || reads(a, "infra/a") {
		t.Fatal("a second finish put removed access back")
	}
	a, _ = New(p)
	if reads(a, "infra/a") || !reads(a, "infra/b") {
		t.Fatal("removed access came back")
	}
}

// A staged rule allows nothing, in memory or from the file, until it is finished.
func TestStagedAllowsNothing(t *testing.T) {
	a, p := alwaysACL(t)
	if err := a.StageAlways("courier", from("req_1"), []string{"infra/a"}, anyAgent); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		for _, act := range []Action{ActionReadValue, ActionList, ActionWrite, ActionDelete, ActionAdmin} {
			if a.Authorize("courier", "infra/a", act) == nil {
				t.Fatalf("staged rule allows %s", act)
			}
		}
		if len(a.ListAlways()) != 0 || a.HasAlways("courier", "infra/a") || !slices.Equal(a.StagedRequests(), []string{"req_1"}) {
			t.Fatal("staged rule counts as a real one")
		}
		a, _ = New(p) // and after a restart
	}
	no := errors.New("token changed")
	if err := a.FinishAlways("courier", "req_1", func(Agent) error { return no }); !errors.Is(err, no) || reads(a, "infra/a") {
		t.Fatalf("finished for another token: %v", err)
	}
	if err := a.DropStaged("req_1"); err != nil || len(a.StagedRequests()) != 0 {
		t.Fatal("not dropped")
	}
	if err := a.FinishAlways("courier", "req_1", anyAgent); err != nil || reads(a, "infra/a") {
		t.Fatal("a dropped rule was finished")
	}
}

func TestAlwaysRefusals(t *testing.T) {
	a, _ := alwaysACL(t)
	for _, path := range []string{"", "*", "**", "infra/*", "infra/**", "a*b"} {
		if a.StageAlways("courier", from("req_1"), []string{path}, anyAgent) == nil {
			t.Errorf("path %q accepted", path)
		}
	}
	if err := a.StageAlways("nobody", from("req_1"), []string{"infra/a"}, anyAgent); !errors.Is(err, ErrAgentNotFound) {
		t.Errorf("unknown agent: %v", err)
	}
	no := errors.New("token changed")
	if err := a.StageAlways("courier", from("req_1"), []string{"infra/a"}, func(Agent) error { return no }); !errors.Is(err, no) {
		t.Errorf("check ignored: %v", err)
	}
	// The mark cannot be set through the agent API.
	if ValidatePermissions([]Permission{{Path: "x/y", Actions: []Action{ActionReadValue}, Always: &AlwaysOrigin{RequestID: "req_1"}}}) == nil {
		t.Error("always accepted in a hand-written rule")
	}
}

func TestAlwaysSaveFailures(t *testing.T) {
	a, p := alwaysACL(t)
	disk := errors.New("disk full")
	good := a.writeFile
	broken := func(string, []byte, os.FileMode) error { return disk }
	a.writeFile = broken
	if err := a.StageAlways("courier", from("req_1"), []string{"infra/a"}, anyAgent); !errors.Is(err, disk) || len(a.StagedRequests()) != 0 {
		t.Fatalf("failed stage: %v", err)
	}
	// Replaced but not confirmed: whatever is on disk allows nothing.
	a.writeFile = func(path string, data []byte, perm os.FileMode) error {
		good(path, data, perm)
		return fmt.Errorf("%w: x", fsutil.ErrDirSyncFailed)
	}
	if err := a.StageAlways("courier", from("req_1"), []string{"infra/a"}, anyAgent); err == nil {
		t.Fatal("unconfirmed stage reported as saved")
	}
	if again, _ := New(p); reads(again, "infra/a") {
		t.Fatal("an unconfirmed stage reads")
	}
	// A finish that cannot be saved counts now, and the next start finishes it.
	a.writeFile = good
	if err := a.StageAlways("courier", from("req_1"), []string{"infra/a"}, anyAgent); err != nil {
		t.Fatal(err)
	}
	a.writeFile = broken
	if err := a.FinishAlways("courier", "req_1", anyAgent); err == nil || !reads(a, "infra/a") {
		t.Fatalf("finish: %v", err)
	}
	a, _ = New(p)
	if reads(a, "infra/a") || len(a.StagedRequests()) != 1 {
		t.Fatal("after a restart it should still be staged")
	}
	add(t, a, "req_1", "infra/a")

	// A failed remove denies at once, stays listed, and can be retried.
	good = a.writeFile
	a.writeFile = broken
	if _, err := a.RemoveAlways("courier", "infra/a", "req_1"); err == nil || reads(a, "infra/a") {
		t.Fatalf("failed remove: %v", err)
	}
	if l := a.ListAlways(); len(l) != 1 || !l[0].Unsaved {
		t.Fatalf("list = %+v", l)
	}
	a.writeFile = good
	if ok, err := a.RemoveAlways("courier", "infra/a", "req_1"); !ok || err != nil || len(a.ListAlways()) != 0 {
		t.Fatalf("retry: %v %+v", err, a.ListAlways())
	}
	if again, _ := New(p); reads(again, "infra/a") {
		t.Fatal("removal not saved by the retry")
	}
}

// The mark alone is not permission: a marked rule someone narrowed by hand
// counts only for what it still allows.
func TestHasAlwaysNeedsReadValue(t *testing.T) {
	for _, actions := range [][]Action{{}, {ActionList}, nil} {
		o := from("req_1")
		a := NewFromConfig(&ACLConfig{Agents: map[string]Agent{"courier": {Permissions: []Permission{{Path: "infra/a", Actions: actions, Always: &o}}}}})
		if a.HasAlways("courier", "infra/a") {
			t.Errorf("actions %v count as read access", actions)
		}
	}
}

// Callers hold permission slices read earlier; changing rules must not touch them.
func TestAlwaysDoesNotChangeSharedSlices(t *testing.T) {
	a, _ := alwaysACL(t)
	add(t, a, "req_1", "infra/a")
	held, _ := a.GetAgent("courier")
	a.RemoveAlways("courier", "infra/a", "req_1")
	add(t, a, "req_2", "infra/z")
	if len(held.Permissions) != 2 || held.Permissions[1].Path != "infra/a" || len(held.Permissions[1].Actions) != 1 {
		t.Fatalf("held = %+v", held.Permissions)
	}
}
