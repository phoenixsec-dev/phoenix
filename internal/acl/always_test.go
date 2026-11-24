package acl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	if err := a.AddAgent("vector", "tok", []Permission{{Path: "dev/**", Actions: []Action{ActionReadValue}}}); err != nil {
		t.Fatal(err)
	}
	return a, p
}

func from(id string) AlwaysOrigin {
	return AlwaysOrigin{RequestID: id, By: "dashboard@x", At: time.Unix(1, 0).UTC()}
}

func anyAgent(Agent) error { return nil }

func reads(a *ACL, path string) bool { return a.Authorize("vector", path, ActionReadValue) == nil }

func TestAlwaysAddRemoveSurvivesRestart(t *testing.T) {
	a, p := alwaysACL(t)
	if err := a.AddAlways("vector", from("req_1"), []string{"infra/a", "infra/b"}, anyAgent); err != nil {
		t.Fatal(err)
	}
	a, err := New(p) // restart
	if err != nil {
		t.Fatal(err)
	}
	if !reads(a, "infra/a") || !reads(a, "infra/b") || reads(a, "infra/a/x") || reads(a, "infra/c") || a.Authorize("vector", "infra/a", ActionWrite) == nil {
		t.Fatal("not exactly read_value on the two paths")
	}
	// The same request again replaces its own rules.
	if err := a.AddAlways("vector", from("req_1"), []string{"infra/a"}, anyAgent); err != nil || reads(a, "infra/b") {
		t.Fatalf("replace: %v", err)
	}
	if n, err := a.RemoveAlways("vector", "infra/a"); n != 1 || err != nil || reads(a, "infra/a") {
		t.Fatalf("remove: %d %v", n, err)
	}
	if n, err := a.RemoveAlways("vector", "dev/**"); n != 0 || err != nil || !reads(a, "dev/x") {
		t.Fatal("remove touched a rule the operator wrote")
	}
	a, _ = New(p)
	if reads(a, "infra/a") || len(a.ListAlways()) != 0 {
		t.Fatal("removed access came back")
	}
}

func TestAlwaysRefusals(t *testing.T) {
	a, _ := alwaysACL(t)
	for _, path := range []string{"", "*", "**", "infra/*", "infra/**", "a*b"} {
		if a.AddAlways("vector", from("req_1"), []string{path}, anyAgent) == nil {
			t.Errorf("path %q accepted", path)
		}
	}
	if err := a.AddAlways("nobody", from("req_1"), []string{"infra/a"}, anyAgent); !errors.Is(err, ErrAgentNotFound) {
		t.Errorf("unknown agent: %v", err)
	}
	no := errors.New("token changed")
	if err := a.AddAlways("vector", from("req_1"), []string{"infra/a"}, func(Agent) error { return no }); !errors.Is(err, no) || reads(a, "infra/a") {
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
	a.writeFile = func(string, []byte, os.FileMode) error { return disk }
	if err := a.AddAlways("vector", from("req_1"), []string{"infra/a"}, anyAgent); !errors.Is(err, disk) || reads(a, "infra/a") {
		t.Fatalf("failed add: %v", err)
	}
	// Renamed into place but not confirmed: the old file goes back.
	once := true
	a.writeFile = func(path string, data []byte, perm os.FileMode) error {
		err := good(path, data, perm)
		if once {
			once = false
			return fmt.Errorf("%w: x", fsutil.ErrDirSyncFailed)
		}
		return err
	}
	if err := a.AddAlways("vector", from("req_1"), []string{"infra/a"}, anyAgent); err == nil || reads(a, "infra/a") {
		t.Fatalf("unconfirmed add: %v", err)
	}
	if again, _ := New(p); reads(again, "infra/a") {
		t.Fatal("an unconfirmed add is on disk")
	}

	a.writeFile = good
	if err := a.AddAlways("vector", from("req_1"), []string{"infra/a"}, anyAgent); err != nil {
		t.Fatal(err)
	}
	// A failed remove denies at once, stays listed, and can be retried.
	a.writeFile = func(string, []byte, os.FileMode) error { return disk }
	if _, err := a.RemoveAlways("vector", "infra/a"); err == nil || reads(a, "infra/a") {
		t.Fatalf("failed remove: %v", err)
	}
	if l := a.ListAlways(); len(l) != 1 || !l[0].Unsaved {
		t.Fatalf("list = %+v", l)
	}
	a.writeFile = good
	if _, err := a.RemoveAlways("vector", "infra/a"); err != nil || len(a.ListAlways()) != 0 {
		t.Fatalf("retry: %v %+v", err, a.ListAlways())
	}
	if again, _ := New(p); reads(again, "infra/a") {
		t.Fatal("removal not saved by the retry")
	}
	if err := a.AddAlways("vector", from("req_2"), []string{"infra/b"}, anyAgent); err != nil {
		t.Fatal(err)
	}
	if err := a.ClearAlways("req_2"); err != nil || reads(a, "infra/b") {
		t.Fatalf("clear: %v", err)
	}
}

// Callers hold permission slices read earlier; changing rules must not touch them.
func TestAlwaysDoesNotChangeSharedSlices(t *testing.T) {
	a, _ := alwaysACL(t)
	a.AddAlways("vector", from("req_1"), []string{"infra/a"}, anyAgent)
	held, _ := a.GetAgent("vector")
	a.RemoveAlways("vector", "infra/a")
	a.AddAlways("vector", from("req_2"), []string{"infra/z"}, anyAgent)
	if len(held.Permissions) != 2 || held.Permissions[1].Path != "infra/a" {
		t.Fatalf("held = %+v", held.Permissions)
	}
}
