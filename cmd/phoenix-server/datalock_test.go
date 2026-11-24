package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/crypto"
	"github.com/phoenixsec/phoenix/internal/store"
)

// lockTestConfig is a config whose files all live in dir.
func lockTestConfig(dir string) *config.Config {
	cfg := config.DefaultConfig()
	cfg.Store.Path = filepath.Join(dir, "store.json")
	cfg.Store.MasterKey = filepath.Join(dir, "master.key")
	cfg.ACL.Path = filepath.Join(dir, "acl.json")
	cfg.Audit.Path = filepath.Join(dir, "audit.log")
	return cfg
}

// Why the lock exists: two servers on one store lose each other's secrets.
func TestTwoStoresOnOneFileLoseWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	key, _ := crypto.GenerateKey()
	a, err := store.New(path, key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.New(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Set("ns/a", "fake", "x", "", nil); err != nil {
		t.Fatal(err)
	}
	if err := b.Set("ns/b", "fake", "x", "", nil); err != nil {
		t.Fatal(err)
	}
	c, err := store.New(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if c.Count() != 1 {
		t.Skip("the store now merges writes; the lock may no longer be needed")
	}
}

// A second server is refused if it shares any file the first one rewrites,
// and can start once the first is gone.
func TestSecondServerOnSameFilesIsRefused(t *testing.T) {
	first := lockTestConfig(t.TempDir())
	held, err := lockDataFiles(first, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	shares := map[string]func(c *config.Config){
		"everything":                     func(c *config.Config) { *c = *first },
		"only the store":                 func(c *config.Config) { c.Store.Path = first.Store.Path },
		"only the ACL":                   func(c *config.Config) { c.ACL.Path = first.ACL.Path },
		"only the log":                   func(c *config.Config) { c.Audit.Path = first.Audit.Path },
		"a log only one of them rotates": func(c *config.Config) { c.Audit.Path, c.Audit.RotateMB = first.Audit.Path, -1 },
	}
	for name, share := range shares {
		second := lockTestConfig(t.TempDir())
		share(second)
		if _, err := lockDataFiles(second, t.Logf); err == nil || !strings.Contains(err.Error(), "in use by another") {
			t.Errorf("%s: %v, want a refusal", name, err)
		}
	}
	other, err := lockDataFiles(lockTestConfig(t.TempDir()), t.Logf)
	if err != nil {
		t.Errorf("own files: %v", err)
	} else {
		other.release()
	}
	held.release()
	if again, err := lockDataFiles(first, t.Logf); err != nil {
		t.Errorf("after the first server stopped: %v", err)
	} else {
		again.release()
	}
}

// Where no lock file can be made the server still starts, and says so.
func TestLockingUnavailableStillStarts(t *testing.T) {
	cfg := lockTestConfig("/proc/phoenix-cannot-write-here")
	var warned bool
	held, err := lockDataFiles(cfg, func(f string, _ ...any) { warned = warned || strings.HasPrefix(f, "WARNING") })
	if err != nil || !warned {
		t.Fatalf("err %v, warned %v", err, warned)
	}
	held.release()
}

// Appending to one log together keeps working as long as nobody rotates it,
// whichever server starts first.
func TestSharedLogWithoutRotation(t *testing.T) {
	a, b := lockTestConfig(t.TempDir()), lockTestConfig(t.TempDir())
	b.Audit.Path, a.Audit.RotateMB, b.Audit.RotateMB = a.Audit.Path, -1, -1
	for range 2 {
		x, err := lockDataFiles(a, t.Logf)
		if err != nil {
			t.Fatal(err)
		}
		y, err := lockDataFiles(b, t.Logf)
		if err != nil {
			t.Fatalf("sharing a log nobody rotates: %v", err)
		}
		x.release()
		a.Audit.RotateMB = 0 // now rotating, while b still appends
		if _, err := lockDataFiles(a, t.Logf); err == nil {
			t.Error("a rotating server started on a log in use")
		}
		a.Audit.RotateMB = -1
		y.release()
		a, b = b, a
	}
}

// Two servers may share a master key, but then neither may rotate it.
func TestSharedMasterKeyCannotBeRotated(t *testing.T) {
	a, b := lockTestConfig(t.TempDir()), lockTestConfig(t.TempDir())
	b.Store.MasterKey = a.Store.MasterKey
	x, err := lockDataFiles(a, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer x.release()
	y, err := lockDataFiles(b, t.Logf)
	if err != nil {
		t.Fatalf("sharing a key: %v", err)
	}
	if err := x.key.Exclusive(); err == nil {
		t.Error("the key could be rotated while another server uses it")
	}
	y.release()
	if err := x.key.Exclusive(); err != nil {
		t.Errorf("alone: %v", err)
	}
}

// Behind a symlink, a missing directory is a volume that is not mounted: it is
// not created.
func TestMissingVolumeIsNotCreated(t *testing.T) {
	dir := t.TempDir()
	cfg := lockTestConfig(filepath.Join(dir, "data"))
	volume := filepath.Join(dir, "volume")
	if err := errors.Join(os.Mkdir(filepath.Join(dir, "data"), 0700),
		os.Symlink(filepath.Join(volume, "store.json"), cfg.Store.Path), os.Symlink(filepath.Join(volume, "acl.json"), cfg.ACL.Path)); err != nil {
		t.Fatal(err)
	}
	locks, err := lockDataFiles(cfg, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer locks.release()
	key, _ := crypto.GenerateKey()
	st, err := store.New(cfg.Store.Path, key)
	if err != nil {
		t.Fatal(err)
	}
	a, err := acl.New(cfg.ACL.Path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Set("ns/a", "fake", "x", "", nil) == nil || a.AddAgent("worker", "fake", nil) == nil {
		t.Error("a write without its volume should fail")
	}
	if _, err := os.Stat(volume); !os.IsNotExist(err) {
		t.Errorf("the volume's directory was created: %v", err)
	}
}
