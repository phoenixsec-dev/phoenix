package main

import (
	"path/filepath"
	"strings"
	"testing"

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
	release, err := lockDataFiles(first, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	shares := map[string]func(c *config.Config){
		"everything":     func(c *config.Config) { *c = *first },
		"only the store": func(c *config.Config) { c.Store.Path = first.Store.Path },
		"only the ACL":   func(c *config.Config) { c.ACL.Path = first.ACL.Path },
		"only the log":   func(c *config.Config) { c.Audit.Path = first.Audit.Path },
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
		other()
	}
	release()
	if again, err := lockDataFiles(first, t.Logf); err != nil {
		t.Errorf("after the first server stopped: %v", err)
	} else {
		again()
	}
}

// Where no lock file can be made the server still starts, and says so.
func TestLockingUnavailableStillStarts(t *testing.T) {
	cfg := lockTestConfig("/proc/phoenix-cannot-write-here")
	var warned bool
	release, err := lockDataFiles(cfg, func(f string, _ ...any) { warned = warned || strings.HasPrefix(f, "WARNING") })
	if err != nil || !warned {
		t.Fatalf("err %v, warned %v", err, warned)
	}
	release()
}
