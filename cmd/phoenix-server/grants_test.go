package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/audit"
	"github.com/phoenixsec/phoenix/internal/config"
)

// R1 H1: an install with no access_requests block whose secrets data file is
// grants.json next to the ACL must be refused before the grant store opens,
// and nothing on disk may change (no overwrite, no "corrupt" quarantine).
func TestOpenGrantStoreRefusesCollisionWithoutTouchingFiles(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.ACL.Path = filepath.Join(dir, "acl.json")
	cfg.Audit.Path = filepath.Join(dir, "audit.log")
	cfg.Store.Path = filepath.Join(dir, "grants.json") // the default grants path
	cfg.Store.MasterKey = filepath.Join(dir, "master.key")
	if err := os.WriteFile(cfg.Store.Path, []byte(`{"secrets":"not grants"}`), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := acl.New(cfg.ACL.Path)
	if err != nil {
		t.Fatal(err)
	}
	al, err := audit.NewLogger(cfg.Audit.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted a grants path that is the secrets data file")
	}
	st, err := openGrantStore(cfg, a, al, time.Hour)
	if err == nil || st != nil || !strings.Contains(err.Error(), "store_path") {
		t.Fatalf("openGrantStore = %v, %v; want a refusal naming store_path", st, err)
	}
	if b, _ := os.ReadFile(cfg.Store.Path); string(b) != `{"secrets":"not grants"}` {
		t.Fatalf("data file changed: %q", b)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), "corrupt") || strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("unexpected file after refusal: %s", e.Name())
		}
	}
}
