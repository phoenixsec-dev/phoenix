package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --passphrase was removed; --init takes the passphrase from the environment
// (or stdin), and no passphrase at all means an unprotected key.
func TestInitPassphraseFromEnv(t *testing.T) {
	t.Setenv("PHOENIX_MASTER_PASSPHRASE", "")
	if p, err := initPassphrase(false); err != nil || p != "" {
		t.Fatalf("no source: got %q, %v", p, err)
	}
	t.Setenv("PHOENIX_MASTER_PASSPHRASE", "from-env")
	if p, err := initPassphrase(false); err != nil || p != "from-env" {
		t.Fatalf("env: got %q, %v", p, err)
	}
}

// --init never replaces a file that is already there. A data directory whose
// master key lives elsewhere, or was lost, still holds a store, CA and config
// that nothing can make again.
func TestInitRefusesToReplaceAnything(t *testing.T) {
	for _, name := range []string{"master.key", "store.json", "acl.json", "config.json", "ca.crt", "ca.key", "server.crt", "server.key"} {
		for _, kind := range []string{"file", "dangling link"} {
			t.Run(name+" "+kind, func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, name)
				var err error
				if kind == "file" {
					err = os.WriteFile(path, []byte("{}"), 0600)
				} else {
					err = os.Symlink(filepath.Join(dir, "elsewhere", "x"), path)
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := runInit(dir, ""); err == nil || !strings.Contains(err.Error(), name) {
					t.Errorf("runInit = %v, want a refusal naming %s", err, name)
				}
				if ents, _ := os.ReadDir(dir); len(ents) != 1 {
					t.Errorf("init left %d files, want only the one that was there", len(ents))
				}
			})
		}
	}
}

// A new directory, and one that holds unrelated files, both work.
func TestInitNextToOtherFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("mine"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runInit(dir, ""); err != nil {
		t.Fatal(err)
	}
	if err := runCheckConfig(filepath.Join(dir, "config.json")); err != nil {
		t.Errorf("the config --init wrote: %v", err)
	}
}
