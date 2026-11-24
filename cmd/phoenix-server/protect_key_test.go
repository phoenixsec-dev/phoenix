package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/phoenixsec/phoenix/internal/fsutil"
)

// --protect-key waits for a person to type. If rotate-master replaced the key
// meanwhile, saving the key read before would leave a store no key opens.
func TestProtectKeyDoesNotOverwriteARotatedKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	saved := false
	save := func() error { saved = true; return nil }
	write("old")
	if err := replaceKeyFile(path, []byte("old"), save); err != nil || !saved {
		t.Fatalf("unchanged: err %v, saved %v", err, saved)
	}
	saved = false
	write("rotated")
	if err := replaceKeyFile(path, []byte("old"), save); err == nil || saved {
		t.Errorf("changed: err %v, saved %v, want a refusal", err, saved)
	}
	lock, err := fsutil.Lock(path) // a rotation is saving its key right now
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	if err := replaceKeyFile(path, []byte("rotated"), save); !errors.Is(err, fsutil.ErrLocked) || saved {
		t.Errorf("locked: err %v, saved %v, want ErrLocked", err, saved)
	}
}
