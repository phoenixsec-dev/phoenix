package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// One holder at a time, also when one of them comes through a symlink, and the
// leftover lock file does not block the next one.
func TestLock(t *testing.T) {
	dir := t.TempDir()
	path, link := filepath.Join(dir, "store.json"), filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		release, err := Lock(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{path, link} {
			if _, err := Lock(p); !errors.Is(err, ErrLocked) {
				t.Errorf("second lock on %s: %v, want ErrLocked", p, err)
			}
		}
		release()
	}
}

// A directory that cannot hold a lock file is not a conflict.
func TestLockUnavailableIsNotLocked(t *testing.T) {
	if _, err := Lock(filepath.Join(t.TempDir(), "missing", "store.json")); err == nil || errors.Is(err, ErrLocked) {
		t.Errorf("got %v, want another error", err)
	}
}
