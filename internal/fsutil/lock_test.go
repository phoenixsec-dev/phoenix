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
		l, err := Lock(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{path, link} {
			if _, err := Lock(p); !errors.Is(err, ErrLocked) {
				t.Errorf("second lock on %s: %v, want ErrLocked", p, err)
			}
			if _, err := LockShared(p); !errors.Is(err, ErrLocked) {
				t.Errorf("shared lock on %s: %v, want ErrLocked", p, err)
			}
		}
		l.Release()
	}
}

// Shared holders keep exclusive ones out until they are alone, and a failed
// attempt to be alone leaves the lock shared.
func TestLockShared(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	a, err := LockShared(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LockShared(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Exclusive(); !errors.Is(err, ErrLocked) {
		t.Errorf("exclusive while shared: %v, want ErrLocked", err)
	}
	if _, err := Lock(path); !errors.Is(err, ErrLocked) {
		t.Errorf("lock while shared: %v, want ErrLocked", err)
	}
	b.Release()
	if err := a.Exclusive(); err != nil {
		t.Errorf("exclusive when alone: %v", err)
	}
	if _, err := LockShared(path); !errors.Is(err, ErrLocked) {
		t.Errorf("shared while exclusive: %v, want ErrLocked", err)
	}
	if err := a.Share(); err != nil {
		t.Error(err)
	}
	if c, err := LockShared(path); err != nil {
		t.Errorf("shared again: %v", err)
	} else {
		c.Release()
	}
}

// A lock file its user may only read still locks, and one that is a symlink is
// not followed.
func TestLockFileAccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "master.key")
	if err := os.WriteFile(path+".lock", nil, 0400); err != nil {
		t.Fatal(err)
	}
	l, err := Lock(path)
	if err != nil {
		t.Fatalf("read-only lock file: %v", err)
	}
	l.Release()
	planted := filepath.Join(dir, "store.json")
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), planted+".lock"); err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(planted); err == nil || errors.Is(err, ErrLocked) {
		t.Errorf("planted link: %v, want another error", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "elsewhere")); !os.IsNotExist(err) {
		t.Error("the link was followed")
	}
}

// A directory that cannot hold a lock file is not a conflict.
func TestLockUnavailableIsNotLocked(t *testing.T) {
	if _, err := Lock(filepath.Join(t.TempDir(), "missing", "store.json")); err == nil || errors.Is(err, ErrLocked) {
		t.Errorf("got %v, want another error", err)
	}
}
