package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Replacing an existing file: new content, requested mode (even though the
// old file was 0644), and no temp files left in the directory.
func TestWriteFileAtomicReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.json")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := WriteFileAtomic(path, []byte("new"), 0600); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("content = %q, want %q", got, "new")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected only the target file, found %d entries", len(entries))
	}
}

// A failed write must leave the target untouched and remove its temp file.
func TestWriteFileAtomicFailureKeepsOriginal(t *testing.T) {
	dir := t.TempDir()
	// A non-empty directory at the target path makes the final rename fail
	// after the temp file has been written and synced.
	target := filepath.Join(dir, "store.json")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "child"), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := WriteFileAtomic(target, []byte("new"), 0600); err == nil {
		t.Fatal("expected error replacing a non-empty directory")
	}

	got, err := os.ReadFile(filepath.Join(target, "child"))
	if err != nil || string(got) != "old" {
		t.Fatalf("target changed: %q %v", got, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("temp file left behind: %d entries", len(entries))
	}
}

// swapSeam replaces a package seam for one test and restores it afterwards.
func swapSeam[T any](t *testing.T, seam *T, fake T) {
	t.Helper()
	orig := *seam
	*seam = fake
	t.Cleanup(func() { *seam = orig })
}

// The temp file must be fsynced BEFORE the rename (target still old when
// the sync runs), and a failed sync must leave the target untouched.
func TestWriteFileAtomicFileSyncFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.json")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	var atSync string
	swapSeam(t, &syncFile, func(f *os.File) error {
		got, _ := os.ReadFile(path)
		atSync = string(got)
		return errors.New("injected sync failure")
	})

	if err := WriteFileAtomic(path, []byte("new"), 0600); err == nil {
		t.Fatal("expected error when the temp file sync fails")
	}
	if atSync != "old" {
		t.Fatalf("target held %q during file sync; sync must run before rename", atSync)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "old" {
		t.Fatalf("target changed after failed sync: %q %v", got, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("temp file left behind: %d entries", len(entries))
	}
}

// The directory is fsynced AFTER the rename. If that sync fails the file
// has already been replaced, so the call must report success (an error
// would tell callers the old content is still in place).
func TestWriteFileAtomicDirSyncFailureStillSucceeds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.json")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	var atSync string
	swapSeam(t, &syncDir, func(string) error {
		got, _ := os.ReadFile(path)
		atSync = string(got)
		return errors.New("injected dir sync failure")
	})

	if err := WriteFileAtomic(path, []byte("new"), 0600); err != nil {
		t.Fatalf("dir sync failure after rename must not be an error: %v", err)
	}
	if atSync != "new" {
		t.Fatalf("target held %q during dir sync; dir sync must run after rename", atSync)
	}
}
