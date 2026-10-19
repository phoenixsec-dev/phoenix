package fsutil

import (
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
