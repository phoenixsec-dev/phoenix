package fsutil

import (
	"errors"
	"fmt"
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

// Strict mode: a dir fsync failure after the rename is reported as
// ErrDirSyncFailed (content already replaced), so durability-critical callers
// can treat it as a failed save. Pre-rename failures are NOT ErrDirSyncFailed
// and leave the old content.
func TestWriteFileAtomicStrict(t *testing.T) {
	injected := errors.New("injected")
	cases := []struct {
		name        string
		ops         AtomicOps
		wantContent string
		wantDirSync bool
	}{
		{"ok", AtomicOps{}, "new", false},
		{"write", AtomicOps{Write: func(*os.File, []byte) error { return injected }}, "old", false},
		{"fsync", AtomicOps{SyncFile: func(*os.File) error { return injected }}, "old", false},
		{"rename", AtomicOps{Rename: func(string, string) error { return injected }}, "old", false},
		{"dirsync", AtomicOps{SyncDir: func(string) error { return injected }}, "new", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "grants.json")
			if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
				t.Fatal(err)
			}
			err := WriteFileAtomicStrictOps(path, []byte("new"), 0600, tc.ops)
			if tc.name == "ok" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.name != "ok" && err == nil {
				t.Fatal("expected error")
			}
			if got := errors.Is(err, ErrDirSyncFailed); got != tc.wantDirSync {
				t.Fatalf("errors.Is(ErrDirSyncFailed) = %v, want %v (err %v)", got, tc.wantDirSync, err)
			}
			got, rerr := os.ReadFile(path)
			if rerr != nil || string(got) != tc.wantContent {
				t.Fatalf("content = %q (%v), want %q", got, rerr, tc.wantContent)
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 1 {
				t.Fatalf("temp file left behind: %d entries", len(entries))
			}
		})
	}
}

// A file reached through a symlink is replaced where it really is and the link
// stays. Replacing the link would leave the new content off the volume the
// owner pointed it at, and the old content on it.
func TestWriteGoesThroughSymlinks(t *testing.T) {
	for name, target := range map[string]string{
		"absolute":     "ABS",
		"relative":     "../vol/real.json",
		"link to link": "LINK",
	} {
		for _, exists := range []bool{true, false} {
			t.Run(name+fmt.Sprintf(" exists=%v", exists), func(t *testing.T) {
				dir := t.TempDir()
				real := filepath.Join(dir, "vol", "real.json")
				link := filepath.Join(dir, "data", "file.json")
				for _, d := range []string{filepath.Dir(real), filepath.Dir(link)} {
					if err := os.Mkdir(d, 0700); err != nil {
						t.Fatal(err)
					}
				}
				target := target
				switch target {
				case "ABS":
					target = real
				case "LINK":
					target = filepath.Join(dir, "vol", "second")
					if err := os.Symlink("real.json", target); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
				if exists {
					if err := os.WriteFile(real, []byte("old"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err := WriteFileAtomic(link, []byte("new"), 0600); err != nil {
					t.Fatal(err)
				}
				if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
					t.Errorf("the link is gone: %v %v", fi, err)
				}
				if b, err := os.ReadFile(real); string(b) != "new" {
					t.Errorf("target = %q %v", b, err)
				}
			})
		}
	}
}

// A link whose target directory is gone (a volume that is not mounted) is a
// failed write, not a reason to write somewhere else.
func TestWriteThroughDanglingSymlinkFails(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "file.json")
	if err := os.Symlink(filepath.Join(dir, "unmounted", "file.json"), link); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(link, []byte("new"), 0600); err == nil {
		t.Error("want an error")
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link is gone: %v %v", fi, err)
	}
}
