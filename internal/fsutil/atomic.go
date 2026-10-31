// Package fsutil holds small filesystem helpers shared by packages that
// persist critical state (the secret store and master key files).
package fsutil

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// WriteFileAtomic replaces path with data so that, after a crash or power
// loss, the file holds either the complete old content or the complete new
// content — never a zero-length or half-written file. This assumes the
// filesystem honors fsync (normal local ext4/xfs/zfs do).
//
// It covers ONE file. Two files written one after the other (the store and
// master.key during rotation) are not a transaction: a crash between them
// can leave a new store next to an old key. Rotation handles that with the
// .pre-rotate backup.
//
// Steps: write a temp file in the same directory, fsync it, rename it over
// path, then fsync the directory so the rename itself is on disk. Without
// the two fsyncs, rename can reach disk before the data does, which is how
// a single-file store gets truncated to zero bytes on power loss.
//
// An error means path was NOT replaced and still holds its old content.
// Callers (key rotation in particular) roll back on error, so a failure
// after the rename must not be reported as one — see the SyncDir note below.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmp := f.Name()

	// Any failure before the rename: drop the temp file, leave path alone.
	fail := func(step string, err error) error {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("%s: %w", step, err)
	}

	if err := f.Chmod(perm); err != nil {
		return fail("setting temp file mode", err)
	}
	if _, err := f.Write(data); err != nil {
		return fail("writing temp file", err)
	}
	if err := syncFile(f); err != nil {
		return fail("syncing temp file", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("renaming temp file: %w", err)
	}

	// The new content is now what every reader sees. If the directory fsync
	// fails we log loudly but return nil: returning an error here would make
	// callers roll back as if the old file were still in place, and during
	// master key rotation that pairs a new key file with old DEK wrappers —
	// unrecoverable. The filesystem still flushes the rename on its own, but
	// until it does a power cut can bring back the old content (still a whole
	// file, never a torn one).
	if err := syncDir(dir); err != nil {
		log.Printf("WARNING: %s was replaced but syncing directory %s failed: %v — "+
			"the change may not survive a power loss", path, dir, err)
	}
	return nil
}

// Test seams: tests swap these to inject fsync failures and check ordering.
var (
	syncFile = (*os.File).Sync
	syncDir  = SyncDir
)

// SyncDir fsyncs a directory so that renames and new entries in it are
// durable. Call it after os.Rename when the rename must survive a crash.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
