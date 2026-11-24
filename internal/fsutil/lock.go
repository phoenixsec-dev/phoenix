package fsutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrLocked means another process holds the lock.
var ErrLocked = errors.New("in use by another process")

// FileLock is a held lock; see Lock.
type FileLock struct{ f *os.File }

// Lock marks path as in use by this process alone, through an empty
// "<path>.lock" file next to it (next to the real file if path is a symlink).
// The lock ends with Release or with the process, however it dies; the lock
// file stays and means nothing by itself. If someone else holds it the error
// is ErrLocked. Any other error means locking does not work here (read-only
// directory, odd filesystem), which callers should report but not treat as a
// conflict.
func Lock(path string) (*FileLock, error) { return lock(path, ".lock", true) }

// LockShared is Lock for a use that others may share: it conflicts only with
// Lock and Exclusive.
func LockShared(path string) (*FileLock, error) { return lock(path, ".lock", false) }

// LockUsers is a second, shared lock on path, independent of Lock: "I am using
// this file", held for long, next to "I am changing it", held briefly.
func LockUsers(path string) (*FileLock, error) { return lock(path, ".users.lock", false) }

func lock(path, suffix string, exclusive bool) (*FileLock, error) {
	path = RealPath(path)
	// Read-only is enough to lock. Whatever someone left at this name is not
	// followed and not waited for.
	f, err := os.OpenFile(path+suffix, os.O_RDONLY|os.O_CREATE|openSafely, 0600)
	if err != nil {
		return nil, err
	}
	if !plainEmptyFile(f) {
		f.Close()
		return nil, fmt.Errorf("%s is not an empty lock file", f.Name())
	}
	// Made by root, it must still open for the user whose file it guards, or
	// that user could not lock at all.
	uid, gid, ok := owner(path)
	if !ok {
		uid, gid, ok = owner(filepath.Dir(path))
	}
	if ok {
		_ = f.Chown(uid, gid)
	}
	if err := flock(f, exclusive); err != nil {
		f.Close()
		return nil, err
	}
	return &FileLock{f}, nil
}

// Exclusive turns a shared lock into one nobody else shares, or fails with
// ErrLocked and leaves it shared. Share turns it back.
func (l *FileLock) Exclusive() error {
	err := flock(l.f, true)
	if err != nil {
		_ = flock(l.f, false) // the failed attempt may have dropped it
	}
	return err
}

// Share turns an exclusive lock into a shared one.
func (l *FileLock) Share() error { return flock(l.f, false) }

// Release ends the lock.
func (l *FileLock) Release() { l.f.Close() }
