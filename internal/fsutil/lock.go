package fsutil

import (
	"errors"
	"os"
)

// ErrLocked means another process holds the lock.
var ErrLocked = errors.New("in use by another process")

// Lock marks path as in use by this process, through an empty "<path>.lock"
// file next to it (next to the real file if path is a symlink). The lock ends
// with release or with the process, however it dies; the lock file stays and
// means nothing by itself. A second Lock on the same path gets ErrLocked. Any
// other error means locking does not work here (read-only directory, odd
// filesystem), which callers should report but not treat as a conflict.
func Lock(path string) (release func(), err error) {
	f, err := os.OpenFile(RealPath(path)+".lock", os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	if err := flock(f); err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}
