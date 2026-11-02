package grant

import (
	"os"

	"github.com/phoenixsec/phoenix/internal/fsutil"
)

// FS is the filesystem the store uses. The default is OSFS{}; tests use
// OSFS with injected AtomicOps, or wrap it, to fail one step on purpose.
type FS interface {
	ReadFile(name string) ([]byte, error)
	// WriteFileAtomic must be durable: temp write, fsync, rename, dir fsync.
	// When the rename happened but the dir fsync failed it must return an
	// error wrapping fsutil.ErrDirSyncFailed.
	WriteFileAtomic(name string, data []byte, perm os.FileMode) error
	// Rename is used only to quarantine a corrupt grants.json.
	Rename(oldpath, newpath string) error
}

// OSFS is the real filesystem. Ops is empty in production; tests set one
// field to inject a failure at that step of the atomic write.
type OSFS struct {
	Ops fsutil.AtomicOps
}

func (o OSFS) ReadFile(name string) ([]byte, error) { return os.ReadFile(name) }

func (o OSFS) WriteFileAtomic(name string, data []byte, perm os.FileMode) error {
	return fsutil.WriteFileAtomicStrictOps(name, data, perm, o.Ops)
}

func (o OSFS) Rename(oldpath, newpath string) error { return os.Rename(oldpath, newpath) }
