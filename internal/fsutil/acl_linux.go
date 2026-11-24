package fsutil

import (
	"os"
	"syscall"
)

const posixACL = "system.posix_acl_access"

// copyACL gives f the POSIX access ACL of the file at path, if it has one, so
// that replacing a key does not take away a user's setfacl access to it. It is
// skipped when perm is not the file's own mode: an ACL would override it.
func copyACL(path string, f *os.File, perm os.FileMode) {
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != perm {
		return
	}
	buf := make([]byte, 4096)
	if n, err := syscall.Getxattr(path, posixACL, buf); err == nil && n > 0 {
		_ = syscall.Setxattr(f.Name(), posixACL, buf[:n], 0)
	}
}
