package fsutil

import "os"

// ReplaceKeepingAccess writes a file whose readers the owner may have set up by
// hand (a TLS key another user was given): it keeps the mode, owner and ACL an
// existing file has. A file that a new one can stand in for is replaced in one
// step, so a failed write leaves the old one whole. One that it cannot (an ACL,
// another user's file, not a regular file) is written in place; use this only
// for files that can be made again.
func ReplaceKeepingAccess(path string, data []byte, perm os.FileMode) error {
	path = RealPath(path)
	fi, err := os.Stat(path)
	if err != nil {
		return WriteFileAtomic(path, data, perm)
	}
	uid, _, known := owner(path)
	if !fi.Mode().IsRegular() || hasACL(path) || (known && uid != os.Geteuid() && os.Geteuid() != 0) {
		return os.WriteFile(path, data, perm)
	}
	return WriteFileAtomic(path, data, fi.Mode().Perm())
}
