package fsutil

import "syscall"

// hasACL reports whether a file has a POSIX access ACL (setfacl).
func hasACL(path string) bool {
	n, err := syscall.Getxattr(path, "system.posix_acl_access", nil)
	return err == nil && n > 0
}
