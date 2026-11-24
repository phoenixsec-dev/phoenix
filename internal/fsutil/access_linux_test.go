package fsutil

import "syscall"

func setTestACL(path string) bool {
	return syscall.Setxattr(path, "system.posix_acl_access", testACL(), 0) == nil
}

func makeFIFO(path string) error { return syscall.Mkfifo(path, 0600) }
