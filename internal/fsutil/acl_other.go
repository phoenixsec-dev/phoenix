//go:build !linux

package fsutil

import "os"

// copyACL is only needed where POSIX ACLs are kept in xattrs.
func copyACL(string, *os.File, os.FileMode) {}
