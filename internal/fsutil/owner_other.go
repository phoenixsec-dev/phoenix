//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package fsutil

// owner is not available on this system.
func owner(string) (uid, gid int, ok bool) { return 0, 0, false }
