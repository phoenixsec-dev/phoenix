//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package fsutil

import (
	"os"
	"syscall"
)

// owner returns the user and group a file belongs to, if it exists.
func owner(path string) (uid, gid int, ok bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
