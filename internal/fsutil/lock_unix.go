//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package fsutil

import (
	"errors"
	"os"
	"syscall"
)

const openSafely = syscall.O_NOFOLLOW | syscall.O_NONBLOCK

// plainEmptyFile reports whether f is what a lock file is: an empty regular
// file with one name. Giving away anything else could give away another file.
func plainEmptyFile(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() != 0 {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Nlink == 1
}

// flock locks f without waiting.
func flock(f *os.File, exclusive bool) error {
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	err := syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return ErrLocked
	}
	return err
}
