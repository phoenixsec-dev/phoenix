//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package fsutil

import (
	"errors"
	"os"
	"syscall"
)

const noFollow = syscall.O_NOFOLLOW

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
