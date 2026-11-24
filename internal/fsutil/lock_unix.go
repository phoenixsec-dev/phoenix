//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package fsutil

import (
	"errors"
	"os"
	"syscall"
)

// flock takes an exclusive lock on f without waiting.
func flock(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return ErrLocked
	}
	return err
}
