//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package fsutil

import (
	"errors"
	"os"
)

const openSafely = 0

func plainEmptyFile(*os.File) bool { return true }

// flock is not available on this system.
func flock(*os.File, bool) error { return errors.ErrUnsupported }
