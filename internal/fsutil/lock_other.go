//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package fsutil

import (
	"errors"
	"os"
)

const noFollow = 0

// flock is not available on this system.
func flock(*os.File, bool) error { return errors.ErrUnsupported }
