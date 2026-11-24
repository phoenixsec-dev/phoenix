//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package fsutil

import (
	"errors"
	"os"
)

// flock is not available on this system.
func flock(*os.File) error { return errors.ErrUnsupported }
