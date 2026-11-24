package fsutil

import (
	"errors"
	"syscall"
)

// NoSpace reports whether err means the disk (or the owner's quota on it) is
// full. That is no reason to keep a server from starting on files it can read.
func NoSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT)
}
