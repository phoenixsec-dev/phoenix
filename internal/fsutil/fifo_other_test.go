//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package fsutil

import "errors"

func makeFIFO(string) error { return errors.ErrUnsupported }
