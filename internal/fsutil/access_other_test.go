//go:build !linux

package fsutil

import "errors"

func setTestACL(string) bool { return false }

func makeFIFO(string) error { return errors.ErrUnsupported }
