//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package fsutil

import "syscall"

func makeFIFO(path string) error { return syscall.Mkfifo(path, 0600) }
