//go:build !linux

package fsutil

// hasACL is only known on Linux.
func hasACL(string) bool { return false }
