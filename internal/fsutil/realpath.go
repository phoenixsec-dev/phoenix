package fsutil

import (
	"os"
	"path/filepath"
)

// RealPath follows path while its last element is a symlink and returns the
// file it leads to, which need not exist yet. Replacing that file keeps the
// link; renaming over path itself would replace the link and strand the
// content on the wrong disk. A path that is not a symlink, or that leads to
// something other than a regular file (/dev/stdout), comes back unchanged.
func RealPath(path string) string {
	if fi, err := os.Stat(path); err == nil && !fi.Mode().IsRegular() {
		return path
	}
	p := path
	for i := 0; ; i++ {
		target, err := os.Readlink(p)
		if err != nil {
			break // not a symlink, or nothing there
		}
		if i == 40 {
			return path // a loop; using it will fail with a clear error
		}
		if !filepath.IsAbs(target) {
			// Split, not Dir: Dir would clean a ".." away before any
			// symlink in front of it is followed.
			dir, _ := filepath.Split(p)
			target = dir + target
		}
		p = target
	}
	if p == path {
		return path
	}
	dir, base := filepath.Split(p)
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		return filepath.Join(real, base)
	}
	return p // its directory is missing, so writing there fails
}
