package fsutil

import (
	"errors"
	"os"
	"path/filepath"
)

// WriteFileNew writes a file that must not exist yet. It appears at path whole
// and synced, or not at all, and never replaces another: if something is there
// (or gets there first) the error is os.ErrExist.
func WriteFileNew(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	_, err = f.Write(data)
	err = errors.Join(f.Chmod(perm), err, f.Sync(), f.Close())
	if err != nil {
		return err
	}
	// Link fails if path exists, where rename would replace it.
	err = os.Link(tmp, path)
	if err != nil && !errors.Is(err, os.ErrExist) {
		// No hard links here (some network and FUSE mounts): take the name
		// first, then rename over our own empty file.
		g, gerr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if gerr != nil {
			return gerr
		}
		g.Close()
		if err = os.Rename(tmp, path); err != nil {
			os.Remove(path)
		}
	}
	if err != nil {
		return err
	}
	return SyncDir(filepath.Dir(path))
}
