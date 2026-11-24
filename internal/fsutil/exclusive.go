package fsutil

import (
	"errors"
	"os"
	"path/filepath"
)

// linkFile is a test seam: some filesystems have no hard links.
var linkFile = os.Link

// WriteFileNew writes a file that must not exist yet and never replaces one:
// if something is there (or gets there first) the error is os.ErrExist. Where
// hard links work the file appears whole and synced, or not at all.
func WriteFileNew(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(data)
	if err = errors.Join(f.Chmod(perm), err, f.Sync(), f.Close()); err != nil {
		return err
	}
	// Link fails if path exists, where rename would replace it.
	err = linkFile(f.Name(), path)
	if err != nil && !errors.Is(err, os.ErrExist) {
		err = writeExclusive(path, data, perm) // no hard links here
	}
	if err != nil {
		return err
	}
	return SyncDir(filepath.Dir(path))
}

// writeExclusive creates path directly and removes it again if that fails.
func writeExclusive(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err = errors.Join(err, f.Sync(), f.Close()); err != nil {
		os.Remove(path)
	}
	return err
}
