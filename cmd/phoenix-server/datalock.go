package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/fsutil"
)

// keyUsersSuffix names the lock every server holds, shared, on its master key
// for as long as it runs. Rotation needs it alone. It is not "<key>.lock",
// which rotate-master and --protect-key hold only while they work.
const keyUsersSuffix = ".users"

// dataLocks are the locks a running server holds.
type dataLocks struct {
	held []*fsutil.FileLock
	key  *fsutil.FileLock // on the master key; nil without one or without locking
}

func (d *dataLocks) release() {
	for _, l := range d.held {
		l.Release()
	}
}

// lockDataFiles makes sure no other phoenix-server uses this one's files. Each
// server keeps them in memory and rewrites them whole, so two on the same file
// silently undo each other's writes: secrets, tokens, revokes. It must run
// before anything is opened, because opening already writes. Where locking is
// not possible the server still starts, with a warning.
func lockDataFiles(cfg *config.Config, logf func(string, ...any)) (*dataLocks, error) {
	d := &dataLocks{}
	take := func(path string, lock func(string) (*fsutil.FileLock, error)) (*fsutil.FileLock, error) {
		l, err := lock(path)
		if errors.Is(err, fsutil.ErrLocked) {
			d.release()
			return nil, fmt.Errorf("%s is in use by another running phoenix-server (it holds %s.lock). "+
				"Two servers on one file undo each other's writes: stop the other one, or give this one its own files", path, path)
		}
		if err != nil {
			logf("WARNING: cannot lock %s (%v): make sure no second phoenix-server uses it", path, err)
			return nil, nil
		}
		d.held = append(d.held, l)
		return l, nil
	}
	paths := []string{cfg.ACL.Path, cfg.GrantStorePath()}
	if cfg.Backend() == "file" {
		paths = append(paths, cfg.Store.Path)
	}
	if cfg.Session.Enabled {
		paths = append(paths, cfg.SessionStorePath())
	}
	for _, p := range paths {
		if fsutil.RealPath(p) == p { // behind a link, a missing directory is a missing volume
			if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
				logf("WARNING: creating %s: %v", filepath.Dir(p), err)
			}
		}
		if _, err := take(p, fsutil.Lock); err != nil {
			return nil, err
		}
	}
	// Appending to one log together is fine, unless someone rotates it: that
	// renames and compresses it under the others.
	if fi, err := os.Stat(cfg.Audit.Path); err != nil || fi.Mode().IsRegular() {
		lock := fsutil.LockShared
		if cfg.AuditRotateBytes() > 0 {
			lock = fsutil.Lock
		}
		if _, err := take(cfg.Audit.Path, lock); err != nil {
			return nil, err
		}
	}
	// Two servers with their own stores may share a key, but then neither may
	// rotate it: the other's store would no longer open.
	if cfg.Backend() == "file" {
		l, err := take(fsutil.RealPath(cfg.Store.MasterKey)+keyUsersSuffix, fsutil.LockShared)
		if err != nil {
			return nil, err
		}
		d.key = l
	}
	return d, nil
}
