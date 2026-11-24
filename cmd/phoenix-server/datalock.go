package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/fsutil"
)

// lockDataFiles makes sure no other phoenix-server uses this one's files. Each
// server keeps them in memory and rewrites them whole, so two on the same file
// silently undo each other's writes: secrets, tokens, revokes. It must run
// before anything is opened, because opening already writes. Where locking is
// not possible the server still starts, with a warning.
func lockDataFiles(cfg *config.Config, logf func(string, ...any)) (release func(), err error) {
	paths := []string{cfg.ACL.Path, cfg.GrantStorePath()}
	if cfg.Backend() == "file" {
		paths = append(paths, cfg.Store.Path)
	}
	if cfg.Session.Enabled {
		paths = append(paths, cfg.SessionStorePath())
	}
	// A rotating log is renamed and compressed under a second writer.
	if fi, err := os.Stat(cfg.Audit.Path); cfg.AuditRotateBytes() > 0 && (err != nil || fi.Mode().IsRegular()) {
		paths = append(paths, cfg.Audit.Path)
	}
	var held []func()
	release = func() {
		for _, r := range held {
			r()
		}
	}
	for _, p := range paths {
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			logf("WARNING: creating %s: %v", filepath.Dir(p), err)
		}
		r, err := fsutil.Lock(p)
		if errors.Is(err, fsutil.ErrLocked) {
			release()
			return nil, fmt.Errorf("%s is in use by another running phoenix-server (it holds %s.lock). "+
				"Two servers on one file undo each other's writes: stop the other one, or give this one its own files", p, p)
		}
		if err != nil {
			logf("WARNING: cannot lock %s (%v): make sure no second phoenix-server uses it", p, err)
			continue
		}
		held = append(held, r)
	}
	return release, nil
}
