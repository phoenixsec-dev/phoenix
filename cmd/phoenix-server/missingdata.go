package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/phoenixsec/phoenix/internal/audit"
	"github.com/phoenixsec/phoenix/internal/config"
)

// refuseMissingData stops a start that would begin an empty access list or an
// empty store where there was a real one: a volume not mounted, a wrong path, a
// deleted file. The next write would take the real file's place.
//
// The access list is made by --init, and nobody can log in without one, so it
// must be there. So is the store, but before v0.25.0 the first secret made it, so
// an older install without secrets has none. The audit log tells those apart:
// once it has a line about a secret that was written or handed over, there was a
// store.
//
// storeThere tells whether the store file is there now. A file can still go away
// before it is read, so the reads refuse that too (openFileStore, acl.NewExisting).
func refuseMissingData(cfg *config.Config) (storeThere bool, err error) {
	if missing(cfg.ACL.Path) {
		return false, fmt.Errorf("acl.path: %[1]s is not there, so no agent could log in. Check that its disk is mounted and the path is right, "+
			"or put the file back from a backup. For a new install run phoenix-server --init <directory>. "+
			`To start without agents on purpose, make that file with this text in it: {"agents":{}}`, cfg.ACL.Path)
	}
	if cfg.Backend() != "file" {
		return false, nil
	}
	if !missing(cfg.Store.Path) {
		return true, nil
	}
	const next = "Check that its disk is mounted and the path is right, or put the file back from a backup. " +
		`To start with an empty store on purpose, make that file with this text in it: {"version":1,"secrets":{},"namespaces":{}}`
	used, err := audit.MentionsSecrets(cfg.Audit.Path)
	if err != nil {
		return false, fmt.Errorf("store.path: %[1]s is not there, and the audit log cannot be read to see if it ever was (%[2]w). %[3]s", cfg.Store.Path, err, next)
	}
	if used {
		return false, fmt.Errorf("store.path: %[1]s is not there, but the audit log %[2]s says secrets were kept here. "+
			"Starting would put an empty store in its place. %[3]s", cfg.Store.Path, cfg.Audit.Path, next)
	}
	return false, nil
}

// missing reports whether there is nothing at path, or only a link to nothing.
func missing(path string) bool {
	_, err := os.Stat(path)
	return errors.Is(err, os.ErrNotExist)
}
