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
// must be there. The store file is made by the first secret, so on a new install
// it is missing too. The audit log tells those apart: once it has a line about a
// secret that was written or handed over, there was a store.
func refuseMissingData(cfg *config.Config) error {
	if missing(cfg.ACL.Path) {
		return fmt.Errorf("acl.path: %[1]s is not there, so no agent could log in. Check that its disk is mounted and the path is right, "+
			"or put the file back from a backup. For a new install run phoenix-server --init <directory>. "+
			"To start without agents on purpose: echo '{\"agents\":{}}' > %[1]s", cfg.ACL.Path)
	}
	if cfg.Backend() != "file" || !missing(cfg.Store.Path) {
		return nil
	}
	const next = "Check that its disk is mounted and the path is right, or put the file back from a backup. " +
		"To start with an empty store on purpose: echo '{\"version\":1,\"secrets\":{},\"namespaces\":{}}' > "
	used, err := audit.MentionsSecrets(cfg.Audit.Path)
	if err != nil {
		return fmt.Errorf("store.path: %[1]s is not there, and the audit log cannot be read to see if it ever was (%[2]w). %[3]s%[1]s", cfg.Store.Path, err, next)
	}
	if used {
		return fmt.Errorf("store.path: %[1]s is not there, but the audit log %[2]s says secrets were kept here. "+
			"Starting would put an empty store in its place. %[3]s%[1]s", cfg.Store.Path, cfg.Audit.Path, next)
	}
	return nil
}

// missing reports whether there is nothing at path, or only a link to nothing.
func missing(path string) bool {
	_, err := os.Stat(path)
	return errors.Is(err, os.ErrNotExist)
}
