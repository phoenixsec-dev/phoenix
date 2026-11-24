package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/phoenixsec/phoenix/internal/audit"
	"github.com/phoenixsec/phoenix/internal/fsutil"
)

// dataFile is one file Phoenix uses, for the collision check.
type dataFile struct {
	field    string
	path     string
	written  bool     // the server writes it (else it only reads it)
	besides  []string // suffixes of files the server writes next to it
	locks    []string // suffixes of the empty lock files it holds next to it
	archives bool     // the server also makes dated archives of it (audit log)
	resolved []string // where it really is, and its name as written
	lockBase string   // what lock file names start with: next to the real file
}

const grantsField = "access_requests grants file"

// quarantined is what the grants store adds to a damaged file's name.
var quarantined = regexp.MustCompile(`^\.corrupt-\d+$`)

// resolved returns p with every symlink and ".." above its last element
// resolved as far as the directories exist, so that two spellings of one file
// that is not there yet are seen to be one.
func resolved(p string) string {
	p = parentResolved(p)
	rest := ""
	for dir := p; dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		if dir != p {
			if real, err := filepath.EvalSymlinks(dir); err == nil {
				return filepath.Join(real, rest)
			}
		}
		rest = filepath.Join(filepath.Base(dir), rest)
	}
	return p
}

// dataFiles lists every file this config makes Phoenix read or write.
func (c *Config) dataFiles() []dataFile {
	lock := []string{".lock"}
	auditLock := lock
	if fi, err := os.Stat(c.Audit.Path); err == nil && !fi.Mode().IsRegular() {
		auditLock = nil // /dev/stdout and the like are not locked
	}
	files := []dataFile{
		{field: "acl.path", path: c.ACL.Path, written: true, locks: lock},
		{field: "audit.path", path: c.Audit.Path, written: true, locks: auditLock, archives: c.AuditRotateBytes() > 0},
		{field: grantsField, path: c.GrantStorePath(), written: true, locks: lock},
		{field: "config file", path: c.file},
		{field: "policy.path", path: c.Policy.Path},
		{field: "https_listener.cert", path: c.HTTPSListener.Cert},
		{field: "https_listener.key", path: c.HTTPSListener.Key},
		{field: "https_listener.ca_cert", path: c.HTTPSListener.CACert},
		{field: "https_listener.ca_key", path: c.HTTPSListener.CAKey},
	}
	if c.Backend() == "file" {
		files = append(files,
			dataFile{field: "store.path", path: c.Store.Path, written: true, locks: lock, besides: []string{".pre-rotate", ".emergency-key"}},
			dataFile{field: "store.master_key", path: c.Store.MasterKey, written: true, locks: []string{".lock", ".users.lock"}, besides: []string{".prev", ".prev.new"}})
	}
	if c.Session.Enabled {
		files = append(files, dataFile{field: "role sessions file", path: c.SessionStorePath(), written: true, locks: lock})
	}
	if c.SSHCAEnabled() {
		files = append(files, dataFile{field: "ssh_ca key", path: c.SSHCAKeyPath(), written: true})
	}
	files = slices.DeleteFunc(files, func(f dataFile) bool { return f.path == "" })
	for i, f := range files {
		// RealPath too: unlike fullyResolved it follows a link whose target
		// does not exist yet, as the writers do.
		files[i].resolved = []string{resolved(f.path), fullyResolved(f.path), resolved(fsutil.RealPath(f.path))}
		files[i].lockBase = files[i].resolved[2]
	}
	return files
}

// validateDataPaths refuses a config in which a file the server writes is also
// another of its files, or a file it writes next to one (temp, lock, rotation
// backup). Whichever is written last would destroy the other. Files that are
// only read may be shared.
func (c *Config) validateDataPaths() error {
	return checkDataFiles(c.dataFiles())
}

// ValidateReissuePaths is the same check for --reissue-cert, which also writes
// the server certificate, its key and the CA certificate.
func (c *Config) ValidateReissuePaths() error {
	files := c.dataFiles()
	for i, f := range files {
		if strings.HasPrefix(f.field, "https_listener.") {
			files[i].written = true
		}
	}
	return checkDataFiles(files)
}

func checkDataFiles(files []dataFile) error {
	for i, a := range files {
		for _, b := range files[i+1:] {
			if (a.written || b.written) && (a.hits(b) || b.hits(a)) {
				return fmt.Errorf("%s %q and %s %q are the same file (or one is a file Phoenix writes next to the other); "+
					"give each its own path", a.field, a.path, b.field, b.path)
			}
		}
	}
	return nil
}

// hits reports whether b is a's file, or a file the server writes next to it.
func (a dataFile) hits(b dataFile) bool {
	if sameFile(a.path, b.path) {
		return true
	}
	for _, l := range a.locks {
		if slices.Contains(b.resolved, a.lockBase+l) {
			return true
		}
		for _, m := range b.locks { // both would hold one lock file
			if a.lockBase+l == b.lockBase+m {
				return true
			}
		}
	}
	for _, p := range a.resolved {
		for _, q := range b.resolved {
			if p == q {
				return true
			}
			if a.archives && audit.UsesName(p, q) {
				return true
			}
			// A damaged grants file is moved aside under this name.
			if tail, ok := strings.CutPrefix(q, p); ok && a.field == grantsField && quarantined.MatchString(tail) {
				return true
			}
			for _, s := range a.besides {
				if q == p+s {
					return true
				}
			}
		}
	}
	return false
}
