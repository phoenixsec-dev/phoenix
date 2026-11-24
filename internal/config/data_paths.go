package config

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/phoenixsec/phoenix/internal/fsutil"
)

// dataFile is one file Phoenix uses, for the collision check.
type dataFile struct {
	field    string
	path     string
	written  bool     // the server writes it (else it only reads it)
	besides  []string // suffixes of files the server writes next to it
	archives bool     // the server also makes dated archives of it (audit log)
	resolved []string // where it really is, and its name as written
}

const grantsField = "access_requests grants file"

// archiveStamp is the time in a rotated audit log's name (internal/audit).
var archiveStamp = regexp.MustCompile(`^\d{8}T\d{6}\.\d{3}Z$`)

// isArchiveOf reports whether q is a name audit rotation gives an archive of
// the log at p, or a compressed or half-compressed one. The server compresses
// and then removes files with such names.
func isArchiveOf(p, q string) bool {
	if filepath.Dir(p) != filepath.Dir(q) {
		return false
	}
	ext := filepath.Ext(p)
	rest, ok := strings.CutPrefix(q, strings.TrimSuffix(p, ext)+"-")
	if !ok {
		return false
	}
	rest = strings.TrimSuffix(strings.TrimSuffix(rest, ".tmp"), ".gz")
	stamp, ok := strings.CutSuffix(rest, ext)
	return ok && archiveStamp.MatchString(stamp)
}

// dataFiles lists every file this config makes Phoenix read or write.
func (c *Config) dataFiles() []dataFile {
	files := []dataFile{
		{field: "acl.path", path: c.ACL.Path, written: true},
		{field: "audit.path", path: c.Audit.Path, written: true, archives: true},
		{field: grantsField, path: c.GrantStorePath(), written: true},
		{field: "config file", path: c.file},
		{field: "policy.path", path: c.Policy.Path},
		{field: "https_listener.cert", path: c.HTTPSListener.Cert},
		{field: "https_listener.key", path: c.HTTPSListener.Key},
		{field: "https_listener.ca_cert", path: c.HTTPSListener.CACert},
		{field: "https_listener.ca_key", path: c.HTTPSListener.CAKey},
	}
	if c.Backend() == "file" {
		files = append(files,
			dataFile{field: "store.path", path: c.Store.Path, written: true, besides: []string{".pre-rotate", ".emergency-key"}},
			dataFile{field: "store.master_key", path: c.Store.MasterKey, written: true, besides: []string{".prev", ".prev.new", ".users.lock"}})
	}
	if c.Session.Enabled {
		files = append(files, dataFile{field: "role sessions file", path: c.SessionStorePath(), written: true})
	}
	if c.SSHCAEnabled() {
		files = append(files, dataFile{field: "ssh_ca key", path: c.SSHCAKeyPath(), written: true})
	}
	files = slices.DeleteFunc(files, func(f dataFile) bool { return f.path == "" })
	for i, f := range files {
		// RealPath too: unlike fullyResolved it follows a link whose target
		// does not exist yet, as the writers do.
		files[i].resolved = []string{parentResolved(f.path), fullyResolved(f.path), parentResolved(fsutil.RealPath(f.path))}
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
	for _, p := range a.resolved {
		for _, q := range b.resolved {
			if p == q {
				return true
			}
			if a.written && q == p+".lock" {
				return true
			}
			if a.archives && isArchiveOf(p, q) {
				return true
			}
			// A damaged grants file is moved aside under this name.
			if a.field == grantsField && strings.HasPrefix(q, p+".corrupt-") {
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
