package config

import (
	"fmt"
	"slices"
	"strings"
)

// dataFile is one file Phoenix uses, for the collision check.
type dataFile struct {
	field    string
	path     string
	written  bool     // the server writes it (else it only reads it)
	besides  []string // suffixes of files the server writes next to it
	resolved []string // where it really is, and its name as written
}

// dataFiles lists every file this config makes Phoenix read or write.
func (c *Config) dataFiles() []dataFile {
	files := []dataFile{
		{field: "acl.path", path: c.ACL.Path, written: true},
		{field: "audit.path", path: c.Audit.Path, written: true},
		{field: "access_requests grants file", path: c.GrantStorePath(), written: true},
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
			dataFile{field: "store.master_key", path: c.Store.MasterKey, written: true, besides: []string{".prev"}})
	}
	if c.Session.Enabled {
		files = append(files, dataFile{field: "role sessions file", path: c.SessionStorePath(), written: true})
	}
	if c.SSHCAEnabled() {
		files = append(files, dataFile{field: "ssh_ca key", path: c.SSHCAKeyPath(), written: true})
	}
	files = slices.DeleteFunc(files, func(f dataFile) bool { return f.path == "" })
	for i, f := range files {
		files[i].resolved = []string{fullyResolved(f.path), parentResolved(f.path)}
	}
	return files
}

// validateDataPaths refuses a config in which a file the server writes is also
// another of its files, or a file it writes next to one (temp, lock, rotation
// backup). Whichever is written last would destroy the other. Files that are
// only read may be shared.
func (c *Config) validateDataPaths() error {
	files := c.dataFiles()
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
			if a.written && (q == p+".lock" || strings.HasPrefix(q, p+".tmp-")) {
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
