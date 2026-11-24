package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// dataPathsConfig is a loaded config with every file in dir and nothing shared.
func dataPathsConfig(t *testing.T, dir string) *Config {
	t.Helper()
	file := filepath.Join(dir, "config.json")
	if err := os.WriteFile(file, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(file)
	if err != nil {
		t.Fatal(err)
	}
	in := func(name string) string { return filepath.Join(dir, name) }
	cfg.Store.Path, cfg.Store.MasterKey = in("store.json"), in("master.key")
	cfg.ACL.Path, cfg.Audit.Path, cfg.Policy.Path = in("acl.json"), in("audit.log"), in("policy.json")
	cfg.HTTPSListener = HTTPSListenerConfig{Cert: in("server.crt"), Key: in("server.key"), CACert: in("ca.crt"), CAKey: in("ca.key")}
	cfg.AccessRequests = NewInstallAccessRequests()
	cfg.SSHCA = &SSHCAConfig{Enabled: true, Hosts: map[string]SSHHost{"build-1": {Address: "192.0.2.20"}}}
	cfg.Session = SessionConfig{Enabled: true, Roles: map[string]RoleConfig{"dev": {Namespaces: []string{"dev/*"}, BootstrapTrust: []string{"bearer"}}}}
	return cfg
}

// No file the server writes may be another of its files, or one a write or a
// key rotation makes next to it.
func TestDataPathCollisionsAreRefused(t *testing.T) {
	dir := t.TempDir()
	in := func(name string) string { return filepath.Join(dir, name) }
	if err := dataPathsConfig(t, dir).Validate(); err != nil {
		t.Fatalf("separate files: %v", err)
	}
	link := in("linked")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(c *Config){
		"audit into the master key":    func(c *Config) { c.Audit.Path = c.Store.MasterKey },
		"audit into the store":         func(c *Config) { c.Audit.Path = c.Store.Path },
		"audit into the config":        func(c *Config) { c.Audit.Path = in("config.json") },
		"audit into the policy":        func(c *Config) { c.Audit.Path = c.Policy.Path },
		"audit into the TLS key":       func(c *Config) { c.Audit.Path = c.HTTPSListener.Key },
		"audit into the CA key":        func(c *Config) { c.Audit.Path = c.HTTPSListener.CAKey },
		"audit into the SSH key":       func(c *Config) { c.Audit.Path = in("ssh_ca.key") },
		"store over the ACL":           func(c *Config) { c.Store.Path = c.ACL.Path },
		"store over the key":           func(c *Config) { c.Store.Path = c.Store.MasterKey },
		"store over the old key":       func(c *Config) { c.Store.Path = c.Store.MasterKey + ".prev" },
		"store over the SSH key":       func(c *Config) { c.Store.Path = in("ssh_ca.key") },
		"key over the rotation backup": func(c *Config) { c.Store.MasterKey = c.Store.Path + ".pre-rotate" },
		"key over the emergency key":   func(c *Config) { c.Store.MasterKey = c.Store.Path + ".emergency-key" },
		"ACL over the policy":          func(c *Config) { c.ACL.Path = c.Policy.Path },
		"key over the staged old key":  func(c *Config) { c.Store.Path = c.Store.MasterKey + ".prev.new" },
		"key as an audit archive":      func(c *Config) { c.Store.MasterKey = in("audit-20261108T120000.000Z.log") },
		"store as a gzipped archive":   func(c *Config) { c.Store.Path = in("audit-20261108T120000.000Z.log.gz") },
		"ACL as a half-gzipped one":    func(c *Config) { c.ACL.Path = in("audit-20261108T120000.000Z.log.gz.tmp") },
		"store over the users lock":    func(c *Config) { c.Store.Path = c.Store.MasterKey + ".users" },
		"key as a .gz log's archive": func(c *Config) {
			c.Audit.Path, c.Store.MasterKey = in("audit.gz"), in("audit-20261108T120000.000Z.gz")
		},
		"store as quarantined grants": func(c *Config) { c.Store.Path = in("grants.json.corrupt-1790000000") },
		"ACL over a lock file":        func(c *Config) { c.ACL.Path = c.Store.Path + ".lock" },
		"through a linked directory":  func(c *Config) { c.Store.Path = filepath.Join(link, "acl.json") },
		"grants over the config":      func(c *Config) { c.AccessRequests.StorePath = in("config.json") },
		"grants over the TLS key":     func(c *Config) { c.AccessRequests.StorePath = c.HTTPSListener.Key },
		"grants over the SSH key":     func(c *Config) { c.AccessRequests.StorePath = in("ssh_ca.key") },
		"SSH key over the config":     func(c *Config) { c.SSHCA.KeyPath = in("config.json") },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := dataPathsConfig(t, dir)
			change(cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "same file") {
				t.Errorf("Validate = %v, want a same-file error", err)
			}
		})
	}
}

// A hard link is the same file under another name.
func TestDataPathHardLinkIsRefused(t *testing.T) {
	dir := t.TempDir()
	cfg := dataPathsConfig(t, dir)
	if err := os.WriteFile(cfg.Store.MasterKey, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(cfg.Store.MasterKey, cfg.Audit.Path); err != nil {
		t.Skip(err)
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "same file") {
		t.Errorf("Validate = %v, want a same-file error", err)
	}
}

// Two links to one file that does not exist yet are one file.
func TestDataPathDanglingLinksAreRefused(t *testing.T) {
	dir := t.TempDir()
	cfg := dataPathsConfig(t, dir)
	for _, p := range []string{cfg.Store.Path, cfg.Audit.Path} {
		if err := os.Symlink(filepath.Join(dir, "not-yet"), p); err != nil {
			t.Fatal(err)
		}
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "same file") {
		t.Errorf("Validate = %v, want a same-file error", err)
	}
}

// Nor do directories that do not exist yet hide that two paths are one.
func TestDataPathMissingParentsAreResolved(t *testing.T) {
	dir := t.TempDir()
	cfg := dataPathsConfig(t, dir)
	if err := errors.Join(os.Mkdir(filepath.Join(dir, "run"), 0700), os.Symlink("run", filepath.Join(dir, "var"))); err != nil {
		t.Fatal(err)
	}
	cfg.Store.Path, cfg.Audit.Path = filepath.Join(dir, "run", "not", "yet", "x"), filepath.Join(dir, "var", "not", "yet", "x")
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "same file") {
		t.Errorf("Validate = %v, want a same-file error", err)
	}
}

// A missing config file still counts: the server must not create it as its
// own audit log.
func TestMissingConfigFileIsProtected(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-there")
	cfg, err := Load(file)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Audit.Path = file
	if err := cfg.validateDataPaths(); err == nil || !strings.Contains(err.Error(), "same file") {
		t.Errorf("got %v, want a same-file error", err)
	}
}

// Sharing that harms nothing keeps working: files only read may be one file,
// and with the 1Password backend the store and key paths are not used.
func TestHarmlessPathSharingIsAllowed(t *testing.T) {
	cfg := dataPathsConfig(t, t.TempDir())
	cfg.HTTPSListener.Key = cfg.HTTPSListener.Cert // one PEM with both
	if err := cfg.Validate(); err != nil {
		t.Errorf("combined certificate: %v", err)
	}
	// Temp files are made under a free name, so these never meet.
	cfg = dataPathsConfig(t, t.TempDir())
	cfg.ACL.Path = cfg.Store.Path + ".tmp-acl"
	if err := cfg.Validate(); err != nil {
		t.Errorf("shared prefix: %v", err)
	}
	// Names that only look like ones Phoenix makes.
	for _, name := range []string{"grants.json.corrupt-copy", "audit-notes.log"} {
		cfg = dataPathsConfig(t, t.TempDir())
		cfg.ACL.Path = filepath.Join(filepath.Dir(cfg.ACL.Path), name)
		if err := cfg.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Without rotation there are no archives.
	cfg = dataPathsConfig(t, t.TempDir())
	cfg.Audit.RotateMB, cfg.ACL.Path = -1, filepath.Join(filepath.Dir(cfg.ACL.Path), "audit-20261108T120000.000Z.log")
	if err := cfg.Validate(); err != nil {
		t.Errorf("no rotation: %v", err)
	}
	cfg = dataPathsConfig(t, t.TempDir())
	cfg.Store.Backend, cfg.OnePassword.Vault = "1password", "v"
	cfg.Store.MasterKey = cfg.Store.Path
	if err := cfg.Validate(); err != nil {
		t.Errorf("1password: %v", err)
	}
}
