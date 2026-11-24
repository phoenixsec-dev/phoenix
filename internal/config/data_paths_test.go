package config

import (
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
		"ACL over a store temp file":   func(c *Config) { c.ACL.Path = c.Store.Path + ".tmp-1" },
		"ACL over a lock file":         func(c *Config) { c.ACL.Path = c.Store.Path + ".lock" },
		"through a linked directory":   func(c *Config) { c.Store.Path = filepath.Join(link, "acl.json") },
		"grants over the config":       func(c *Config) { c.AccessRequests.StorePath = in("config.json") },
		"grants over the TLS key":      func(c *Config) { c.AccessRequests.StorePath = c.HTTPSListener.Key },
		"grants over the SSH key":      func(c *Config) { c.AccessRequests.StorePath = in("ssh_ca.key") },
		"SSH key over the config":      func(c *Config) { c.SSHCA.KeyPath = in("config.json") },
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

// Sharing that harms nothing keeps working: files only read may be one file,
// and with the 1Password backend the store and key paths are not used.
func TestHarmlessPathSharingIsAllowed(t *testing.T) {
	cfg := dataPathsConfig(t, t.TempDir())
	cfg.HTTPSListener.Key = cfg.HTTPSListener.Cert // one PEM with both
	if err := cfg.Validate(); err != nil {
		t.Errorf("combined certificate: %v", err)
	}
	cfg = dataPathsConfig(t, t.TempDir())
	cfg.Store.Backend, cfg.OnePassword.Vault = "1password", "v"
	cfg.Store.MasterKey = cfg.Store.Path
	if err := cfg.Validate(); err != nil {
		t.Errorf("1password: %v", err)
	}
}
