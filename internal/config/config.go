// Package config loads and validates Phoenix server configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Config is the top-level server configuration.
type Config struct {
	Server      ServerConfig  `json:"server"`
	Store       StoreConfig   `json:"store"`
	Crypto      CryptoConfig  `json:"crypto"`
	ACL         ACLFileConfig `json:"acl"`
	Audit       AuditConfig   `json:"audit"`
	OnePassword OPConfig      `json:"onepassword,omitempty"`
}

// CryptoConfig controls the key management provider.
type CryptoConfig struct {
	Provider string `json:"provider"` // "file" (default, only option in Phase 2 spike)
}

// ServerConfig controls the HTTP server.
type ServerConfig struct {
	Listen string `json:"listen"` // e.g., "0.0.0.0:9090" (all interfaces) or "127.0.0.1:9090" (loopback only)
}

// StoreConfig controls the secret store.
type StoreConfig struct {
	Path      string `json:"path"`       // Path to encrypted store file
	MasterKey string `json:"master_key"` // Path to master key file
}

// ACLFileConfig points to the ACL definition file.
type ACLFileConfig struct {
	Path string `json:"path"` // Path to ACL JSON file
}

// AuditConfig controls audit logging.
type AuditConfig struct {
	Path string `json:"path"` // Path to audit log file
}

// OPConfig controls the optional 1Password backend.
type OPConfig struct {
	Enabled              bool   `json:"enabled"`
	ServiceAccountTokenEnv string `json:"service_account_token_env,omitempty"`
}

// DefaultConfig returns a config with sensible defaults for /data volume mount.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Listen: "0.0.0.0:9090",
		},
		Store: StoreConfig{
			Path:      "/data/store.json",
			MasterKey: "/data/master.key",
		},
		Crypto: CryptoConfig{
			Provider: "file",
		},
		ACL: ACLFileConfig{
			Path: "/data/acl.json",
		},
		Audit: AuditConfig{
			Path: "/data/audit.log",
		},
		OnePassword: OPConfig{
			Enabled:              false,
			ServiceAccountTokenEnv: "OP_SERVICE_ACCOUNT_TOKEN",
		},
	}
}

// Load reads a config file from disk. Missing file returns defaults.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return cfg, nil
}

// Validate checks that all required fields are set.
func (c *Config) Validate() error {
	if c.Server.Listen == "" {
		return errors.New("server.listen is required")
	}
	if c.Store.Path == "" {
		return errors.New("store.path is required")
	}
	if c.Store.MasterKey == "" {
		return errors.New("store.master_key is required")
	}
	if c.ACL.Path == "" {
		return errors.New("acl.path is required")
	}
	if c.Audit.Path == "" {
		return errors.New("audit.path is required")
	}
	return nil
}

// SaveExample writes a default config to disk as a reference.
func SaveExample(path string) error {
	cfg := DefaultConfig()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
