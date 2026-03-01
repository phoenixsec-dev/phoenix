// Package config loads and validates Phoenix server configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// Config is the top-level server configuration.
type Config struct {
	Server      ServerConfig      `json:"server"`
	Store       StoreConfig       `json:"store"`
	Crypto      CryptoConfig      `json:"crypto"`
	Auth        AuthConfig        `json:"auth"`
	ACL         ACLFileConfig     `json:"acl"`
	Audit       AuditConfig       `json:"audit"`
	Policy      PolicyConfig      `json:"policy,omitempty"`
	Attestation AttestationConfig `json:"attestation,omitempty"`
	OnePassword OPConfig          `json:"onepassword,omitempty"`
}

// AuthConfig controls authentication methods.
type AuthConfig struct {
	Bearer BearerAuthConfig `json:"bearer"`
	MTLS   MTLSConfig       `json:"mtls"`
}

// BearerAuthConfig controls bearer token authentication.
type BearerAuthConfig struct {
	Enabled bool `json:"enabled"`
}

// MTLSConfig controls mTLS client certificate authentication.
type MTLSConfig struct {
	Enabled    bool   `json:"enabled"`
	CACert     string `json:"ca_cert,omitempty"`
	CAKey      string `json:"ca_key,omitempty"`
	ServerCert string `json:"server_cert,omitempty"` // Leaf cert for TLS server identity
	ServerKey  string `json:"server_key,omitempty"`  // Key for TLS server identity
	CRLPath    string `json:"crl_path,omitempty"`    // Path to CRL file for persistence
	Require    bool   `json:"require"`               // If true, reject connections without client cert
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
	Backend   string `json:"backend,omitempty"` // "file" (default), "1password"
	Path      string `json:"path"`              // Path to encrypted store file
	MasterKey string `json:"master_key"`        // Path to master key file
}

// ACLFileConfig points to the ACL definition file.
type ACLFileConfig struct {
	Path string `json:"path"` // Path to ACL JSON file
}

// AuditConfig controls audit logging.
type AuditConfig struct {
	Path string `json:"path"` // Path to audit log file
}

// PolicyConfig controls the optional attestation policy engine.
type PolicyConfig struct {
	Path string `json:"path,omitempty"` // Path to attestation policy JSON file
}

// AttestationConfig controls optional attestation components
// (nonce challenge-response, short-lived tokens, and local agent).
// All are disabled by default and enabled explicitly.
type AttestationConfig struct {
	Nonce      NonceConfig      `json:"nonce,omitempty"`
	Token      TokenConfig      `json:"token,omitempty"`
	LocalAgent LocalAgentConfig `json:"local_agent,omitempty"`
}

// LocalAgentConfig controls the local Unix socket attestation agent.
type LocalAgentConfig struct {
	Enabled    bool   `json:"enabled"`
	SocketPath string `json:"socket_path,omitempty"` // default: /tmp/phoenix-agent.sock
}

// NonceConfig controls the nonce challenge-response store.
type NonceConfig struct {
	Enabled bool   `json:"enabled"`
	MaxAge  string `json:"max_age,omitempty"` // duration string, e.g. "30s" (default)
}

// TokenConfig controls short-lived token minting.
type TokenConfig struct {
	Enabled bool   `json:"enabled"`
	TTL     string `json:"ttl,omitempty"` // duration string, e.g. "15m" (default)
}

// OPConfig controls the optional 1Password backend.
type OPConfig struct {
	Enabled                bool   `json:"enabled"`
	Vault                  string `json:"vault,omitempty"`                     // 1Password vault name
	ServiceAccountTokenEnv string `json:"service_account_token_env,omitempty"` // env var name (default: OP_SERVICE_ACCOUNT_TOKEN)
	CacheTTL               string `json:"cache_ttl,omitempty"`                 // duration string, e.g. "60s" (default)
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
		Auth: AuthConfig{
			Bearer: BearerAuthConfig{Enabled: true},
			MTLS:   MTLSConfig{Enabled: false},
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

// Backend returns the effective backend name, defaulting to "file".
func (c *Config) Backend() string {
	if c.Store.Backend == "" {
		return "file"
	}
	return c.Store.Backend
}

// Validate checks that all required fields are set.
func (c *Config) Validate() error {
	if c.Server.Listen == "" {
		return errors.New("server.listen is required")
	}

	// Validate backend selection
	switch c.Backend() {
	case "file":
		if c.Store.Path == "" {
			return errors.New("store.path is required for file backend")
		}
		if c.Store.MasterKey == "" {
			return errors.New("store.master_key is required for file backend")
		}
	case "1password":
		if c.OnePassword.Vault == "" {
			return errors.New("onepassword.vault is required when store.backend is \"1password\"")
		}
		if c.OnePassword.CacheTTL != "" {
			if _, err := time.ParseDuration(c.OnePassword.CacheTTL); err != nil {
				return fmt.Errorf("onepassword.cache_ttl: invalid duration %q: %w", c.OnePassword.CacheTTL, err)
			}
		}
	default:
		return fmt.Errorf("store.backend: unknown backend %q (supported: file, 1password)", c.Store.Backend)
	}

	if c.ACL.Path == "" {
		return errors.New("acl.path is required")
	}
	if c.Audit.Path == "" {
		return errors.New("audit.path is required")
	}
	// At least one auth mode must be enabled
	if !c.Auth.Bearer.Enabled && !c.Auth.MTLS.Enabled {
		return errors.New("at least one auth mode must be enabled (auth.bearer.enabled or auth.mtls.enabled)")
	}
	// mTLS requires CA and server cert paths
	if c.Auth.MTLS.Enabled {
		if c.Auth.MTLS.CACert == "" || c.Auth.MTLS.CAKey == "" {
			return errors.New("auth.mtls.enabled requires ca_cert and ca_key paths")
		}
		if c.Auth.MTLS.ServerCert == "" || c.Auth.MTLS.ServerKey == "" {
			return errors.New("auth.mtls.enabled requires server_cert and server_key paths")
		}
	}
	// Validate attestation duration strings
	if c.Attestation.Nonce.Enabled && c.Attestation.Nonce.MaxAge != "" {
		if _, err := time.ParseDuration(c.Attestation.Nonce.MaxAge); err != nil {
			return fmt.Errorf("attestation.nonce.max_age: invalid duration %q: %w", c.Attestation.Nonce.MaxAge, err)
		}
	}
	if c.Attestation.Token.Enabled && c.Attestation.Token.TTL != "" {
		if _, err := time.ParseDuration(c.Attestation.Token.TTL); err != nil {
			return fmt.Errorf("attestation.token.ttl: invalid duration %q: %w", c.Attestation.Token.TTL, err)
		}
	}
	if c.Attestation.LocalAgent.Enabled && c.Attestation.LocalAgent.SocketPath == "" {
		return errors.New("attestation.local_agent.socket_path is required when local_agent is enabled")
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
