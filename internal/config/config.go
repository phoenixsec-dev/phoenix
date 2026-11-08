// Package config loads and validates Phoenix server configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/phoenixsec/phoenix/internal/removed"
)

// Config is the top-level server configuration.
type Config struct {
	Server        ServerConfig        `json:"server"`
	HTTPSListener HTTPSListenerConfig `json:"https_listener"`
	Store         StoreConfig         `json:"store"`
	Crypto        CryptoConfig        `json:"crypto"`
	Auth          AuthConfig          `json:"auth"`
	ACL           ACLFileConfig       `json:"acl"`
	Audit         AuditConfig         `json:"audit"`
	Policy        PolicyConfig        `json:"policy,omitempty"`
	Attestation   AttestationConfig   `json:"attestation,omitempty"`
	OnePassword   OPConfig            `json:"onepassword,omitempty"`
	Session       SessionConfig       `json:"session,omitempty"`
	Dashboard     DashboardConfig     `json:"dashboard,omitempty"`
	// AccessRequests is nil when the block is missing, which means the
	// request-use feature is off (safe default for upgraded installs).
	AccessRequests *AccessRequestsConfig `json:"access_requests,omitempty"`
	// SSHCA is nil when the block is missing, which means SSH certificates are off.
	SSHCA *SSHCAConfig `json:"ssh_ca,omitempty"`

	// removed lists the removed settings Load found in the file (removed.go);
	// Validate refuses to start while any are left.
	removed []string
}

// AuthConfig controls authentication methods. Bearer tokens are the only
// way to log in (sessions are minted with one), so bearer must stay on.
type AuthConfig struct {
	Bearer BearerAuthConfig `json:"bearer"`
}

// BearerAuthConfig controls bearer token authentication.
type BearerAuthConfig struct {
	Enabled bool `json:"enabled"`
}

// HTTPSListenerConfig is the one way to serve HTTPS. It adds an HTTPS
// endpoint next to the plain HTTP one at server.listen, which should stay on
// loopback. Cert and Key are the server certificate (--init writes one,
// signed by the internal CA). CACert and CAKey are that CA; only
// --reissue-cert uses them, to sign a new server certificate.
type HTTPSListenerConfig struct {
	Enabled bool   `json:"enabled"`
	Listen  string `json:"listen,omitempty"`
	Cert    string `json:"cert,omitempty"`
	Key     string `json:"key,omitempty"`
	CACert  string `json:"ca_cert,omitempty"`
	CAKey   string `json:"ca_key,omitempty"`
}

// Validate is called from Config.Validate, so a blank address or missing
// certificate path stops startup like any other config error. Only runtime
// failures (bind, serve) are contained so the primary keeps running.
func (c HTTPSListenerConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.Listen == "" {
		return errors.New("https_listener.listen is required")
	}
	if c.Cert == "" || c.Key == "" {
		return errors.New("https_listener.cert and https_listener.key are required")
	}
	return nil
}

// CryptoConfig controls the key management provider.
type CryptoConfig struct {
	Provider string `json:"provider"` // "file" (default, only option in Phase 2 spike)
}

// ServerConfig controls the HTTP server.
type ServerConfig struct {
	Listen string `json:"listen"` // e.g., "127.0.0.1:9090" (loopback, default) or "0.0.0.0:9090" (all interfaces)
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
	// RotateMB: when the log passes this many MB it is renamed to a dated
	// archive next to it and a new file is started. Archives are never
	// deleted. 0 or unset = 50; negative = never rotate.
	RotateMB int `json:"rotate_mb,omitempty"`
}

// DefaultAuditRotateMB is the rotate size when audit.rotate_mb is unset.
const DefaultAuditRotateMB = 50

// AuditRotateBytes is the audit log rotate size in bytes (0 = never).
func (c *Config) AuditRotateBytes() int64 {
	switch {
	case c.Audit.RotateMB < 0:
		return 0
	case c.Audit.RotateMB == 0:
		return DefaultAuditRotateMB << 20
	default:
		return int64(c.Audit.RotateMB) << 20
	}
}

// PolicyConfig controls the optional attestation policy engine.
type PolicyConfig struct {
	Path string `json:"path,omitempty"` // Path to attestation policy JSON file
}

// AttestationConfig controls the local agent socket. It is off by default;
// it stays (unused) as the base for the local Phoenix service.
type AttestationConfig struct {
	LocalAgent LocalAgentConfig `json:"local_agent,omitempty"`
}

// LocalAgentConfig controls the local Unix socket attestation agent.
type LocalAgentConfig struct {
	Enabled    bool   `json:"enabled"`
	SocketPath string `json:"socket_path,omitempty"` // default: /tmp/phoenix-agent.sock
}

// OPConfig controls the optional 1Password backend (store.backend
// "1password"); it is used only when that backend is selected.
type OPConfig struct {
	Vault                  string `json:"vault,omitempty"`                     // 1Password vault name
	ServiceAccountTokenEnv string `json:"service_account_token_env,omitempty"` // env var name (default: OP_SERVICE_ACCOUNT_TOKEN)
	CacheTTL               string `json:"cache_ttl,omitempty"`                 // duration string, e.g. "60s" (default)
}

// SessionConfig controls the v1 session identity system.
type SessionConfig struct {
	Enabled bool                  `json:"enabled"`
	TTL     string                `json:"ttl,omitempty"` // default "1h"
	Roles   map[string]RoleConfig `json:"roles,omitempty"`
}

// RoleConfig defines a named role that agents assume via session tokens.
type RoleConfig struct {
	Namespaces     []string `json:"namespaces"`
	Actions        []string `json:"actions,omitempty"`     // default: ["list", "read_value"]
	BootstrapTrust []string `json:"bootstrap_trust"`       // allowed auth methods: "bearer", "local"
	RequireSealKey bool     `json:"require_seal_key"`      // must present seal pubkey at mint
	MaxTTL         string   `json:"max_ttl,omitempty"`     // per-role session TTL override
	Attestation    []string `json:"attestation,omitempty"` // "source_ip" (caller must be on loopback) and/or "require_sealed"
}

// DashboardConfig controls the optional operator dashboard web UI.
type DashboardConfig struct {
	Enabled         bool   `json:"enabled"`
	PasswordHash    string `json:"password_hash,omitempty"` // bcrypt hash (generate with: phoenix-server --hash-password)
	PIN             string `json:"pin,omitempty"`
	SessionTTL      string `json:"session_ttl,omitempty"`       // default "4h"
	AllowMultiLogin bool   `json:"allow_multi_login,omitempty"` // default false: only one active dashboard session
}

// validBootstrapMethods lists the allowed values for RoleConfig.BootstrapTrust.
var validBootstrapMethods = map[string]bool{
	"bearer": true,
	"local":  true,
}

// validSessionActions lists the allowed values for RoleConfig.Actions.
var validSessionActions = map[string]bool{
	"list":       true,
	"read_value": true,
	"write":      true,
	"delete":     true,
	"admin":      true,
}

// DefaultConfig returns a config with sensible defaults for /data volume mount.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Listen: "127.0.0.1:9090",
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
		},
		ACL: ACLFileConfig{
			Path: "/data/acl.json",
		},
		Audit: AuditConfig{
			Path: "/data/audit.log",
		},
		OnePassword: OPConfig{
			ServiceAccountTokenEnv: "OP_SERVICE_ACCOUNT_TOKEN",
		},
	}
}

// ExampleConfig returns a fuller reference config for config.example.json and
// other human-facing examples. Unlike DefaultConfig, it includes optional
// sections in disabled/sample form so operators can see the current surface
// area without having to cross-reference multiple docs.
func ExampleConfig() *Config {
	cfg := DefaultConfig()
	cfg.HTTPSListener = HTTPSListenerConfig{
		Listen: "127.0.0.1:9443",
		Cert:   "/data/server.crt",
		Key:    "/data/server.key",
		CACert: "/data/ca.crt",
		CAKey:  "/data/ca.key",
	}
	// Loopback plaintext is the supported default: loopback traffic never
	// reaches a NIC. Anything that crosses a wire uses https_listener; the
	// server starts either way, but warns loudly when server.listen is not
	// loopback, since bearer tokens and secret values would cross the
	// network in cleartext.
	cfg.Server.Listen = "127.0.0.1:9090"
	cfg.Store.Backend = "file"
	cfg.Attestation.LocalAgent.Enabled = false
	cfg.Attestation.LocalAgent.SocketPath = "/tmp/phoenix-agent.sock"
	cfg.OnePassword.Vault = "Engineering"
	cfg.OnePassword.CacheTTL = "60s"
	cfg.Session = SessionConfig{
		Enabled: false,
		TTL:     "1h",
		Roles: map[string]RoleConfig{
			"dev": {
				Namespaces:     []string{"dev/*", "staging/*"},
				Actions:        []string{"list", "read_value"},
				BootstrapTrust: []string{"bearer"},
			},
			"deploy": {
				Namespaces:     []string{"prod/*"},
				Actions:        []string{"list", "read_value"},
				BootstrapTrust: []string{"bearer"},
				RequireSealKey: true,
			},
		},
	}
	cfg.Dashboard = DashboardConfig{
		Enabled:    false,
		SessionTTL: "4h",
	}
	cfg.AccessRequests = NewInstallAccessRequests()
	return cfg
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
	cfg.removed = removed.Find(data, removedSettings)

	return cfg, nil
}

// Backend returns the effective backend name, defaulting to "file".
func (c *Config) Backend() string {
	if c.Store.Backend == "" {
		return "file"
	}
	return c.Store.Backend
}

// Validate checks that all required fields are set and that the file used
// no removed settings.
func (c *Config) Validate() error {
	if err := removed.Error("config", c.removed); err != nil {
		return err
	}
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
	if !c.Auth.Bearer.Enabled {
		return errors.New("auth.bearer.enabled must be true: bearer tokens are the only way to log in")
	}
	if err := c.HTTPSListener.Validate(); err != nil {
		return err
	}
	// Validate attestation duration strings
	if c.Attestation.LocalAgent.Enabled && c.Attestation.LocalAgent.SocketPath == "" {
		return errors.New("attestation.local_agent.socket_path is required when local_agent is enabled")
	}

	// Validate dashboard config
	if c.Dashboard.Enabled {
		if c.Dashboard.PasswordHash == "" && c.Dashboard.PIN == "" {
			return errors.New("dashboard: password_hash or pin is required when dashboard is enabled")
		}
		if c.Dashboard.PasswordHash != "" {
			if !strings.HasPrefix(c.Dashboard.PasswordHash, "$2") {
				return errors.New("dashboard.password_hash: must be a bcrypt hash (generate with: phoenix-server --hash-password)")
			}
			// Verify it's a parseable bcrypt hash, not just a $2 prefix
			if len(c.Dashboard.PasswordHash) < 59 {
				return errors.New("dashboard.password_hash: truncated bcrypt hash (expected ~60 characters)")
			}
		}
		if c.Dashboard.SessionTTL != "" {
			if _, err := time.ParseDuration(c.Dashboard.SessionTTL); err != nil {
				return fmt.Errorf("dashboard.session_ttl: invalid duration %q: %w", c.Dashboard.SessionTTL, err)
			}
		}
	}

	// Validate session config
	if c.Session.Enabled {
		if c.Session.TTL != "" {
			if _, err := time.ParseDuration(c.Session.TTL); err != nil {
				return fmt.Errorf("session.ttl: invalid duration %q: %w", c.Session.TTL, err)
			}
		}
		if len(c.Session.Roles) == 0 {
			return errors.New("session.roles: at least one role must be defined when sessions are enabled")
		}
		for name, role := range c.Session.Roles {
			if len(role.Namespaces) == 0 {
				return fmt.Errorf("session.roles.%s: at least one namespace is required", name)
			}
			if len(role.BootstrapTrust) == 0 {
				return fmt.Errorf("session.roles.%s: at least one bootstrap_trust method is required", name)
			}
			for _, method := range role.BootstrapTrust {
				if !validBootstrapMethods[method] {
					return fmt.Errorf("session.roles.%s: unknown bootstrap_trust method %q (valid: bearer, local)", name, method)
				}
			}
			for _, a := range role.Attestation {
				if a != "source_ip" && a != "require_sealed" {
					return fmt.Errorf("session.roles.%s: unknown attestation %q (valid: source_ip, require_sealed)", name, a)
				}
			}
			for _, action := range role.Actions {
				if !validSessionActions[action] {
					return fmt.Errorf("session.roles.%s: unknown action %q (valid: list, read_value, write, delete, admin)", name, action)
				}
			}
			if role.MaxTTL != "" {
				if _, err := time.ParseDuration(role.MaxTTL); err != nil {
					return fmt.Errorf("session.roles.%s.max_ttl: invalid duration %q: %w", name, role.MaxTTL, err)
				}
			}
		}
	}

	if err := c.validateAccessRequests(); err != nil {
		return err
	}
	if err := c.validateSSHCA(); err != nil {
		return err
	}
	// Always, even without an access_requests block: the store always opens.
	if err := c.ValidateGrantStorePath(); err != nil {
		return err
	}

	return nil
}

// SaveExample writes a default config to disk as a reference.
func SaveExample(path string) error {
	cfg := ExampleConfig()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
