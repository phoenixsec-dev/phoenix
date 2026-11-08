package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHTTPSListenerConfig(t *testing.T) {
	for _, tc := range []struct {
		name, block string
		wantError   bool
	}{
		{"omitted", `{}`, false},
		{"disabled", `{"https_listener":{"enabled":false,"listen":"bad","cert":"missing"}}`, false},
		{"missing address", `{"https_listener":{"enabled":true,"cert":"cert","key":"key"}}`, true},
		{"missing cert", `{"https_listener":{"enabled":true,"listen":"127.0.0.1:9443","key":"key"}}`, true},
		{"missing key", `{"https_listener":{"enabled":true,"listen":"127.0.0.1:9443","cert":"cert"}}`, true},
		{"complete", `{"https_listener":{"enabled":true,"listen":"127.0.0.1:9443","cert":"cert","key":"key"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tc.block), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			// An incomplete enabled block is a startup error, like any other
			// config error; it must be reported by the top-level Validate.
			err = cfg.Validate()
			if (err != nil) != tc.wantError {
				t.Fatalf("validation: %v", err)
			}
			if err != nil && !strings.Contains(err.Error(), "https_listener") {
				t.Fatalf("error does not name https_listener: %v", err)
			}
			if cfg.TLSEnabled() || cfg.Server.Listen != "127.0.0.1:9090" {
				t.Fatal("optional config changed primary transport")
			}
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var roundtrip Config
			if err := json.Unmarshal(data, &roundtrip); err != nil {
				t.Fatal(err)
			}
			if roundtrip.HTTPSListener != cfg.HTTPSListener {
				t.Fatal("optional config did not round trip")
			}
		})
	}
	if DefaultConfig().HTTPSListener.Enabled || ExampleConfig().HTTPSListener.Enabled {
		t.Fatal("HTTPS listener must be opt-in")
	}
	if ExampleConfig().HTTPSListener.Listen != "127.0.0.1:9443" {
		t.Fatal("example must bind optional listener to loopback")
	}
}

func TestValidateRequiresAuthMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Auth.Bearer.Enabled = false
	cfg.Auth.MTLS.Enabled = false

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error when no auth mode enabled")
	}
}

func TestValidateMTLSRequiresPaths(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Auth.MTLS.Enabled = true
	cfg.Auth.MTLS.CACert = "/data/ca.crt"
	cfg.Auth.MTLS.CAKey = "/data/ca.key"
	// Missing server cert/key

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error when mTLS enabled without server cert paths")
	}
}

func TestValidateMTLSComplete(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Auth.MTLS.Enabled = true
	cfg.Auth.MTLS.CACert = "/data/ca.crt"
	cfg.Auth.MTLS.CAKey = "/data/ca.key"
	cfg.Auth.MTLS.ServerCert = "/data/server.crt"
	cfg.Auth.MTLS.ServerKey = "/data/server.key"

	err := cfg.Validate()
	if err != nil {
		t.Fatalf("complete mTLS config should validate: %v", err)
	}
}

func TestValidateDefaultPasses(t *testing.T) {
	cfg := DefaultConfig()
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("default config should validate: %v", err)
	}
}

func TestValidateBearerOnlyPasses(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Auth.Bearer.Enabled = true
	cfg.Auth.MTLS.Enabled = false

	err := cfg.Validate()
	if err != nil {
		t.Fatalf("bearer-only config should validate: %v", err)
	}
}

func TestBackendDefaultsToFile(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Backend() != "file" {
		t.Fatalf("expected default backend 'file', got %q", cfg.Backend())
	}
	// Empty string should also default to file
	cfg.Store.Backend = ""
	if cfg.Backend() != "file" {
		t.Fatalf("expected empty backend to default to 'file', got %q", cfg.Backend())
	}
}

func TestValidateUnknownBackend(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Store.Backend = "redis"
	if err := cfg.Validate(); err == nil {
		t.Fatal("unknown backend should fail validation")
	}
}

func TestValidate1PasswordBackendRequiresVault(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Store.Backend = "1password"
	cfg.OnePassword.Vault = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("1password backend without vault should fail validation")
	}
}

func TestValidate1PasswordBackendValid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Store.Backend = "1password"
	cfg.OnePassword.Vault = "Engineering"
	// 1password backend doesn't require store.path or master_key
	cfg.Store.Path = ""
	cfg.Store.MasterKey = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid 1password config should pass: %v", err)
	}
}

func TestValidate1PasswordCacheTTLInvalid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Store.Backend = "1password"
	cfg.OnePassword.Vault = "Engineering"
	cfg.OnePassword.CacheTTL = "not-a-duration"
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid cache_ttl should fail validation")
	}
}

func TestValidate1PasswordCacheTTLValid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Store.Backend = "1password"
	cfg.OnePassword.Vault = "Engineering"
	cfg.OnePassword.CacheTTL = "30s"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid cache_ttl should pass: %v", err)
	}
}

func TestValidateLocalAgentEnabledRequiresSocket(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Attestation.LocalAgent.Enabled = true
	cfg.Attestation.LocalAgent.SocketPath = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("local_agent enabled without socket_path should fail validation")
	}
}

func TestValidateLocalAgentEnabledWithSocket(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Attestation.LocalAgent.Enabled = true
	cfg.Attestation.LocalAgent.SocketPath = "/tmp/phoenix-agent.sock"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid local_agent config should pass: %v", err)
	}
}

func TestValidateLocalAgentDisabledIgnoresMissingSocket(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Attestation.LocalAgent.Enabled = false
	cfg.Attestation.LocalAgent.SocketPath = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled local_agent should not require socket_path: %v", err)
	}
}

func TestLocalAgentConfigJSON(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Attestation.LocalAgent.Enabled = true
	cfg.Attestation.LocalAgent.SocketPath = "/run/phoenix/agent.sock"

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed Config
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !parsed.Attestation.LocalAgent.Enabled {
		t.Error("local_agent.enabled should be true after round-trip")
	}
	if parsed.Attestation.LocalAgent.SocketPath != "/run/phoenix/agent.sock" {
		t.Errorf("local_agent.socket_path = %q, want %q", parsed.Attestation.LocalAgent.SocketPath, "/run/phoenix/agent.sock")
	}
}

func TestDefaultConfigNoLocalAgent(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Attestation.LocalAgent.Enabled {
		t.Error("local_agent should be disabled by default")
	}
}

func TestValidateSessionActionNames(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Session.Enabled = true
	cfg.Session.Roles = map[string]RoleConfig{
		"bad": {
			Namespaces:     []string{"dev/*"},
			Actions:        []string{"list", "explode"},
			BootstrapTrust: []string{"bearer"},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for invalid action name")
	}
	if !strings.Contains(err.Error(), "explode") {
		t.Fatalf("error should mention invalid action: %v", err)
	}
}

func TestValidateSessionActionNamesValid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Session.Enabled = true
	cfg.Session.Roles = map[string]RoleConfig{
		"good": {
			Namespaces:     []string{"dev/*"},
			Actions:        []string{"list", "read_value", "write"},
			BootstrapTrust: []string{"bearer"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid actions should pass: %v", err)
	}
}

// --- Dashboard config validation ---

func TestValidateDashboardEnabledRequiresCredential(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.PasswordHash = ""
	cfg.Dashboard.PIN = ""

	err := cfg.Validate()
	if err == nil {
		t.Fatal("dashboard enabled without password_hash or pin should fail")
	}
	if !strings.Contains(err.Error(), "password_hash or pin") {
		t.Fatalf("error should mention credential requirement: %v", err)
	}
}

func TestValidateDashboardWithPasswordHash(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.PasswordHash = "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("dashboard with bcrypt hash should pass: %v", err)
	}
}

func TestValidateDashboardRejectsPlaintextPassword(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.PasswordHash = "plaintext-password"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("plaintext password_hash should fail validation")
	}
	if !strings.Contains(err.Error(), "bcrypt hash") {
		t.Fatalf("error should mention bcrypt: %v", err)
	}
}

func TestValidateDashboardWithPIN(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.PIN = "1234"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("dashboard with PIN should pass: %v", err)
	}
}

func TestValidateDashboardSessionTTLInvalid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.PasswordHash = "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"
	cfg.Dashboard.SessionTTL = "not-a-duration"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("invalid session_ttl should fail validation")
	}
	if !strings.Contains(err.Error(), "session_ttl") {
		t.Fatalf("error should mention session_ttl: %v", err)
	}
}

func TestValidateDashboardSessionTTLValid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.PasswordHash = "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"
	cfg.Dashboard.SessionTTL = "8h"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid session_ttl should pass: %v", err)
	}
}

func TestValidateDashboardDisabledIgnoresFields(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Dashboard.Enabled = false
	cfg.Dashboard.PasswordHash = ""
	cfg.Dashboard.PIN = ""
	cfg.Dashboard.SessionTTL = "garbage"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled dashboard should not validate fields: %v", err)
	}
}

func TestDashboardConfigJSON(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.PasswordHash = "$2a$10$testbcrypthashvalue"
	cfg.Dashboard.SessionTTL = "4h"

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed Config
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !parsed.Dashboard.Enabled {
		t.Error("dashboard.enabled should be true after round-trip")
	}
	if parsed.Dashboard.PasswordHash != "$2a$10$testbcrypthashvalue" {
		t.Errorf("dashboard.password_hash = %q, want %q", parsed.Dashboard.PasswordHash, "$2a$10$testbcrypthashvalue")
	}
	if parsed.Dashboard.SessionTTL != "4h" {
		t.Errorf("dashboard.session_ttl = %q, want %q", parsed.Dashboard.SessionTTL, "4h")
	}
}

func TestExampleConfigIncludesSessionAndDashboard(t *testing.T) {
	cfg := ExampleConfig()

	if cfg.Server.Listen != "127.0.0.1:9090" {
		t.Fatalf("server.listen = %q, want loopback 127.0.0.1:9090", cfg.Server.Listen)
	}
	if cfg.Session.TTL != "1h" {
		t.Fatalf("session.ttl = %q, want 1h", cfg.Session.TTL)
	}
	if len(cfg.Session.Roles) == 0 {
		t.Fatal("expected example session roles")
	}
	if cfg.Dashboard.SessionTTL != "4h" {
		t.Fatalf("dashboard.session_ttl = %q, want 4h", cfg.Dashboard.SessionTTL)
	}
}

func TestOPConfigJSON(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Store.Backend = "1password"
	cfg.OnePassword.Vault = "Engineering"
	cfg.OnePassword.CacheTTL = "60s"

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed Config
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if parsed.Store.Backend != "1password" {
		t.Errorf("backend = %q, want %q", parsed.Store.Backend, "1password")
	}
	if parsed.OnePassword.Vault != "Engineering" {
		t.Errorf("vault = %q, want %q", parsed.OnePassword.Vault, "Engineering")
	}
	if parsed.OnePassword.CacheTTL != "60s" {
		t.Errorf("cache_ttl = %q, want %q", parsed.OnePassword.CacheTTL, "60s")
	}
}

func TestTLSEnabledCombinations(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.TLSEnabled() {
		t.Fatal("default config should not enable TLS")
	}

	cfg.TLS.Enabled = true
	if !cfg.TLSEnabled() {
		t.Fatal("tls.enabled=true should enable TLS")
	}

	cfg = DefaultConfig()
	cfg.Auth.MTLS.Enabled = true
	if !cfg.TLSEnabled() {
		t.Fatal("auth.mtls.enabled=true should imply TLS (backward compat)")
	}
}

func TestTLSCertKeyFallsBackToMTLSPaths(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Auth.MTLS.ServerCert = "/data/server.crt"
	cfg.Auth.MTLS.ServerKey = "/data/server.key"

	cert, key := cfg.TLSCertKey()
	if cert != "/data/server.crt" || key != "/data/server.key" {
		t.Fatalf("expected mTLS leaf fallback, got cert=%q key=%q", cert, key)
	}

	cfg.TLS.Cert = "/custom/tls.crt"
	cfg.TLS.Key = "/custom/tls.key"
	cert, key = cfg.TLSCertKey()
	if cert != "/custom/tls.crt" || key != "/custom/tls.key" {
		t.Fatalf("explicit tls paths should win, got cert=%q key=%q", cert, key)
	}
}

func TestValidateTLSEnabledRequiresPaths(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLS.Enabled = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error: tls.enabled with no cert/key anywhere")
	}

	// mTLS leaf paths present (as written by --init) satisfy the requirement
	// even with mTLS disabled.
	cfg.Auth.MTLS.ServerCert = "/data/server.crt"
	cfg.Auth.MTLS.ServerKey = "/data/server.key"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("tls.enabled with --init mTLS leaf paths should pass: %v", err)
	}

	// Explicit tls paths also satisfy it.
	cfg = DefaultConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.Cert = "/custom/tls.crt"
	cfg.TLS.Key = "/custom/tls.key"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("tls.enabled with explicit paths should pass: %v", err)
	}
}

func TestValidateTLSCertKeyMustBeSetTogether(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLS.Cert = "/custom/tls.crt"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error: tls.cert without tls.key")
	}
	cfg = DefaultConfig()
	cfg.TLS.Key = "/custom/tls.key"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error: tls.key without tls.cert")
	}
}

func TestTLSConfigJSON(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.Cert = "/data/server.crt"
	cfg.TLS.Key = "/data/server.key"

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed Config
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !parsed.TLS.Enabled || parsed.TLS.Cert != "/data/server.crt" || parsed.TLS.Key != "/data/server.key" {
		t.Fatalf("tls block did not round-trip: %+v", parsed.TLS)
	}

	// The tls block must appear in generated configs even when disabled,
	// so operators can discover the one-line fix.
	data, err = json.Marshal(DefaultConfig())
	if err != nil {
		t.Fatalf("marshal default: %v", err)
	}
	if !strings.Contains(string(data), `"tls"`) {
		t.Fatal("default config JSON should include the tls block")
	}
}

func TestAccessRequestsConfig(t *testing.T) {
	load := func(t *testing.T, block string) (*Config, error) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.json")
		body := `{"acl":{"path":"/data/acl.json"},"audit":{"path":"/data/audit.log"},"store":{"path":"/data/store.json","master_key":"/data/master.key"}`
		if block != "" {
			body += `,"access_requests":` + block
		}
		if err := os.WriteFile(path, []byte(body+"}"), 0600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		return cfg, cfg.Validate()
	}

	t.Run("missing block is disabled", func(t *testing.T) {
		cfg, err := load(t, "")
		if err != nil {
			t.Fatal(err)
		}
		s := cfg.AccessRequestsSettings()
		if s.Enabled || s.StorePath != "/data/grants.json" || !s.RequireSealed {
			t.Fatalf("settings = %+v", s)
		}
	})
	t.Run("defaults and explicit false", func(t *testing.T) {
		cfg, err := load(t, `{"enabled":true,"require_sealed":false}`)
		if err != nil {
			t.Fatal(err)
		}
		s := cfg.AccessRequestsSettings()
		if !s.Enabled || s.RequireSealed || !s.BindSourceIP || s.MaxGrantTTL != 8*time.Hour ||
			len(s.GrantableActions) != 1 || s.GrantableActions[0] != "read_value" {
			t.Fatalf("settings = %+v", s)
		}
	})
	for _, c := range []struct{ name, block, want string }{
		{"write not supported", `{"grantable_actions":["read_value","write"]}`, "write grants are not supported yet"},
		{"never grantable", `{"grantable_actions":["admin"]}`, "can never be granted"},
		{"bad duration", `{"request_ttl":"soon"}`, "request_ttl"},
		{"request ttl too short", `{"request_ttl":"30s"}`, "at least 1m"},
		{"default above max", `{"default_grant_ttl":"9h"}`, "default_grant_ttl <= max_grant_ttl"},
		{"max above 24h", `{"max_grant_ttl":"25h"}`, "<= 24h"},
		{"bad deny glob", `{"deny_paths":["infra/*/keys"]}`, "deny_paths"},
		{"store collides with acl", `{"store_path":"/data/acl.json"}`, "same file as acl.path"},
		{"store collides with temp", `{"store_path":"/data/store.json.tmp-1"}`, "same file as store.path"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := load(t, c.block)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
	t.Run("new installs are enabled", func(t *testing.T) {
		if ar := ExampleConfig().AccessRequests; ar == nil || !ar.Enabled {
			t.Fatal("example/new-install config must enable access_requests")
		}
		if DefaultConfig().AccessRequests != nil {
			t.Fatal("DefaultConfig must leave access_requests unset (upgrade safety)")
		}
		data, err := os.ReadFile("../../config.example.json")
		if err != nil {
			t.Fatal(err)
		}
		var ex Config
		if err := json.Unmarshal(data, &ex); err != nil {
			t.Fatal(err)
		}
		if ex.AccessRequests == nil || !ex.AccessRequests.Enabled {
			t.Fatal("config.example.json must enable access_requests")
		}
	})
}

// R1 H1: the grants file path is validated even without an access_requests
// block, and aliases (relative paths, symlinks) are resolved.
func TestGrantStorePathCollisions(t *testing.T) {
	base := func(dir string) *Config {
		cfg := DefaultConfig()
		cfg.ACL.Path = filepath.Join(dir, "acl.json")
		cfg.Audit.Path = filepath.Join(dir, "audit.log")
		cfg.Store.Path = filepath.Join(dir, "store.json")
		cfg.Store.MasterKey = filepath.Join(dir, "master.key")
		return cfg
	}
	mustCollide := func(t *testing.T, cfg *Config, field string) {
		t.Helper()
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), field) || !strings.Contains(err.Error(), "store_path") {
			t.Fatalf("err = %v, want a collision with %s naming access_requests.store_path", err, field)
		}
	}

	t.Run("no block, data file is grants.json", func(t *testing.T) {
		dir := t.TempDir()
		cfg := base(dir)
		cfg.Store.Path = filepath.Join(dir, "grants.json")
		if err := os.WriteFile(cfg.Store.Path, []byte("secrets-db"), 0600); err != nil {
			t.Fatal(err)
		}
		mustCollide(t, cfg, "store.path")
		if b, _ := os.ReadFile(cfg.Store.Path); string(b) != "secrets-db" {
			t.Fatalf("data file changed: %q", b)
		}
	})
	t.Run("no block, ACL is grants.json", func(t *testing.T) {
		cfg := base(t.TempDir())
		cfg.ACL.Path = filepath.Join(filepath.Dir(cfg.ACL.Path), "grants.json")
		mustCollide(t, cfg, "acl.path")
	})
	t.Run("relative and absolute spelling", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		cfg := base(dir)
		cfg.AccessRequests = &AccessRequestsConfig{StorePath: "store.json"}
		mustCollide(t, cfg, "store.path")
		cfg.AccessRequests.StorePath = "./audit.log.tmp-1"
		mustCollide(t, cfg, "audit.path")
	})
	t.Run("symlinked directory", func(t *testing.T) {
		dir := t.TempDir()
		real := filepath.Join(dir, "real")
		if err := os.Mkdir(real, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, filepath.Join(dir, "link")); err != nil {
			t.Fatal(err)
		}
		cfg := base(real)
		// The ACL file does not exist yet: its parent directory is resolved.
		cfg.AccessRequests = &AccessRequestsConfig{StorePath: filepath.Join(dir, "link", "acl.json")}
		mustCollide(t, cfg, "acl.path")
	})
	// R2: "link/.." must be resolved the way the kernel does (follow the
	// link, then go up), not cleaned away first.
	t.Run("symlink then dot-dot", func(t *testing.T) {
		dir := t.TempDir()
		real := filepath.Join(dir, "real")
		if err := os.MkdirAll(filepath.Join(real, "child"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(real, "child"), filepath.Join(dir, "link")); err != nil {
			t.Fatal(err)
		}
		cfg := base(real)
		if err := os.WriteFile(cfg.Store.Path, []byte("secrets-db"), 0600); err != nil {
			t.Fatal(err)
		}
		cfg.AccessRequests = &AccessRequestsConfig{StorePath: filepath.Join(dir, "link") + "/../store.json"}
		mustCollide(t, cfg, "store.path")
	})
	// R2: a symlinked ACL file is saved through "<configured name>.tmp", so
	// that name is protected even though the link points elsewhere.
	t.Run("temp name of a symlinked file", func(t *testing.T) {
		dir := t.TempDir()
		cfg := base(dir)
		if err := os.WriteFile(filepath.Join(dir, "real-acl.json"), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(dir, "real-acl.json"), cfg.ACL.Path); err != nil {
			t.Fatal(err)
		}
		cfg.AccessRequests = &AccessRequestsConfig{StorePath: cfg.ACL.Path + ".tmp"}
		mustCollide(t, cfg, "acl.path")
	})
	// R3: the grants file itself must not be a symlink (it could point at a
	// protected file's temp name, which no path comparison would see).
	t.Run("grants file is a symlink", func(t *testing.T) {
		dir := t.TempDir()
		cfg := base(dir)
		alias := filepath.Join(dir, "grants-alias.json")
		if err := os.Symlink(cfg.ACL.Path+".tmp", alias); err != nil {
			t.Fatal(err)
		}
		cfg.AccessRequests = &AccessRequestsConfig{StorePath: alias}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("err = %v, want a symlink refusal", err)
		}
	})
	// R3: unresolvable paths ending in "/", "/." or "/.." must not loop.
	t.Run("odd unresolvable paths terminate", func(t *testing.T) {
		for _, p := range []string{"/missing-dir-r3/", "/missing-dir-r3/.", "/missing-dir-r3/.."} {
			cfg := base(t.TempDir())
			cfg.Auth.MTLS.CRLPath = p
			done := make(chan struct{})
			go func() { _ = cfg.ValidateGrantStorePath(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("ValidateGrantStorePath hung on %q", p)
			}
		}
	})
	t.Run("store path is canonical", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "real", "child"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(dir, "real", "child"), filepath.Join(dir, "link")); err != nil {
			t.Fatal(err)
		}
		cfg := base(dir)
		cfg.AccessRequests = &AccessRequestsConfig{StorePath: filepath.Join(dir, "link") + "/../g.json"}
		want, _ := filepath.EvalSymlinks(filepath.Join(dir, "real"))
		if got := cfg.GrantStorePath(); got != filepath.Join(want, "g.json") {
			t.Fatalf("GrantStorePath = %q, want %q", got, filepath.Join(want, "g.json"))
		}
	})
	t.Run("separate file is fine", func(t *testing.T) {
		cfg := base(t.TempDir())
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
	})
}

// R1 M2: only ONE trailing wildcard suffix is allowed; "infra/*/**" used to
// pass validation while matching nothing at runtime.
func TestValidatePathGlob(t *testing.T) {
	for _, ok := range []string{"*", "**", "infra/b2/app-key", "infra/*", "infra/**", "phoenix/**"} {
		if err := ValidatePathGlob(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "infra/*/**", "infra/**/*", "infra/**/**", "infra/*/keys", "in*fra", "/infra/**", "/**", "infra/[ab]"} {
		if err := ValidatePathGlob(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestAccessRequestsNotifyValidation(t *testing.T) {
	cases := []struct {
		name string
		ar   AccessRequestsConfig
		want string // "" = valid
	}{
		{"ntfy url and ref", AccessRequestsConfig{NotifyURL: "https://ntfy.example.net/phoenix", NotifyTokenRef: "phoenix://phoenix/ntfy-token", NotifyDashboardURL: "https://phoenix.example.net"}, ""},
		{"not http", AccessRequestsConfig{NotifyURL: "ftp://x/y"}, "notify_url"},
		{"no host", AccessRequestsConfig{NotifyURL: "https:///topic"}, "no host"},
		{"credentials in url", AccessRequestsConfig{NotifyURL: "https://user:pw@ntfy.example.net/t"}, "notify_token_ref"},
		{"query", AccessRequestsConfig{NotifyURL: "https://ntfy.example.net/t?auth=x"}, "query"},
		{"dashboard fragment", AccessRequestsConfig{NotifyDashboardURL: "https://p.example.net/#x"}, "notify_dashboard_url"},
		{"token not a ref", AccessRequestsConfig{NotifyTokenRef: "tk_abc"}, "phoenix://"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := DefaultConfig()
			dir := t.TempDir()
			cfg.ACL.Path = filepath.Join(dir, "acl.json")
			cfg.Audit.Path = filepath.Join(dir, "audit.log")
			cfg.Store.Path = filepath.Join(dir, "store.json")
			cfg.Store.MasterKey = filepath.Join(dir, "master.key")
			ar := c.ar
			cfg.AccessRequests = &ar
			err := cfg.Validate()
			if c.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

// P4 review N2: a rejected notify value never appears in the error, because
// startup logs it. A pasted token or a URL with a secret in it must not leak.
func TestAccessRequestsNotifyErrorsDoNotEchoValues(t *testing.T) {
	const secret = "s3cr3t-topic-or-token"
	for _, ar := range []AccessRequestsConfig{
		{NotifyURL: "https://ntfy.example.net/t?auth=" + secret},
		{NotifyURL: "https://ntfy.example.net/" + secret + "#frag"},
		{NotifyURL: "ftp://ntfy.example.net/" + secret},
		{NotifyURL: "https:///" + secret},
		{NotifyDashboardURL: "https://p.example.net/?k=" + secret},
		{NotifyTokenRef: "tk_" + secret},
	} {
		cfg := DefaultConfig()
		a := ar
		cfg.AccessRequests = &a
		err := cfg.validateAccessRequests()
		if err == nil {
			t.Fatalf("%+v accepted", ar)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error echoes the value: %v", err)
		}
	}
}

func TestSSHCAValidation(t *testing.T) {
	base := func() *Config {
		return &Config{
			AccessRequests: &AccessRequestsConfig{Enabled: true},
			SSHCA:          &SSHCAConfig{Enabled: true, Hosts: map[string]SSHHost{"arch-omen": {Address: "192.168.0.99"}}},
		}
	}
	if err := base().validateSSHCA(); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	if got := base().SSHCAHosts()["arch-omen"].User; got != DefaultSSHUser {
		t.Fatalf("default user = %q", got)
	}
	for name, mutate := range map[string]func(*Config){
		"grants off":       func(c *Config) { c.AccessRequests.Enabled = false },
		"no grants block":  func(c *Config) { c.AccessRequests = nil },
		"no hosts":         func(c *Config) { c.SSHCA.Hosts = nil },
		"bad name":         func(c *Config) { c.SSHCA.Hosts["Bad Name"] = SSHHost{Address: "1.2.3.4"} },
		"option address":   func(c *Config) { c.SSHCA.Hosts["x"] = SSHHost{Address: "-oProxyCommand=evil"} },
		"empty address":    func(c *Config) { c.SSHCA.Hosts["x"] = SSHHost{} },
		"option user name": func(c *Config) { c.SSHCA.Hosts["x"] = SSHHost{Address: "1.2.3.4", User: "-l"} },
	} {
		c := base()
		mutate(c)
		if err := c.validateSSHCA(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	off := &Config{SSHCA: &SSHCAConfig{Enabled: false}}
	if err := off.validateSSHCA(); err != nil {
		t.Fatalf("a disabled block must not be checked: %v", err)
	}
}
