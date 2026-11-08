package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A config shaped like an older live one (written by an older --init, plus a
// step-up role) must refuse to start with one line per removed field, each
// saying what to use instead. Disabled blocks count too: a removed setting is
// never silently ignored.
func TestValidateRefusesRemovedSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := `{
		"server": {"listen": "127.0.0.1:9090"},
		"tls": {"enabled": false},
		"store": {"path": "/data/store.json", "master_key": "/data/master.key"},
		"auth": {"bearer": {"enabled": true}, "mtls": {"enabled": false, "ca_cert": "/data/ca.crt"}},
		"acl": {"path": "/data/acl.json"},
		"audit": {"path": "/data/audit.log"},
		"attestation": {"nonce": {"enabled": false}, "token": {"enabled": false}, "local_agent": {"enabled": false}},
		"onepassword": {"enabled": false},
		"session": {"enabled": true, "roles": {
			"ok": {"namespaces": ["a/*"], "bootstrap_trust": ["bearer"]},
			"elevated": {"namespaces": ["b/*"], "bootstrap_trust": ["bearer", "mtls"], "attestation": ["cert_fingerprint"],
				"step_up": true, "step_up_ttl": "15m", "elevates_acl": true, "allowed_agents": ["openclaw"]}
		}}
	}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	err = cfg.Validate()
	if err == nil {
		t.Fatal("config with removed settings validated")
	}
	want := []string{
		"tls: removed", "auth.mtls: removed", "attestation.nonce: removed", "attestation.token: removed",
		"onepassword.enabled: removed",
		"session.roles.elevated.step_up: removed", "session.roles.elevated.step_up_ttl: removed",
		"session.roles.elevated.elevates_acl: removed", "session.roles.elevated.allowed_agents: removed",
		`session.roles.elevated.bootstrap_trust "mtls": removed`,
		`session.roles.elevated.attestation "cert_fingerprint": removed`,
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), "\n  "+w) {
			t.Errorf("error lacks line %q:\n%v", w, err)
		}
	}
	if got := strings.Count(err.Error(), "\n  "); got != len(want) {
		t.Errorf("got %d lines, want %d:\n%v", got, len(want), err)
	}
	if strings.Contains(err.Error(), "local_agent") || strings.Contains(err.Error(), "roles.ok") {
		t.Errorf("kept settings reported as removed:\n%v", err)
	}
	for _, f := range removedSettings {
		if f.Why == "" {
			t.Errorf("%s has no reason", f.Path)
		}
	}
}

// The same file with the removed fields taken out validates.
func TestValidateAcceptsCleanedConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := `{
		"server": {"listen": "127.0.0.1:9090"},
		"https_listener": {"enabled": false, "listen": "0.0.0.0:9443", "cert": "/data/server.crt", "key": "/data/server.key",
			"ca_cert": "/data/ca.crt", "ca_key": "/data/ca.key"},
		"store": {"path": "/data/store.json", "master_key": "/data/master.key"},
		"auth": {"bearer": {"enabled": true}},
		"acl": {"path": "/data/acl.json"},
		"audit": {"path": "/data/audit.log"},
		"attestation": {"local_agent": {"enabled": false}},
		"onepassword": {"service_account_token_env": "OP_SERVICE_ACCOUNT_TOKEN"},
		"session": {"enabled": true, "roles": {"ok": {"namespaces": ["a/*"], "bootstrap_trust": ["bearer"], "attestation": ["source_ip"]}}}
	}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("cleaned config: %v", err)
	}
}

// config.example.json is what new users copy; it must load and validate
// cleanly, so it can never carry a removed setting.
func TestExampleConfigHasNoRemovedSettings(t *testing.T) {
	cfg, err := Load("../../config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config.example.json: %v", err)
	}
}

// Review H3: role attestation "require_sealed" checks nothing without
// require_seal_key, so that combination is refused instead of trusted.
func TestRoleRequireSealedNeedsSealKey(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Session.Enabled = true
	cfg.Session.Roles = map[string]RoleConfig{
		"r": {Namespaces: []string{"a/*"}, BootstrapTrust: []string{"bearer"}, Attestation: []string{"require_sealed"}},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "require_seal_key") {
		t.Fatalf("require_sealed without require_seal_key: %v", err)
	}
	r := cfg.Session.Roles["r"]
	r.RequireSealKey = true
	cfg.Session.Roles["r"] = r
	if err := cfg.Validate(); err != nil {
		t.Fatalf("require_sealed with require_seal_key: %v", err)
	}
}
