package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --check-config reports removed settings in both the config and the policy
// file it names, and passes a clean pair. It never needs the master key.
func TestRunCheckConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	policyPath := filepath.Join(dir, "policy.json")
	write := func(p, s string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	base := `"server": {"listen": "127.0.0.1:9090"},
		"store": {"path": "` + dir + `/store.json", "master_key": "` + dir + `/missing.key"},
		"auth": {"bearer": {"enabled": true}},
		"acl": {"path": "` + dir + `/acl.json"},
		"audit": {"path": "` + dir + `/audit.log"},
		"policy": {"path": "` + policyPath + `"}`

	write(cfgPath, `{`+base+`, "auth_extra_ignored": 1, "tls": {"enabled": true}}`)
	write(policyPath, `{"attestation": {"a/*": {"source_ip": ["10.0.0.1"]}}}`)
	if err := runCheckConfig(cfgPath); err == nil || !strings.Contains(err.Error(), "tls: removed") {
		t.Fatalf("config with tls block: %v", err)
	}

	write(cfgPath, `{`+base+`}`)
	write(policyPath, `{"attestation": {"a/*": {"deny_bearer": true}}}`)
	if err := runCheckConfig(cfgPath); err == nil || !strings.Contains(err.Error(), "attestation.a/*.deny_bearer: removed") {
		t.Fatalf("policy with deny_bearer: %v", err)
	}

	write(policyPath, `{"attestation": {"a/*": {"source_ip": ["10.0.0.1"]}}}`)
	if err := runCheckConfig(cfgPath); err != nil {
		t.Fatalf("clean config: %v", err)
	}
	if err := runCheckConfig(filepath.Join(dir, "nope.json")); err == nil {
		t.Fatal("missing config file passed")
	}
}

// Second cuts: dashboard pin, a role attestation list, the old policy "rules"
// list and the ACL "read" shorthand are all reported in one run.
func TestRunCheckConfigSecondPass(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	policyPath := filepath.Join(dir, "policy.json")
	aclPath := filepath.Join(dir, "acl.json")
	write := func(p, s string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(cfgPath, `{"server": {"listen": "127.0.0.1:9090"},
		"store": {"path": "`+dir+`/store.json", "master_key": "`+dir+`/missing.key"},
		"auth": {"bearer": {"enabled": true}},
		"acl": {"path": "`+aclPath+`"},
		"audit": {"path": "`+dir+`/audit.log"},
		"policy": {"path": "`+policyPath+`"},
		"dashboard": {"enabled": true, "pin": "1234"},
		"session": {"enabled": true, "roles": {"r": {"namespaces": ["a/*"], "bootstrap_trust": ["bearer"], "attestation": ["source_ip"]}}}}`)
	write(policyPath, `{"rules": [{"path": "a/*", "allowed_ips": ["10.0.0.1"]}]}`)
	write(aclPath, `{"agents": {"old": {"name": "old", "token_hash": "x", "permissions": [{"path": "a/*", "actions": ["read"]}]}}}`)
	err := runCheckConfig(cfgPath)
	if err == nil {
		t.Fatal("second-pass removals passed")
	}
	for _, want := range []string{"dashboard.pin: removed", "session.roles.r.attestation: removed", "rules: removed", `agent "old" path "a/*"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}
}
