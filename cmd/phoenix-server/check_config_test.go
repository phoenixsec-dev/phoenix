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
