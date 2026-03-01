package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCmdPolicyTestTimeWindow(t *testing.T) {
	// Create a policy file with time_window
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	policyData := `{
		"attestation": {
			"prod/*": {
				"time_window": "09:00-17:00",
				"time_zone": "UTC"
			}
		}
	}`
	os.WriteFile(policyPath, []byte(policyData), 0644)

	// Set PHOENIX_POLICY
	origPolicy := os.Getenv("PHOENIX_POLICY")
	os.Setenv("PHOENIX_POLICY", policyPath)
	defer os.Setenv("PHOENIX_POLICY", origPolicy)

	// Test within window — should pass
	err := cmdPolicyTest([]string{"--time", "2026-03-01T12:00:00Z", "prod/db-password"})
	if err != nil {
		t.Fatalf("expected pass within time window: %v", err)
	}

	// Test outside window — should print FAIL but not return error
	err = cmdPolicyTest([]string{"--time", "2026-03-01T03:00:00Z", "prod/db-password"})
	if err != nil {
		t.Fatalf("cmdPolicyTest should not return error (it prints FAIL): %v", err)
	}
}

func TestCmdPolicyTestNoTimeFlag(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	policyData := `{
		"attestation": {
			"open/*": {}
		}
	}`
	os.WriteFile(policyPath, []byte(policyData), 0644)

	origPolicy := os.Getenv("PHOENIX_POLICY")
	os.Setenv("PHOENIX_POLICY", policyPath)
	defer os.Setenv("PHOENIX_POLICY", origPolicy)

	// Without --time should use current time and pass
	err := cmdPolicyTest([]string{"open/key"})
	if err != nil {
		t.Fatalf("expected pass: %v", err)
	}
}

func TestCmdPolicyTestInvalidTime(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	os.WriteFile(policyPath, []byte(`{"attestation":{}}`), 0644)

	origPolicy := os.Getenv("PHOENIX_POLICY")
	os.Setenv("PHOENIX_POLICY", policyPath)
	defer os.Setenv("PHOENIX_POLICY", origPolicy)

	err := cmdPolicyTest([]string{"--time", "not-a-time", "test/key"})
	if err == nil {
		t.Fatal("expected error for invalid --time value")
	}
}

func TestCmdPolicyTestNoMatch(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	os.WriteFile(policyPath, []byte(`{"attestation":{"prod/*":{"require_mtls":true}}}`), 0644)

	origPolicy := os.Getenv("PHOENIX_POLICY")
	os.Setenv("PHOENIX_POLICY", policyPath)
	defer os.Setenv("PHOENIX_POLICY", origPolicy)

	// Path doesn't match any policy
	err := cmdPolicyTest([]string{"dev/key"})
	if err != nil {
		t.Fatalf("no-match should not return error: %v", err)
	}
}

func TestCmdPolicyTestIPCheck(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	policyData := `{
		"attestation": {
			"net/*": {
				"source_ip": ["192.168.1.10"]
			}
		}
	}`
	os.WriteFile(policyPath, []byte(policyData), 0644)

	origPolicy := os.Getenv("PHOENIX_POLICY")
	os.Setenv("PHOENIX_POLICY", policyPath)
	defer os.Setenv("PHOENIX_POLICY", origPolicy)

	// Matching IP
	err := cmdPolicyTest([]string{"--ip", "192.168.1.10", "net/key"})
	if err != nil {
		t.Fatalf("expected pass with matching IP: %v", err)
	}

	// Non-matching IP — prints FAIL but no error return
	err = cmdPolicyTest([]string{"--ip", "10.0.0.1", "net/key"})
	if err != nil {
		t.Fatalf("should not return error: %v", err)
	}
}

func TestCmdPolicyShowLegacyRulesFormat(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	policyData := `{
		"rules": [
			{
				"path": "secure/*",
				"require_mtls": true,
				"allowed_ips": ["192.168.0.0/24"]
			}
		]
	}`
	if err := os.WriteFile(policyPath, []byte(policyData), 0644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	origPolicy := os.Getenv("PHOENIX_POLICY")
	os.Setenv("PHOENIX_POLICY", policyPath)
	defer os.Setenv("PHOENIX_POLICY", origPolicy)

	out := captureStdout(t, func() {
		if err := cmdPolicyShow([]string{"secure/db"}); err != nil {
			t.Fatalf("cmdPolicyShow: %v", err)
		}
	})
	if !strings.Contains(out, "Pattern: secure/*") {
		t.Fatalf("expected matched pattern in output, got: %s", out)
	}
	if !strings.Contains(out, `source_ip: ["192.168.0.0/24"]`) {
		t.Fatalf("expected source_ip in output, got: %s", out)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("close write pipe: %v", err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close read pipe: %v", err)
	}
	return buf.String()
}
