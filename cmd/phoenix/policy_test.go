package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

	// An empty rule passes
	err := cmdPolicyTest([]string{"open/key"})
	if err != nil {
		t.Fatalf("expected pass: %v", err)
	}
}

func TestCmdPolicyTestNoMatch(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	os.WriteFile(policyPath, []byte(`{"attestation":{"prod/*":{"source_ip":["10.0.0.1"]}}}`), 0644)

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

func TestCmdPolicyShowIncludesRequireSealed(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	policyData := `{
		"attestation": {
			"secure/*": {
				"require_sealed": true
			}
		}
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
	if !strings.Contains(out, "require_sealed: true") {
		t.Fatalf("expected require_sealed in output, got: %s", out)
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
