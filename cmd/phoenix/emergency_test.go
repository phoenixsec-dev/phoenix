package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.home/vector/phoenix/internal/crypto"
	"git.home/vector/phoenix/internal/store"
)

// setupEmergencyDir creates a minimal Phoenix data dir with one secret.
func setupEmergencyDir(t *testing.T, passphrase string) (dir string) {
	t.Helper()
	dir = t.TempDir()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	keyPath := filepath.Join(dir, "master.key")
	if passphrase != "" {
		if err := crypto.SaveProtectedMasterKey(keyPath, key, passphrase); err != nil {
			t.Fatalf("saving protected key: %v", err)
		}
	} else {
		encoded := base64.StdEncoding.EncodeToString(key)
		if err := os.WriteFile(keyPath, []byte(encoded), 0600); err != nil {
			t.Fatalf("writing key: %v", err)
		}
	}

	storePath := filepath.Join(dir, "store.json")
	s, err := store.New(storePath, key)
	if err != nil {
		t.Fatalf("creating store: %v", err)
	}
	if err := s.Set("test/secret", "hunter2", "admin", "test secret", nil); err != nil {
		t.Fatalf("setting secret: %v", err)
	}

	return dir
}

func TestEmergencyGetRejectsWildcards(t *testing.T) {
	err := cmdEmergencyGet([]string{"test/*", "--data-dir", "/tmp", "--confirm"})
	if err == nil {
		t.Fatal("expected error for wildcard path")
	}
	if !strings.Contains(err.Error(), "single-secret only") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEmergencyGetRejectsPrefix(t *testing.T) {
	err := cmdEmergencyGet([]string{"test/", "--data-dir", "/tmp", "--confirm"})
	if err == nil {
		t.Fatal("expected error for prefix path")
	}
	if !strings.Contains(err.Error(), "single-secret only") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEmergencyGetRequiresConfirm(t *testing.T) {
	dir := setupEmergencyDir(t, "")

	// Without --confirm and without TTY, reading stdin returns empty = abort
	err := cmdEmergencyGet([]string{"test/secret", "--data-dir", dir})
	if err == nil {
		t.Fatal("expected error without confirmation")
	}
	if !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("expected abort error, got: %v", err)
	}
}

func TestEmergencyGetWithConfirmFlag(t *testing.T) {
	dir := setupEmergencyDir(t, "")

	// With --confirm flag, should succeed
	err := cmdEmergencyGet([]string{"test/secret", "--data-dir", dir, "--confirm"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check audit log was written
	auditPath := filepath.Join(dir, "audit.log")
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	if !strings.Contains(string(data), "emergency-local") {
		t.Fatal("audit log should contain emergency-local entry")
	}

	// Verify it's valid JSON
	var entry struct {
		Agent  string `json:"agent"`
		Action string `json:"action"`
		Path   string `json:"path"`
	}
	if err := json.Unmarshal(data[:len(data)-1], &entry); err != nil {
		t.Fatalf("audit entry is not valid JSON: %v", err)
	}
	if entry.Agent != "emergency-local" {
		t.Fatalf("expected agent emergency-local, got %s", entry.Agent)
	}
	if entry.Path != "test/secret" {
		t.Fatalf("expected path test/secret, got %s", entry.Path)
	}
}

func TestEmergencyGetMissingArgs(t *testing.T) {
	err := cmdEmergencyGet([]string{})
	if err == nil {
		t.Fatal("expected error for missing args")
	}
	if !strings.Contains(err.Error(), "usage") {
		t.Fatalf("expected usage error, got: %v", err)
	}
}

func TestEmergencyGetSecretNotFound(t *testing.T) {
	dir := setupEmergencyDir(t, "")
	err := cmdEmergencyGet([]string{"test/nonexistent", "--data-dir", dir, "--confirm"})
	if err == nil {
		t.Fatal("expected error for nonexistent secret")
	}
}
