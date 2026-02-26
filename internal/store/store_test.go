package store

import (
	"os"
	"path/filepath"
	"testing"

	"git.home/vector/phoenix/internal/crypto"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	masterKey, err := crypto.GenerateAndSaveMasterKey(keyPath)
	if err != nil {
		t.Fatalf("generate master key: %v", err)
	}

	storePath := filepath.Join(dir, "store.json")
	s, err := New(storePath, masterKey)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	return s
}

func TestSetAndGet(t *testing.T) {
	s := newTestStore(t)

	err := s.Set("openclaw/api-key", "sk-12345", "vector", "test key", []string{"test"})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	secret, err := s.Get("openclaw/api-key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if secret.Value != "sk-12345" {
		t.Fatalf("expected 'sk-12345', got %q", secret.Value)
	}
	if secret.Metadata.CreatedBy != "vector" {
		t.Fatalf("expected creator 'vector', got %q", secret.Metadata.CreatedBy)
	}
	if secret.Metadata.Description != "test key" {
		t.Fatalf("expected description 'test key', got %q", secret.Metadata.Description)
	}
}

func TestGetNotFound(t *testing.T) {
	s := newTestStore(t)

	_, err := s.Get("nonexistent/path")
	if err != ErrSecretNotFound {
		t.Fatalf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestUpdate(t *testing.T) {
	s := newTestStore(t)

	s.Set("test/key", "v1", "vector", "version 1", nil)
	s.Set("test/key", "v2", "vector", "", nil) // empty desc = keep existing

	secret, _ := s.Get("test/key")
	if secret.Value != "v2" {
		t.Fatalf("expected 'v2', got %q", secret.Value)
	}
	if secret.Metadata.Description != "version 1" {
		t.Fatalf("expected preserved description 'version 1', got %q", secret.Metadata.Description)
	}
}

func TestDelete(t *testing.T) {
	s := newTestStore(t)

	s.Set("test/key", "value", "vector", "", nil)
	err := s.Delete("test/key")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = s.Get("test/key")
	if err != ErrSecretNotFound {
		t.Fatalf("expected ErrSecretNotFound after delete, got %v", err)
	}
}

func TestDeleteNotFound(t *testing.T) {
	s := newTestStore(t)

	err := s.Delete("nonexistent/path")
	if err != ErrSecretNotFound {
		t.Fatalf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestList(t *testing.T) {
	s := newTestStore(t)

	s.Set("openclaw/key1", "v1", "vector", "", nil)
	s.Set("openclaw/key2", "v2", "vector", "", nil)
	s.Set("monitoring/grafana", "pass", "vector", "", nil)

	all := s.List("")
	if len(all) != 3 {
		t.Fatalf("expected 3 secrets, got %d", len(all))
	}

	oc := s.List("openclaw/")
	if len(oc) != 2 {
		t.Fatalf("expected 2 openclaw secrets, got %d", len(oc))
	}

	mon := s.List("monitoring/")
	if len(mon) != 1 {
		t.Fatalf("expected 1 monitoring secret, got %d", len(mon))
	}

	none := s.List("nonexistent/")
	if len(none) != 0 {
		t.Fatalf("expected 0 secrets, got %d", len(none))
	}
}

func TestCount(t *testing.T) {
	s := newTestStore(t)

	if s.Count() != 0 {
		t.Fatal("expected 0 on empty store")
	}

	s.Set("a/b", "v", "x", "", nil)
	s.Set("c/d", "v", "x", "", nil)

	if s.Count() != 2 {
		t.Fatalf("expected 2, got %d", s.Count())
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	masterKey, _ := crypto.GenerateAndSaveMasterKey(keyPath)
	storePath := filepath.Join(dir, "store.json")

	// Write with one store instance
	s1, _ := New(storePath, masterKey)
	s1.Set("test/persistent", "secret-value", "vector", "persisted", nil)

	// Read with a new store instance (simulates restart)
	s2, err := New(storePath, masterKey)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}

	secret, err := s2.Get("test/persistent")
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if secret.Value != "secret-value" {
		t.Fatalf("expected 'secret-value', got %q", secret.Value)
	}
}

func TestValidatePath(t *testing.T) {
	tests := []struct {
		path  string
		valid bool
	}{
		{"openclaw/key", true},
		{"a/b/c", true},
		{"ns/deep/nested/path", true},
		{"", false},
		{"noslash", false},
		{"/leading", false},
		{"trailing/", false},
		{"double//slash", false},
		{"dot/../traversal", false},
	}

	for _, tt := range tests {
		err := ValidatePath(tt.path)
		if tt.valid && err != nil {
			t.Errorf("path %q should be valid, got error: %v", tt.path, err)
		}
		if !tt.valid && err == nil {
			t.Errorf("path %q should be invalid, got nil error", tt.path)
		}
	}
}

func TestNamespaceIsolation(t *testing.T) {
	s := newTestStore(t)

	// Secrets in different namespaces use different DEKs
	s.Set("ns1/key", "value1", "vector", "", nil)
	s.Set("ns2/key", "value2", "vector", "", nil)

	sec1, _ := s.Get("ns1/key")
	sec2, _ := s.Get("ns2/key")

	if sec1.Value != "value1" || sec2.Value != "value2" {
		t.Fatal("namespace isolation failed")
	}
}

func TestRotateMasterKeySecretsReadable(t *testing.T) {
	s := newTestStore(t)

	// Seed secrets across multiple namespaces
	s.Set("ns1/key1", "value1", "vector", "desc1", []string{"tag1"})
	s.Set("ns1/key2", "value2", "vector", "", nil)
	s.Set("ns2/secret", "s3cr3t", "vector", "important", nil)
	s.Set("ns3/deep/path", "deep-value", "vector", "", nil)

	// Rotate master key
	rotated, err := s.RotateMasterKey()
	if err != nil {
		t.Fatalf("RotateMasterKey: %v", err)
	}
	if rotated != 3 {
		t.Fatalf("expected 3 namespaces rotated, got %d", rotated)
	}

	// Verify all secrets are still readable after rotation
	tests := []struct {
		path, value string
	}{
		{"ns1/key1", "value1"},
		{"ns1/key2", "value2"},
		{"ns2/secret", "s3cr3t"},
		{"ns3/deep/path", "deep-value"},
	}
	for _, tt := range tests {
		sec, err := s.Get(tt.path)
		if err != nil {
			t.Fatalf("Get(%q) after rotation: %v", tt.path, err)
		}
		if sec.Value != tt.value {
			t.Fatalf("Get(%q) = %q, want %q", tt.path, sec.Value, tt.value)
		}
	}

	// Verify metadata preserved
	sec1, _ := s.Get("ns1/key1")
	if sec1.Metadata.Description != "desc1" {
		t.Fatalf("metadata lost: description = %q", sec1.Metadata.Description)
	}
}

func TestRotateMasterKeyEmptyStore(t *testing.T) {
	s := newTestStore(t)

	rotated, err := s.RotateMasterKey()
	if err != nil {
		t.Fatalf("RotateMasterKey on empty store: %v", err)
	}
	if rotated != 0 {
		t.Fatalf("expected 0 namespaces rotated on empty store, got %d", rotated)
	}
}

func TestRotateMasterKeyPersistence(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	masterKey, _ := crypto.GenerateAndSaveMasterKey(keyPath)
	storePath := filepath.Join(dir, "store.json")

	// Create store and seed data
	s1, _ := New(storePath, masterKey)
	s1.Set("test/secret", "original-value", "vector", "", nil)

	// Rotate
	_, err := s1.RotateMasterKey()
	if err != nil {
		t.Fatalf("RotateMasterKey: %v", err)
	}

	// Get the new master key from the provider
	provider := s1.Provider().(*crypto.FileKeyProvider)
	newKey := provider.MasterKey()

	// Open a fresh store with the new key (simulates server restart)
	s2, err := New(storePath, newKey)
	if err != nil {
		t.Fatalf("reopen store with new key: %v", err)
	}

	sec, err := s2.Get("test/secret")
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if sec.Value != "original-value" {
		t.Fatalf("expected 'original-value', got %q", sec.Value)
	}
}

func TestRotateMasterKeyRollback(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	masterKey, _ := crypto.GenerateAndSaveMasterKey(keyPath)
	storePath := filepath.Join(dir, "store.json")

	// Create store and seed data
	s1, _ := New(storePath, masterKey)
	s1.Set("test/secret", "rollback-value", "vector", "", nil)

	// Save old store before rotation for rollback test
	storeBackup := storePath + ".bak"
	data, _ := os.ReadFile(storePath)
	os.WriteFile(storeBackup, data, 0600)

	// Rotate
	s1.RotateMasterKey()

	// Restore old store from backup
	data, _ = os.ReadFile(storeBackup)
	os.WriteFile(storePath, data, 0600)

	// Old key should work with old store
	s2, err := New(storePath, masterKey)
	if err != nil {
		t.Fatalf("reopen store with old key: %v", err)
	}

	sec, err := s2.Get("test/secret")
	if err != nil {
		t.Fatalf("Get after rollback: %v", err)
	}
	if sec.Value != "rollback-value" {
		t.Fatalf("expected 'rollback-value', got %q", sec.Value)
	}
}

func TestRotateMasterKeyNewSecretsWork(t *testing.T) {
	s := newTestStore(t)

	// Seed and rotate
	s.Set("ns1/key", "before", "vector", "", nil)
	s.RotateMasterKey()

	// Write new secrets after rotation
	if err := s.Set("ns1/key2", "after", "vector", "", nil); err != nil {
		t.Fatalf("Set after rotation: %v", err)
	}
	if err := s.Set("ns2/new", "new-ns", "vector", "", nil); err != nil {
		t.Fatalf("Set new namespace after rotation: %v", err)
	}

	// All should be readable
	sec1, _ := s.Get("ns1/key")
	if sec1.Value != "before" {
		t.Fatalf("pre-rotation secret = %q, want 'before'", sec1.Value)
	}
	sec2, _ := s.Get("ns1/key2")
	if sec2.Value != "after" {
		t.Fatalf("post-rotation secret = %q, want 'after'", sec2.Value)
	}
	sec3, _ := s.Get("ns2/new")
	if sec3.Value != "new-ns" {
		t.Fatalf("new namespace secret = %q, want 'new-ns'", sec3.Value)
	}
}
