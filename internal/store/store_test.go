package store

import (
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
