package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/audit"
	"github.com/phoenixsec/phoenix/internal/crypto"
	"github.com/phoenixsec/phoenix/internal/store"
)

// stubBackend is a read-only SecretBackend for testing non-file backend paths.
type stubBackend struct {
	secrets  map[string]*store.Secret
	listErr  error // if set, List returns this error
	readOnly bool
}

func (b *stubBackend) Get(path string) (*store.Secret, error) {
	if err := store.ValidatePath(path); err != nil {
		return nil, err
	}
	s, ok := b.secrets[path]
	if !ok {
		return nil, store.ErrSecretNotFound
	}
	return s, nil
}

func (b *stubBackend) List(prefix string) ([]string, error) {
	if b.listErr != nil {
		return nil, b.listErr
	}
	var paths []string
	for p := range b.secrets {
		if prefix == "" || strings.HasPrefix(p, prefix) {
			paths = append(paths, p)
		}
	}
	return paths, nil
}

func (b *stubBackend) Set(path, value, createdBy, description string, tags []string) error {
	if b.readOnly {
		return store.ErrReadOnly
	}
	return nil
}

func (b *stubBackend) Delete(path string) error {
	if b.readOnly {
		return store.ErrReadOnly
	}
	return nil
}

func (b *stubBackend) Count() int { return len(b.secrets) }
func (b *stubBackend) ReadOnly() bool { return b.readOnly }
func (b *stubBackend) Name() string { return "stub" }

func setupStubServer(t *testing.T, backend store.SecretBackend) (*Server, string) {
	t.Helper()
	dir := t.TempDir()

	aclConfig := &acl.ACLConfig{
		Agents: map[string]acl.Agent{
			"admin": {
				Name:      "admin",
				TokenHash: crypto.HashToken("admin-token"),
				Permissions: []acl.Permission{
					{Path: "*", Actions: []acl.Action{acl.ActionAdmin}},
				},
			},
		},
	}
	a := acl.NewFromConfig(aclConfig)

	auditPath := filepath.Join(dir, "audit.log")
	al, _ := audit.NewLogger(auditPath)

	srv := NewServer(backend, a, al, auditPath)
	return srv, "admin-token"
}

func TestReadOnlyBackendRejectsWrite(t *testing.T) {
	backend := &stubBackend{readOnly: true, secrets: map[string]*store.Secret{}}
	srv, token := setupStubServer(t, backend)

	body, _ := json.Marshal(setSecretRequest{Value: "v", Description: "d"})
	req := httptest.NewRequest("PUT", "/v1/secrets/test/key1", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if !strings.Contains(resp["error"], "read-only") {
		t.Fatalf("expected read-only error, got %q", resp["error"])
	}
}

func TestReadOnlyBackendRejectsDelete(t *testing.T) {
	backend := &stubBackend{readOnly: true, secrets: map[string]*store.Secret{
		"test/key1": {Path: "test/key1", Value: "v"},
	}}
	srv, token := setupStubServer(t, backend)

	req := httptest.NewRequest("DELETE", "/v1/secrets/test/key1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d: %s", w.Code, w.Body.String())
	}
}

func TestReadOnlyBackendAllowsRead(t *testing.T) {
	backend := &stubBackend{readOnly: true, secrets: map[string]*store.Secret{
		"test/key1": {Path: "test/key1", Value: "secret-val"},
	}}
	srv, token := setupStubServer(t, backend)

	req := httptest.NewRequest("GET", "/v1/secrets/test/key1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp store.Secret
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Value != "secret-val" {
		t.Fatalf("expected 'secret-val', got %q", resp.Value)
	}
}

func TestReadOnlyBackendAllowsList(t *testing.T) {
	backend := &stubBackend{readOnly: true, secrets: map[string]*store.Secret{
		"test/a": {Path: "test/a", Value: "v"},
		"test/b": {Path: "test/b", Value: "v"},
	}}
	srv, token := setupStubServer(t, backend)

	req := httptest.NewRequest("GET", "/v1/secrets/test/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	paths := resp["paths"].([]interface{})
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(paths))
	}
}

func TestListErrorReturns500(t *testing.T) {
	backend := &stubBackend{
		readOnly: true,
		secrets:  map[string]*store.Secret{},
		listErr:  fmt.Errorf("connection to 1Password timed out"),
	}
	srv, token := setupStubServer(t, backend)

	req := httptest.NewRequest("GET", "/v1/secrets/test/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

func TestNonFileBackendRotationReturns501(t *testing.T) {
	backend := &stubBackend{readOnly: true, secrets: map[string]*store.Secret{}}
	srv, token := setupStubServer(t, backend)

	req := httptest.NewRequest("POST", "/v1/rotate-master", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if !strings.Contains(resp["error"], "not supported") {
		t.Fatalf("expected 'not supported' error, got %q", resp["error"])
	}
}

func TestFileBackendParityViaInterface(t *testing.T) {
	// Verify FileBackend satisfies SecretBackend and produces identical
	// results to direct Store usage.
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	masterKey, _ := crypto.GenerateAndSaveMasterKey(keyPath)

	s, err := store.New(filepath.Join(dir, "store.json"), masterKey)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	var backend store.SecretBackend = store.NewFileBackend(s)

	if backend.ReadOnly() {
		t.Fatal("FileBackend should not be read-only")
	}
	if backend.Name() != "file" {
		t.Fatalf("expected name 'file', got %q", backend.Name())
	}

	// Set via backend
	if err := backend.Set("ns/key1", "value1", "test", "desc", nil); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Get via backend
	secret, err := backend.Get("ns/key1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if secret.Value != "value1" {
		t.Fatalf("expected 'value1', got %q", secret.Value)
	}

	// List via backend
	paths, err := backend.List("ns/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(paths) != 1 || paths[0] != "ns/key1" {
		t.Fatalf("expected [ns/key1], got %v", paths)
	}

	// Count
	if backend.Count() != 1 {
		t.Fatalf("expected count 1, got %d", backend.Count())
	}

	// Delete via backend
	if err := backend.Delete("ns/key1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if backend.Count() != 0 {
		t.Fatalf("expected count 0 after delete, got %d", backend.Count())
	}

	// Get after delete
	_, err = backend.Get("ns/key1")
	if err != store.ErrSecretNotFound {
		t.Fatalf("expected ErrSecretNotFound, got %v", err)
	}
}
