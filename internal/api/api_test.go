package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"git.home/vector/phoenix/internal/acl"
	"git.home/vector/phoenix/internal/audit"
	"git.home/vector/phoenix/internal/crypto"
	"git.home/vector/phoenix/internal/store"
)

func setupTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()

	// Master key
	masterKey, _ := crypto.GenerateAndSaveMasterKey(filepath.Join(dir, "master.key"))

	// Store
	s, err := store.New(filepath.Join(dir, "store.json"), masterKey)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	// ACL with admin and reader agents
	aclConfig := &acl.ACLConfig{
		Agents: map[string]acl.Agent{
			"admin": {
				Name:      "admin",
				TokenHash: crypto.HashToken("admin-token"),
				Permissions: []acl.Permission{
					{Path: "*", Actions: []acl.Action{acl.ActionAdmin}},
				},
			},
			"reader": {
				Name:      "reader",
				TokenHash: crypto.HashToken("reader-token"),
				Permissions: []acl.Permission{
					{Path: "test/*", Actions: []acl.Action{acl.ActionRead}},
				},
			},
		},
	}
	a := acl.NewFromConfig(aclConfig)

	// Audit logger
	auditPath := filepath.Join(dir, "audit.log")
	al, _ := audit.NewLogger(auditPath)

	srv := NewServer(s, a, al, auditPath)
	return srv, "admin-token"
}

func TestHealthEndpoint(t *testing.T) {
	srv, _ := setupTestServer(t)

	req := httptest.NewRequest("GET", "/v1/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Fatalf("expected status 'ok', got %v", resp["status"])
	}
}

func TestSetAndGetSecret(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Set a secret
	body, _ := json.Marshal(setSecretRequest{
		Value:       "my-secret-value",
		Description: "test secret",
		Tags:        []string{"test"},
	})
	req := httptest.NewRequest("PUT", "/v1/secrets/test/key1", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("SET: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Get the secret
	req = httptest.NewRequest("GET", "/v1/secrets/test/key1", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("GET: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var secret store.Secret
	json.NewDecoder(w.Body).Decode(&secret)
	if secret.Value != "my-secret-value" {
		t.Fatalf("expected 'my-secret-value', got %q", secret.Value)
	}
}

func TestUnauthorized(t *testing.T) {
	srv, _ := setupTestServer(t)

	// No token
	req := httptest.NewRequest("GET", "/v1/secrets/test/key", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	// Wrong token
	req = httptest.NewRequest("GET", "/v1/secrets/test/key", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401 for wrong token, got %d", w.Code)
	}
}

func TestAccessDenied(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Admin sets a secret in a namespace the reader can't access
	body, _ := json.Marshal(setSecretRequest{Value: "secret"})
	req := httptest.NewRequest("PUT", "/v1/secrets/proxmox/admin-token", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("admin SET: expected 200, got %d", w.Code)
	}

	// Reader tries to read it — should be denied
	req = httptest.NewRequest("GET", "/v1/secrets/proxmox/admin-token", nil)
	req.Header.Set("Authorization", "Bearer reader-token")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("expected 403 for reader, got %d: %s", w.Code, w.Body.String())
	}
}

func TestReaderCanReadAllowed(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Admin sets a secret in reader's namespace
	body, _ := json.Marshal(setSecretRequest{Value: "readable"})
	req := httptest.NewRequest("PUT", "/v1/secrets/test/readable-key", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Reader reads it
	req = httptest.NewRequest("GET", "/v1/secrets/test/readable-key", nil)
	req.Header.Set("Authorization", "Bearer reader-token")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200 for reader, got %d: %s", w.Code, w.Body.String())
	}
}

func TestReaderCannotWrite(t *testing.T) {
	srv, _ := setupTestServer(t)

	body, _ := json.Marshal(setSecretRequest{Value: "nope"})
	req := httptest.NewRequest("PUT", "/v1/secrets/test/key", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer reader-token")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("expected 403 for reader write, got %d", w.Code)
	}
}

func TestDeleteSecret(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Create
	body, _ := json.Marshal(setSecretRequest{Value: "to-delete"})
	req := httptest.NewRequest("PUT", "/v1/secrets/test/deleteme", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Delete
	req = httptest.NewRequest("DELETE", "/v1/secrets/test/deleteme", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("DELETE: expected 200, got %d", w.Code)
	}

	// Verify gone
	req = httptest.NewRequest("GET", "/v1/secrets/test/deleteme", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 404 {
		t.Fatalf("expected 404 after delete, got %d", w.Code)
	}
}

func TestListSecrets(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Create some secrets
	for _, path := range []string{"test/a", "test/b", "other/c"} {
		body, _ := json.Marshal(setSecretRequest{Value: "v"})
		req := httptest.NewRequest("PUT", "/v1/secrets/"+path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
	}

	// List all as admin
	req := httptest.NewRequest("GET", "/v1/secrets/", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	paths := resp["paths"].([]interface{})
	if len(paths) != 3 {
		t.Fatalf("admin should see 3 secrets, got %d", len(paths))
	}

	// List as reader (should only see test/*)
	req = httptest.NewRequest("GET", "/v1/secrets/", nil)
	req.Header.Set("Authorization", "Bearer reader-token")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	json.NewDecoder(w.Body).Decode(&resp)
	paths = resp["paths"].([]interface{})
	if len(paths) != 2 {
		t.Fatalf("reader should see 2 secrets, got %d", len(paths))
	}
}

func TestNotFound(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	req := httptest.NewRequest("GET", "/v1/secrets/nonexistent/path", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 404 {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGetInvalidPath(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Path with no slash (fails ValidatePath)
	req := httptest.NewRequest("GET", "/v1/secrets/noslash", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400 for invalid path, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDeleteInvalidPath(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	req := httptest.NewRequest("DELETE", "/v1/secrets/noslash", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400 for invalid delete path, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSetInvalidPath(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	body, _ := json.Marshal(setSecretRequest{Value: "test"})
	req := httptest.NewRequest("PUT", "/v1/secrets/noslash", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400 for invalid set path, got %d: %s", w.Code, w.Body.String())
	}
}

func TestClientIPIgnoresXFF(t *testing.T) {
	// X-Forwarded-For should be ignored — spoofed header must not affect audit
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.0.115:12345"
	req.Header.Set("X-Forwarded-For", "10.0.0.1")

	ip := clientIP(req)
	if ip != "192.168.0.115" {
		t.Fatalf("expected RemoteAddr IP '192.168.0.115', got %q (XFF was trusted)", ip)
	}
}

func TestClientIPIPv6(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "[::1]:12345"

	ip := clientIP(req)
	if ip != "::1" {
		t.Fatalf("expected '::1', got %q", ip)
	}
}

func TestOversizedRequestBody(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Create a body larger than MaxRequestBodyBytes (1 MB)
	bigValue := strings.Repeat("x", MaxRequestBodyBytes+1)
	body, _ := json.Marshal(setSecretRequest{Value: bigValue})
	req := httptest.NewRequest("PUT", "/v1/secrets/test/big", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized body, got %d: %s", w.Code, w.Body.String())
	}
}
