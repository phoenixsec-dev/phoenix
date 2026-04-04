package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/approval"
	"github.com/phoenixsec/phoenix/internal/audit"
	"github.com/phoenixsec/phoenix/internal/ca"
	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/crypto"
	"github.com/phoenixsec/phoenix/internal/nonce"
	"github.com/phoenixsec/phoenix/internal/policy"
	"github.com/phoenixsec/phoenix/internal/session"
	"github.com/phoenixsec/phoenix/internal/store"
	"github.com/phoenixsec/phoenix/internal/token"
)

func setupTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()

	// Master key
	keyPath := filepath.Join(dir, "master.key")
	masterKey, _ := crypto.GenerateAndSaveMasterKey(keyPath)

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

	fb := store.NewFileBackend(s)
	srv := NewServer(fb, a, al, auditPath)
	srv.SetMasterKeyPath(keyPath)
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

// setupTestServerWithCA creates a test server with mTLS support.
func setupTestServerWithCA(t *testing.T) (*Server, *ca.CA, string) {
	t.Helper()
	srv, adminToken := setupTestServer(t)

	authority, err := ca.GenerateCA("TestOrg")
	if err != nil {
		t.Fatalf("generating CA: %v", err)
	}
	srv.SetCA(authority)

	return srv, authority, adminToken
}

// makeMTLSRequest creates an HTTP request that simulates a verified mTLS client cert.
// In real mTLS the TLS handshake populates r.TLS; in tests we set it directly.
func makeMTLSRequest(method, url string, body []byte, certPEM []byte) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, url, bytes.NewReader(body))
	} else {
		req = httptest.NewRequest(method, url, nil)
	}

	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	return req
}

func TestMTLSAuthentication(t *testing.T) {
	srv, authority, adminToken := setupTestServerWithCA(t)

	// Create a secret via bearer token first
	body, _ := json.Marshal(setSecretRequest{Value: "mtls-test-value"})
	req := httptest.NewRequest("PUT", "/v1/secrets/test/mtls-key", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("setup SET: expected 200, got %d", w.Code)
	}

	// Issue a client cert for "reader" agent
	bundle, err := authority.IssueAgentCert("reader")
	if err != nil {
		t.Fatalf("issuing cert: %v", err)
	}

	// Read the secret using mTLS auth (no bearer token)
	req = makeMTLSRequest("GET", "/v1/secrets/test/mtls-key", nil, bundle.CertPEM)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("mTLS GET: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var secret store.Secret
	json.NewDecoder(w.Body).Decode(&secret)
	if secret.Value != "mtls-test-value" {
		t.Fatalf("expected 'mtls-test-value', got %q", secret.Value)
	}
}

func TestMTLSAdminCanIssueCerts(t *testing.T) {
	srv, authority, _ := setupTestServerWithCA(t)

	// Issue an admin cert
	adminBundle, err := authority.IssueAgentCert("admin")
	if err != nil {
		t.Fatalf("issuing admin cert: %v", err)
	}

	// Use mTLS admin cert to issue another cert via the API
	body, _ := json.Marshal(issueCertRequest{AgentName: "newagent"})
	req := makeMTLSRequest("POST", "/v1/certs/issue", body, adminBundle.CertPEM)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("issue cert: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["agent"] != "newagent" {
		t.Fatalf("expected agent 'newagent', got %v", resp["agent"])
	}
	if resp["cert"] == nil || resp["cert"] == "" {
		t.Fatal("expected cert in response")
	}
	if resp["key"] == nil || resp["key"] == "" {
		t.Fatal("expected key in response")
	}
}

func TestBearerTokenStillWorksWithCA(t *testing.T) {
	srv, _, adminToken := setupTestServerWithCA(t)

	// Bearer token should still work even when CA is configured
	req := httptest.NewRequest("GET", "/v1/health", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("bearer with CA: expected 200, got %d", w.Code)
	}
}

func TestMTLSRevokedCertFallsBackToBearer(t *testing.T) {
	srv, authority, adminToken := setupTestServerWithCA(t)

	// Issue and then revoke a cert for "admin"
	bundle, _ := authority.IssueAgentCert("admin")
	block, _ := pem.Decode(bundle.CertPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	if err := authority.RevokeCert(cert.SerialNumber, "admin"); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}

	// Request with revoked mTLS cert + valid bearer token → should succeed via bearer fallback
	req := makeMTLSRequest("GET", "/v1/health", nil, bundle.CertPEM)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("revoked cert + bearer: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestNoAuthReturns401(t *testing.T) {
	srv, _, _ := setupTestServerWithCA(t)

	// No mTLS cert, no bearer token
	req := httptest.NewRequest("GET", "/v1/secrets/test/key", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Fatalf("no auth: expected 401, got %d", w.Code)
	}
}

func TestIssueCertWithoutCA(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// No CA configured — should return 501
	body, _ := json.Marshal(issueCertRequest{AgentName: "test"})
	req := httptest.NewRequest("POST", "/v1/certs/issue", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 501 {
		t.Fatalf("issue cert without CA: expected 501, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBearerDisabledRejectsTokenAuth(t *testing.T) {
	srv, _, adminToken := setupTestServerWithCA(t)
	srv.SetBearerEnabled(false)

	// Bearer token should be rejected when bearer auth is disabled
	req := httptest.NewRequest("GET", "/v1/secrets/test/key", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Fatalf("bearer disabled: expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBearerDisabledStillAllowsMTLS(t *testing.T) {
	srv, authority, adminToken := setupTestServerWithCA(t)
	srv.SetBearerEnabled(false)

	// First set a secret with bearer (re-enable temporarily)
	srv.SetBearerEnabled(true)
	body, _ := json.Marshal(setSecretRequest{Value: "mtls-only"})
	req := httptest.NewRequest("PUT", "/v1/secrets/test/mtls-key", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("setup: expected 200, got %d", w.Code)
	}
	srv.SetBearerEnabled(false)

	// mTLS should still work
	bundle, _ := authority.IssueAgentCert("reader")
	req = makeMTLSRequest("GET", "/v1/secrets/test/mtls-key", nil, bundle.CertPEM)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("mTLS with bearer disabled: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIssueCertRequiresAdmin(t *testing.T) {
	srv, authority, _ := setupTestServerWithCA(t)

	// Issue cert for reader agent
	readerBundle, _ := authority.IssueAgentCert("reader")

	// Reader tries to issue a cert — should be denied
	body, _ := json.Marshal(issueCertRequest{AgentName: "sneaky"})
	req := makeMTLSRequest("POST", "/v1/certs/issue", body, readerBundle.CertPEM)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("reader issue cert: expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRotateMasterKeyEndpoint(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Seed secrets
	for _, path := range []string{"ns1/key1", "ns2/key2"} {
		body, _ := json.Marshal(setSecretRequest{Value: "value-" + path})
		req := httptest.NewRequest("PUT", "/v1/secrets/"+path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("setup SET %s: expected 200, got %d", path, w.Code)
		}
	}

	// Rotate
	req := httptest.NewRequest("POST", "/v1/rotate-master", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("rotate: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Fatalf("rotate status: %v", resp["status"])
	}
	rotated := int(resp["rotated"].(float64))
	if rotated != 2 {
		t.Fatalf("expected 2 namespaces rotated, got %d", rotated)
	}

	// Verify secrets are still readable after rotation
	for _, path := range []string{"ns1/key1", "ns2/key2"} {
		req := httptest.NewRequest("GET", "/v1/secrets/"+path, nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Fatalf("GET %s after rotation: expected 200, got %d: %s", path, w.Code, w.Body.String())
		}

		var secret store.Secret
		json.NewDecoder(w.Body).Decode(&secret)
		if secret.Value != "value-"+path {
			t.Fatalf("GET %s after rotation: expected 'value-%s', got %q", path, path, secret.Value)
		}
	}
}

func TestRotateMasterKeyRequiresAdmin(t *testing.T) {
	srv, _ := setupTestServer(t)

	// Reader tries to rotate — should be denied
	req := httptest.NewRequest("POST", "/v1/rotate-master", nil)
	req.Header.Set("Authorization", "Bearer reader-token")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("reader rotate: expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRotateMasterKeyRequiresAuth(t *testing.T) {
	srv, _ := setupTestServer(t)

	req := httptest.NewRequest("POST", "/v1/rotate-master", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Fatalf("unauthenticated rotate: expected 401, got %d", w.Code)
	}
}

func TestRotateMasterKeyBackupCreated(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Seed a secret so there's something to rotate
	body, _ := json.Marshal(setSecretRequest{Value: "v"})
	req := httptest.NewRequest("PUT", "/v1/secrets/test/key", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Rotate
	req = httptest.NewRequest("POST", "/v1/rotate-master", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("rotate: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	backup := resp["backup"].(string)
	if !strings.HasSuffix(backup, ".prev") {
		t.Fatalf("expected backup path ending in .prev, got %q", backup)
	}

	// Verify the backup file exists
	info, err := os.Stat(backup)
	if err != nil {
		t.Fatalf("backup file %s not found: %v", backup, err)
	}
	if info.Size() == 0 {
		t.Fatal("backup file is empty")
	}
}

func TestRotateMasterKeyEmptyStore(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Rotate on empty store — should succeed with 0 namespaces
	req := httptest.NewRequest("POST", "/v1/rotate-master", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("rotate empty: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	rotated := int(resp["rotated"].(float64))
	if rotated != 0 {
		t.Fatalf("expected 0 namespaces rotated on empty store, got %d", rotated)
	}
}

func TestRotateMasterKeyFileWriteFailureRollsBack(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Seed a secret
	body, _ := json.Marshal(setSecretRequest{Value: "precious"})
	req := httptest.NewRequest("PUT", "/v1/secrets/test/key", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("setup SET: expected 200, got %d", w.Code)
	}

	// Make the master key file's directory unwritable to force key file write failure
	keyDir := filepath.Dir(srv.masterKeyPath)
	os.Chmod(keyDir, 0500)
	defer os.Chmod(keyDir, 0700)

	// Attempt rotation — should fail and roll back
	req = httptest.NewRequest("POST", "/v1/rotate-master", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 500 {
		t.Fatalf("expected 500 on key write failure, got %d: %s", w.Code, w.Body.String())
	}

	// Restore write permissions
	os.Chmod(keyDir, 0700)

	// Secret should still be readable (rollback preserved old state)
	req = httptest.NewRequest("GET", "/v1/secrets/test/key", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("GET after failed rotation: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var secret store.Secret
	json.NewDecoder(w.Body).Decode(&secret)
	if secret.Value != "precious" {
		t.Fatalf("secret value after rollback = %q, want 'precious'", secret.Value)
	}

	// A subsequent rotation should succeed (state is clean)
	req = httptest.NewRequest("POST", "/v1/rotate-master", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("retry rotation: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRotateMasterKeyPersistenceWithNewKey(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Seed secrets
	body, _ := json.Marshal(setSecretRequest{Value: "persist-test"})
	req := httptest.NewRequest("PUT", "/v1/secrets/test/persist", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Rotate
	req = httptest.NewRequest("POST", "/v1/rotate-master", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("rotate: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Load the new key from disk and verify it matches the provider
	newKey, err := crypto.LoadMasterKey(srv.masterKeyPath)
	if err != nil {
		t.Fatalf("loading new master key from disk: %v", err)
	}

	provider := srv.fileBackend.Provider().(*crypto.FileKeyProvider)
	if !bytes.Equal(newKey, provider.MasterKey()) {
		t.Fatal("key on disk does not match in-memory provider key after rotation")
	}

	// Pending key should be nil (committed)
	if provider.PendingMasterKey() != nil {
		t.Fatal("pending key still set after successful rotation")
	}
}

func TestResolveEndpoint(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Seed secrets
	for _, s := range []struct{ path, value string }{
		{"test/key1", "value1"},
		{"test/key2", "value2"},
		{"other/key3", "value3"},
	} {
		body, _ := json.Marshal(setSecretRequest{Value: s.value})
		req := httptest.NewRequest("PUT", "/v1/secrets/"+s.path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("setup SET %s: expected 200, got %d", s.path, w.Code)
		}
	}

	// Resolve multiple refs as admin
	body, _ := json.Marshal(map[string]interface{}{
		"refs": []string{
			"phoenix://test/key1",
			"phoenix://test/key2",
			"phoenix://other/key3",
		},
	})
	req := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("resolve: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	values := resp["values"].(map[string]interface{})
	if values["phoenix://test/key1"] != "value1" {
		t.Fatalf("key1 = %v, want 'value1'", values["phoenix://test/key1"])
	}
	if values["phoenix://test/key2"] != "value2" {
		t.Fatalf("key2 = %v, want 'value2'", values["phoenix://test/key2"])
	}
	if values["phoenix://other/key3"] != "value3" {
		t.Fatalf("key3 = %v, want 'value3'", values["phoenix://other/key3"])
	}

	// No errors field when all succeed
	if resp["errors"] != nil {
		t.Fatalf("expected no errors, got %v", resp["errors"])
	}
}

func TestResolvePartialFailure(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Seed one secret
	body, _ := json.Marshal(setSecretRequest{Value: "exists"})
	req := httptest.NewRequest("PUT", "/v1/secrets/test/exists", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Resolve mix of valid, not-found, and invalid refs
	body, _ = json.Marshal(map[string]interface{}{
		"refs": []string{
			"phoenix://test/exists",  // exists
			"phoenix://test/missing", // not found
			"not-a-ref",              // invalid scheme
			"phoenix://noslash",      // invalid path
		},
	})
	req = httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("resolve: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	values := resp["values"].(map[string]interface{})
	if values["phoenix://test/exists"] != "exists" {
		t.Fatalf("exists = %v, want 'exists'", values["phoenix://test/exists"])
	}
	if len(values) != 1 {
		t.Fatalf("expected 1 value, got %d", len(values))
	}

	errors := resp["errors"].(map[string]interface{})
	if len(errors) != 3 {
		t.Fatalf("expected 3 errors, got %d: %v", len(errors), errors)
	}
	if errors["phoenix://test/missing"] != "secret not found" {
		t.Fatalf("missing error = %v", errors["phoenix://test/missing"])
	}
}

func TestResolveACLEnforcement(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Seed secrets in test/ and other/ namespaces
	for _, s := range []struct{ path, value string }{
		{"test/readable", "reader-can-see"},
		{"other/hidden", "reader-cannot-see"},
	} {
		body, _ := json.Marshal(setSecretRequest{Value: s.value})
		req := httptest.NewRequest("PUT", "/v1/secrets/"+s.path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
	}

	// Resolve as reader (has test/* read, NOT other/*)
	body, _ := json.Marshal(map[string]interface{}{
		"refs": []string{
			"phoenix://test/readable",
			"phoenix://other/hidden",
		},
	})
	req := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer reader-token")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("resolve: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	values := resp["values"].(map[string]interface{})
	if values["phoenix://test/readable"] != "reader-can-see" {
		t.Fatalf("readable = %v", values["phoenix://test/readable"])
	}

	errors := resp["errors"].(map[string]interface{})
	hiddenErr, _ := errors["phoenix://other/hidden"].(string)
	if !strings.Contains(hiddenErr, "access denied") {
		t.Fatalf("hidden error = %v, want string containing 'access denied'", errors["phoenix://other/hidden"])
	}
}

func TestResolveRequiresAuth(t *testing.T) {
	srv, _ := setupTestServer(t)

	body, _ := json.Marshal(map[string]interface{}{
		"refs": []string{"phoenix://test/key"},
	})
	req := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Fatalf("unauthenticated resolve: expected 401, got %d", w.Code)
	}
}

func TestResolveAuditsAllPaths(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Seed one secret
	body, _ := json.Marshal(setSecretRequest{Value: "secret-val"})
	req := httptest.NewRequest("PUT", "/v1/secrets/test/audited", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("setup: expected 200, got %d", w.Code)
	}

	// Resolve: 1 success, 1 not-found, 1 malformed ref
	body, _ = json.Marshal(map[string]interface{}{
		"refs": []string{
			"phoenix://test/audited", // success
			"phoenix://test/missing", // not found
			"not-a-ref",              // malformed
		},
	})
	req = httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("resolve: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Query audit log for resolve entries
	req = httptest.NewRequest("GET", "/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("audit query: expected 200, got %d", w.Code)
	}

	var auditResp struct {
		Entries []struct {
			Agent  string `json:"agent"`
			Action string `json:"action"`
			Path   string `json:"path"`
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"entries"`
	}
	json.NewDecoder(w.Body).Decode(&auditResp)

	// Filter to resolve entries only (ignore set audit entries from setup)
	type resolveEntry struct {
		path, status, reason string
	}
	var resolves []resolveEntry
	for _, e := range auditResp.Entries {
		if e.Action == "resolve" {
			resolves = append(resolves, resolveEntry{e.Path, e.Status, e.Reason})
		}
	}

	if len(resolves) != 3 {
		t.Fatalf("expected 3 resolve audit entries, got %d: %+v", len(resolves), resolves)
	}

	// Check each expected audit entry exists
	found := map[string]bool{"allowed": false, "not_found": false, "malformed_ref": false}
	for _, e := range resolves {
		switch {
		case e.status == "allowed" && e.path == "test/audited":
			found["allowed"] = true
		case e.status == "denied" && e.reason == "not_found" && e.path == "test/missing":
			found["not_found"] = true
		case e.status == "denied" && e.reason == "malformed_ref" && e.path == "not-a-ref":
			found["malformed_ref"] = true
		}
	}

	for kind, ok := range found {
		if !ok {
			t.Errorf("missing audit entry for %s; got entries: %+v", kind, resolves)
		}
	}
}

func TestResolveEmptyRefs(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	body, _ := json.Marshal(map[string]interface{}{
		"refs": []string{},
	})
	req := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("empty refs: expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestResolveDryRun(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Seed a secret
	body, _ := json.Marshal(setSecretRequest{Value: "super-secret"})
	req := httptest.NewRequest("PUT", "/v1/secrets/test/drykey", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("setup: expected 200, got %d", w.Code)
	}

	// Dry-run resolve — should return "ok" not the actual value
	body, _ = json.Marshal(map[string]interface{}{
		"refs": []string{"phoenix://test/drykey"},
	})
	req = httptest.NewRequest("POST", "/v1/resolve?dry_run=true", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("dry_run resolve: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	values := resp["values"].(map[string]interface{})

	val := values["phoenix://test/drykey"]
	if val != "ok" {
		t.Fatalf("dry_run should return 'ok', got %q", val)
	}
	if val == "super-secret" {
		t.Fatal("dry_run must NOT return the actual secret value")
	}
}

func TestResolveDryRunNotFound(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	body, _ := json.Marshal(map[string]interface{}{
		"refs": []string{"phoenix://test/nonexistent"},
	})
	req := httptest.NewRequest("POST", "/v1/resolve?dry_run=true", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	errors := resp["errors"].(map[string]interface{})

	if errors["phoenix://test/nonexistent"] != "secret not found" {
		t.Fatalf("expected 'secret not found', got %v", errors["phoenix://test/nonexistent"])
	}
}

func TestResolveDryRunAuditsAllPaths(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Seed a secret
	body, _ := json.Marshal(setSecretRequest{Value: "secret-val"})
	req := httptest.NewRequest("PUT", "/v1/secrets/test/dryaudit", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("setup: expected 200, got %d", w.Code)
	}

	// Dry-run resolve: 1 success, 1 not-found
	body, _ = json.Marshal(map[string]interface{}{
		"refs": []string{
			"phoenix://test/dryaudit",
			"phoenix://test/missing",
		},
	})
	req = httptest.NewRequest("POST", "/v1/resolve?dry_run=true", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("dry-run resolve: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Query audit log
	req = httptest.NewRequest("GET", "/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("audit query: expected 200, got %d", w.Code)
	}

	var auditResp struct {
		Entries []struct {
			Action string `json:"action"`
			Path   string `json:"path"`
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"entries"`
	}
	json.NewDecoder(w.Body).Decode(&auditResp)

	// Filter to dry-resolve entries
	var dryResolves []struct{ path, status, reason string }
	for _, e := range auditResp.Entries {
		if e.Action == "dry-resolve" {
			dryResolves = append(dryResolves, struct{ path, status, reason string }{e.Path, e.Status, e.Reason})
		}
	}

	if len(dryResolves) != 2 {
		t.Fatalf("expected 2 dry-resolve audit entries, got %d: %+v", len(dryResolves), dryResolves)
	}

	foundAllowed := false
	foundDenied := false
	for _, e := range dryResolves {
		if e.status == "allowed" && e.path == "test/dryaudit" {
			foundAllowed = true
		}
		if e.status == "denied" && e.reason == "not_found" && e.path == "test/missing" {
			foundDenied = true
		}
	}
	if !foundAllowed {
		t.Error("missing dry-resolve allowed audit entry for test/dryaudit")
	}
	if !foundDenied {
		t.Error("missing dry-resolve denied audit entry for test/missing")
	}
}

// --- Attestation policy tests ---

func TestAttestationDenyBearerOnGet(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Seed a secret
	body, _ := json.Marshal(setSecretRequest{Value: "secret-value"})
	req := httptest.NewRequest("PUT", "/v1/secrets/secure/key", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("setup: expected 200, got %d", w.Code)
	}

	// Configure policy: secure/* denies bearer
	p, err := policy.Load([]byte(`{
		"attestation": {
			"secure/*": {
				"deny_bearer": true,
				"require_mtls": true
			}
		}
	}`))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	srv.SetPolicy(p)

	// Try to GET with bearer — should be denied
	req = httptest.NewRequest("GET", "/v1/secrets/secure/key", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("expected 403 for bearer-denied policy, got %d: %s", w.Code, w.Body.String())
	}

	var errResp map[string]string
	json.NewDecoder(w.Body).Decode(&errResp)
	if !strings.Contains(errResp["error"], "attestation") {
		t.Fatalf("expected attestation error, got: %s", errResp["error"])
	}
}

func TestAttestationSourceIPOnResolve(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Seed a secret
	body, _ := json.Marshal(setSecretRequest{Value: "ip-bound"})
	req := httptest.NewRequest("PUT", "/v1/secrets/infra/db-pass", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Configure policy: infra/* requires specific source IP
	p, _ := policy.Load([]byte(`{
		"attestation": {
			"infra/*": {
				"source_ip": ["10.0.0.5"]
			}
		}
	}`))
	srv.SetPolicy(p)

	// Resolve from default test IP (127.0.0.1) — should fail attestation
	body, _ = json.Marshal(map[string]interface{}{
		"refs": []string{"phoenix://infra/db-pass"},
	})
	req = httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.RemoteAddr = "192.168.0.50:12345"
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	errors, _ := resp["errors"].(map[string]interface{})
	if errors["phoenix://infra/db-pass"] != "attestation required" {
		t.Fatalf("expected attestation required error, got: %v", resp)
	}

	// Resolve from allowed IP — should succeed
	body, _ = json.Marshal(map[string]interface{}{
		"refs": []string{"phoenix://infra/db-pass"},
	})
	req = httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.RemoteAddr = "10.0.0.5:12345"
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	resp = map[string]interface{}{}
	json.NewDecoder(w.Body).Decode(&resp)
	values := resp["values"].(map[string]interface{})
	if values["phoenix://infra/db-pass"] != "ip-bound" {
		t.Fatalf("expected 'ip-bound', got: %v", values)
	}
}

func TestAttestationNoPolicyAllowsAll(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// No policy configured — any request should pass attestation
	body, _ := json.Marshal(setSecretRequest{Value: "open"})
	req := httptest.NewRequest("PUT", "/v1/secrets/test/open", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	req = httptest.NewRequest("GET", "/v1/secrets/test/open", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("no policy should allow: expected 200, got %d", w.Code)
	}
}

func TestAttestationUnmatchedPathPasses(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Policy only covers secure/* — other paths unaffected
	p, _ := policy.Load([]byte(`{
		"attestation": {
			"secure/*": {
				"deny_bearer": true
			}
		}
	}`))
	srv.SetPolicy(p)

	body, _ := json.Marshal(setSecretRequest{Value: "unprotected"})
	req := httptest.NewRequest("PUT", "/v1/secrets/test/free", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	req = httptest.NewRequest("GET", "/v1/secrets/test/free", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("unmatched path should allow: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAttestationAuditsDenial(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Seed a secret
	body, _ := json.Marshal(setSecretRequest{Value: "guarded"})
	req := httptest.NewRequest("PUT", "/v1/secrets/locked/key", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Configure policy that will deny
	p, _ := policy.Load([]byte(`{
		"attestation": {
			"locked/*": {
				"source_ip": ["10.10.10.10"]
			}
		}
	}`))
	srv.SetPolicy(p)

	// Resolve from wrong IP
	body, _ = json.Marshal(map[string]interface{}{
		"refs": []string{"phoenix://locked/key"},
	})
	req = httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.RemoteAddr = "192.168.0.1:9999"
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Query audit log for the attestation denial
	req = httptest.NewRequest("GET", "/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var auditResp struct {
		Entries []struct {
			Action string `json:"action"`
			Path   string `json:"path"`
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"entries"`
	}
	json.NewDecoder(w.Body).Decode(&auditResp)

	found := false
	for _, e := range auditResp.Entries {
		if e.Action == "resolve" && e.Path == "locked/key" && e.Status == "denied" && e.Reason == "attestation" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected audit entry with reason=attestation for locked/key, got: %+v", auditResp.Entries)
	}
}

func TestAttestationListModeHidesProtectedPaths(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Seed secrets in two namespaces
	for _, s := range []struct{ path, value string }{
		{"open/key1", "v1"},
		{"locked/key2", "v2"},
	} {
		body, _ := json.Marshal(setSecretRequest{Value: s.value})
		req := httptest.NewRequest("PUT", "/v1/secrets/"+s.path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("setup SET %s: expected 200, got %d", s.path, w.Code)
		}
	}

	// Configure policy: locked/* requires specific IP (bearer caller won't match)
	p, _ := policy.Load([]byte(`{
		"attestation": {
			"locked/*": {
				"source_ip": ["10.10.10.10"]
			}
		}
	}`))
	srv.SetPolicy(p)

	// List all secrets as admin (bearer, from default IP)
	req := httptest.NewRequest("GET", "/v1/secrets/", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.RemoteAddr = "192.168.0.1:9999"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("list: expected 200, got %d", w.Code)
	}

	var resp struct {
		Paths []string `json:"paths"`
	}
	json.NewDecoder(w.Body).Decode(&resp)

	// open/key1 should be visible, locked/key2 should be hidden by attestation
	for _, p := range resp.Paths {
		if strings.HasPrefix(p, "locked/") {
			t.Fatalf("locked/ paths should be hidden by attestation, but found %q in list: %v", p, resp.Paths)
		}
	}
	foundOpen := false
	for _, p := range resp.Paths {
		if p == "open/key1" {
			foundOpen = true
		}
	}
	if !foundOpen {
		t.Fatalf("expected open/key1 in list, got: %v", resp.Paths)
	}
}

func TestAttestationEnforcedOnWrite(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Configure policy: attested/* requires specific source IP
	p, _ := policy.Load([]byte(`{
		"attestation": {
			"attested/*": {
				"source_ip": ["10.0.0.5"]
			}
		}
	}`))
	srv.SetPolicy(p)

	// Try to write from wrong IP — should be denied by attestation
	body, _ := json.Marshal(setSecretRequest{Value: "should-fail"})
	req := httptest.NewRequest("PUT", "/v1/secrets/attested/key", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.RemoteAddr = "192.168.0.50:12345"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("expected 403 for write from wrong IP, got %d: %s", w.Code, w.Body.String())
	}
	var errResp map[string]string
	json.NewDecoder(w.Body).Decode(&errResp)
	if !strings.Contains(errResp["error"], "attestation") {
		t.Fatalf("expected attestation error on write, got: %s", errResp["error"])
	}

	// Write from allowed IP — should succeed
	body, _ = json.Marshal(setSecretRequest{Value: "should-pass"})
	req = httptest.NewRequest("PUT", "/v1/secrets/attested/key", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.RemoteAddr = "10.0.0.5:12345"
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200 for write from allowed IP, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAttestationEnforcedOnDelete(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Seed a secret before policy is set
	body, _ := json.Marshal(setSecretRequest{Value: "delete-me"})
	req := httptest.NewRequest("PUT", "/v1/secrets/attested/delkey", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Configure policy: attested/* requires specific source IP
	p, _ := policy.Load([]byte(`{
		"attestation": {
			"attested/*": {
				"source_ip": ["10.0.0.5"]
			}
		}
	}`))
	srv.SetPolicy(p)

	// Try to delete from wrong IP — should be denied by attestation
	req = httptest.NewRequest("DELETE", "/v1/secrets/attested/delkey", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.RemoteAddr = "192.168.0.50:12345"
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("expected 403 for delete from wrong IP, got %d: %s", w.Code, w.Body.String())
	}
	var errResp map[string]string
	json.NewDecoder(w.Body).Decode(&errResp)
	if !strings.Contains(errResp["error"], "attestation") {
		t.Fatalf("expected attestation error on delete, got: %s", errResp["error"])
	}

	// Delete from allowed IP — should succeed
	req = httptest.NewRequest("DELETE", "/v1/secrets/attested/delkey", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.RemoteAddr = "10.0.0.5:12345"
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200 for delete from allowed IP, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Wave 2: Challenge endpoint tests ---

func TestChallengeEndpointNotEnabled(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Nonce store not configured — should return 501
	body, _ := json.Marshal(map[string]string{})
	req := httptest.NewRequest("POST", "/v1/challenge", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 501 {
		t.Fatalf("expected 501 when nonces not enabled, got %d: %s", w.Code, w.Body.String())
	}
}

func TestChallengeEndpoint(t *testing.T) {
	srv, adminToken := setupTestServer(t)
	ns := nonce.NewStore(30 * time.Second)
	defer ns.Stop()
	srv.SetNonceStore(ns)

	req := httptest.NewRequest("POST", "/v1/challenge", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["nonce"] == nil || resp["nonce"] == "" {
		t.Fatal("expected nonce in response")
	}
	if resp["expires"] == nil || resp["expires"] == "" {
		t.Fatal("expected expires in response")
	}

	// Validate the nonce is usable
	nonceVal := resp["nonce"].(string)
	if err := ns.Validate(nonceVal); err != nil {
		t.Fatalf("nonce should be valid: %v", err)
	}

	// Second validation should fail (single-use)
	if err := ns.Validate(nonceVal); err == nil {
		t.Fatal("nonce should be single-use")
	}
}

func TestChallengeRequiresAuth(t *testing.T) {
	srv, _ := setupTestServer(t)
	ns := nonce.NewStore(30 * time.Second)
	defer ns.Stop()
	srv.SetNonceStore(ns)

	req := httptest.NewRequest("POST", "/v1/challenge", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401 for unauthenticated challenge, got %d", w.Code)
	}
}

// --- Wave 2: Revoke cert endpoint tests ---

func TestRevokeCertEndpoint(t *testing.T) {
	srv, authority, _ := setupTestServerWithCA(t)

	// Issue a cert for "target-agent"
	bundle, err := authority.IssueAgentCert("target-agent")
	if err != nil {
		t.Fatalf("IssueAgentCert: %v", err)
	}

	// Get the serial number
	block, _ := pem.Decode(bundle.CertPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	serialStr := cert.SerialNumber.String()

	// Issue admin cert for authentication
	adminBundle, _ := authority.IssueAgentCert("admin")

	// Revoke via API
	body, _ := json.Marshal(revokeCertRequest{
		SerialNumber: serialStr,
		AgentName:    "target-agent",
	})
	req := makeMTLSRequest("POST", "/v1/certs/revoke", body, adminBundle.CertPEM)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("revoke: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Fatalf("status = %q, want ok", resp["status"])
	}
	if resp["serial_number"] != serialStr {
		t.Fatalf("serial = %q, want %q", resp["serial_number"], serialStr)
	}

	// Verify the cert is now revoked
	if !authority.IsRevoked(cert.SerialNumber) {
		t.Fatal("cert should be revoked")
	}
}

func TestRevokeCertWithoutCA(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	body, _ := json.Marshal(revokeCertRequest{
		SerialNumber: "12345",
		AgentName:    "test",
	})
	req := httptest.NewRequest("POST", "/v1/certs/revoke", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 501 {
		t.Fatalf("expected 501 without CA, got %d", w.Code)
	}
}

func TestRevokeCertRequiresAdmin(t *testing.T) {
	srv, authority, _ := setupTestServerWithCA(t)

	readerBundle, _ := authority.IssueAgentCert("reader")

	body, _ := json.Marshal(revokeCertRequest{
		SerialNumber: "12345",
		AgentName:    "test",
	})
	req := makeMTLSRequest("POST", "/v1/certs/revoke", body, readerBundle.CertPEM)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("expected 403 for non-admin, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRevokeCertInvalidSerial(t *testing.T) {
	srv, authority, _ := setupTestServerWithCA(t)

	adminBundle, _ := authority.IssueAgentCert("admin")

	body, _ := json.Marshal(revokeCertRequest{
		SerialNumber: "not-a-number",
		AgentName:    "test",
	})
	req := makeMTLSRequest("POST", "/v1/certs/revoke", body, adminBundle.CertPEM)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400 for invalid serial, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRevokeCertMissingSerial(t *testing.T) {
	srv, adminToken := setupTestServer(t)
	authority, _ := ca.GenerateCA("Test")
	srv.SetCA(authority)

	body, _ := json.Marshal(revokeCertRequest{
		AgentName: "test",
	})
	req := httptest.NewRequest("POST", "/v1/certs/revoke", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400 for missing serial, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Wave 2: Status endpoint tests ---

func TestStatusEndpoint(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Seed some secrets
	for _, path := range []string{"test/a", "test/b", "other/c"} {
		body, _ := json.Marshal(setSecretRequest{Value: "v"})
		req := httptest.NewRequest("PUT", "/v1/secrets/"+path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
	}

	// Set a policy
	p, _ := policy.Load([]byte(`{
		"attestation": {
			"test/*": { "require_mtls": true },
			"prod/*": { "require_mtls": true, "source_ip": ["10.0.0.1"], "allowed_tools": ["api-call"] }
		}
	}`))
	srv.SetPolicy(p)

	req := httptest.NewRequest("GET", "/v1/status", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["status"] != "ok" {
		t.Fatalf("status = %v", resp["status"])
	}
	if resp["secrets"].(float64) != 3 {
		t.Fatalf("secrets = %v, want 3", resp["secrets"])
	}
	if resp["uptime"] == nil || resp["uptime"] == "" {
		t.Fatal("expected uptime in response")
	}
	if resp["policy_rules"].(float64) != 2 {
		t.Fatalf("policy_rules = %v, want 2", resp["policy_rules"])
	}
}

func TestStatusRequiresAdmin(t *testing.T) {
	srv, _ := setupTestServer(t)

	req := httptest.NewRequest("GET", "/v1/status", nil)
	req.Header.Set("Authorization", "Bearer reader-token")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("expected 403 for non-admin, got %d", w.Code)
	}
}

func TestStatusRequiresAuth(t *testing.T) {
	srv, _ := setupTestServer(t)

	req := httptest.NewRequest("GET", "/v1/status", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// --- Wave 2: Mint token endpoint tests ---

func TestMintTokenEndpointNotEnabled(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	body, _ := json.Marshal(mintTokenRequest{Agent: "test"})
	req := httptest.NewRequest("POST", "/v1/token/mint", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 501 {
		t.Fatalf("expected 501 when tokens not enabled, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMintTokenEndpoint(t *testing.T) {
	srv, adminToken := setupTestServer(t)
	ti, _ := token.NewIssuer(5 * time.Minute)
	srv.SetTokenIssuer(ti)

	body, _ := json.Marshal(mintTokenRequest{Agent: "worker"})
	req := httptest.NewRequest("POST", "/v1/token/mint", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["token"] == nil || resp["token"] == "" {
		t.Fatal("expected token in response")
	}
	if resp["agent"] != "worker" {
		t.Fatalf("agent = %v, want worker", resp["agent"])
	}
	if resp["issued_at"] == nil {
		t.Fatal("expected issued_at")
	}
	if resp["expires_at"] == nil {
		t.Fatal("expected expires_at")
	}
	if resp["ttl"] != "5m0s" {
		t.Fatalf("ttl = %v, want 5m0s", resp["ttl"])
	}

	// Validate the minted token
	tok := resp["token"].(string)
	claims, err := ti.Validate(tok)
	if err != nil {
		t.Fatalf("minted token should be valid: %v", err)
	}
	if claims.Agent != "worker" {
		t.Fatalf("claims.Agent = %q, want worker", claims.Agent)
	}
}

func TestMintTokenRequiresAdmin(t *testing.T) {
	srv, _ := setupTestServer(t)
	ti, _ := token.NewIssuer(5 * time.Minute)
	srv.SetTokenIssuer(ti)

	body, _ := json.Marshal(mintTokenRequest{Agent: "test"})
	req := httptest.NewRequest("POST", "/v1/token/mint", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer reader-token")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("expected 403 for non-admin, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMintTokenMissingAgent(t *testing.T) {
	srv, adminToken := setupTestServer(t)
	ti, _ := token.NewIssuer(5 * time.Minute)
	srv.SetTokenIssuer(ti)

	body, _ := json.Marshal(mintTokenRequest{})
	req := httptest.NewRequest("POST", "/v1/token/mint", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400 for missing agent, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMintTokenWithProcessClaims(t *testing.T) {
	srv, adminToken := setupTestServer(t)
	ti, _ := token.NewIssuer(5 * time.Minute)
	srv.SetTokenIssuer(ti)

	uid := 1001
	body, _ := json.Marshal(mintTokenRequest{
		Agent:      "deployer",
		ProcessUID: &uid,
		BinaryHash: "sha256:DEADBEEF",
	})
	req := httptest.NewRequest("POST", "/v1/token/mint", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	tok := resp["token"].(string)
	claims, err := ti.Validate(tok)
	if err != nil {
		t.Fatalf("token should be valid: %v", err)
	}
	if claims.Agent != "deployer" {
		t.Fatalf("claims.Agent = %q, want deployer", claims.Agent)
	}
	if claims.ProcessUID == nil || *claims.ProcessUID != 1001 {
		t.Fatalf("claims.ProcessUID = %v, want 1001", claims.ProcessUID)
	}
	if claims.BinaryHash != "sha256:DEADBEEF" {
		t.Fatalf("claims.BinaryHash = %q, want sha256:DEADBEEF", claims.BinaryHash)
	}
}

func TestMintTokenWithoutProcessClaims(t *testing.T) {
	srv, adminToken := setupTestServer(t)
	ti, _ := token.NewIssuer(5 * time.Minute)
	srv.SetTokenIssuer(ti)

	body, _ := json.Marshal(mintTokenRequest{Agent: "basic"})
	req := httptest.NewRequest("POST", "/v1/token/mint", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	tok := resp["token"].(string)
	claims, err := ti.Validate(tok)
	if err != nil {
		t.Fatalf("token should be valid: %v", err)
	}
	if claims.ProcessUID != nil {
		t.Fatalf("claims.ProcessUID should be nil, got %v", claims.ProcessUID)
	}
	if claims.BinaryHash != "" {
		t.Fatalf("claims.BinaryHash should be empty, got %q", claims.BinaryHash)
	}
}

// --- Wave 2: Tool-scoped attestation on API ---

func TestAttestationToolScopedOnResolve(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Seed a secret
	body, _ := json.Marshal(setSecretRequest{Value: "tool-scoped"})
	req := httptest.NewRequest("PUT", "/v1/secrets/api/secret", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Configure tool-scoped policy
	p, _ := policy.Load([]byte(`{
		"attestation": {
			"api/*": {
				"allowed_tools": ["phoenix_resolve"]
			}
		}
	}`))
	srv.SetPolicy(p)

	// Resolve without tool context — should fail attestation
	body, _ = json.Marshal(map[string]interface{}{
		"refs": []string{"phoenix://api/secret"},
	})
	req = httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	errors, _ := resp["errors"].(map[string]interface{})
	if errors["phoenix://api/secret"] != "attestation required" {
		t.Fatalf("expected attestation required, got: %v", resp)
	}
}

func TestAttestationToolHeaderOnResolve(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Seed a secret
	body, _ := json.Marshal(setSecretRequest{Value: "tool-bound"})
	req := httptest.NewRequest("PUT", "/v1/secrets/api/tool-key", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Configure tool-scoped policy
	p, _ := policy.Load([]byte(`{
		"attestation": {
			"api/*": {
				"allowed_tools": ["phoenix_resolve"]
			}
		}
	}`))
	srv.SetPolicy(p)

	// Resolve WITH correct tool header — should succeed
	body, _ = json.Marshal(map[string]interface{}{
		"refs": []string{"phoenix://api/tool-key"},
	})
	req = httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("X-Phoenix-Tool", "phoenix_resolve")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	values := resp["values"].(map[string]interface{})
	if values["phoenix://api/tool-key"] != "tool-bound" {
		t.Fatalf("expected tool-bound value, got: %v", resp)
	}

	// Resolve WITH wrong tool header — should fail
	body, _ = json.Marshal(map[string]interface{}{
		"refs": []string{"phoenix://api/tool-key"},
	})
	req = httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("X-Phoenix-Tool", "wrong_tool")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	resp = map[string]interface{}{}
	json.NewDecoder(w.Body).Decode(&resp)
	errors, _ := resp["errors"].(map[string]interface{})
	if errors["phoenix://api/tool-key"] != "attestation required" {
		t.Fatalf("expected attestation required for wrong tool, got: %v", resp)
	}
}

func TestNonceValidationOnResolve(t *testing.T) {
	srv, adminToken := setupTestServer(t)
	ns := nonce.NewStore(30 * time.Second)
	defer ns.Stop()
	srv.SetNonceStore(ns)

	// Seed a secret
	body, _ := json.Marshal(setSecretRequest{Value: "nonce-guarded"})
	req := httptest.NewRequest("PUT", "/v1/secrets/secure/nonce-key", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Configure nonce-required policy
	p, _ := policy.Load([]byte(`{
		"attestation": {
			"secure/*": {
				"require_nonce": true
			}
		}
	}`))
	srv.SetPolicy(p)

	// Resolve WITHOUT nonce — should fail attestation
	body, _ = json.Marshal(map[string]interface{}{
		"refs": []string{"phoenix://secure/nonce-key"},
	})
	req = httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	errors, _ := resp["errors"].(map[string]interface{})
	if errors["phoenix://secure/nonce-key"] != "attestation required" {
		t.Fatalf("expected attestation required without nonce, got: %v", resp)
	}

	// Get a nonce via /v1/challenge
	req = httptest.NewRequest("POST", "/v1/challenge", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	var challengeResp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&challengeResp)
	nonceVal := challengeResp["nonce"].(string)

	// Resolve WITH valid nonce — should succeed
	body, _ = json.Marshal(map[string]interface{}{
		"refs":  []string{"phoenix://secure/nonce-key"},
		"nonce": nonceVal,
	})
	req = httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	resp = map[string]interface{}{}
	json.NewDecoder(w.Body).Decode(&resp)
	values := resp["values"].(map[string]interface{})
	if values["phoenix://secure/nonce-key"] != "nonce-guarded" {
		t.Fatalf("expected nonce-guarded value, got: %v", resp)
	}

	// Replay same nonce — should fail
	body, _ = json.Marshal(map[string]interface{}{
		"refs":  []string{"phoenix://secure/nonce-key"},
		"nonce": nonceVal,
	})
	req = httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("expected 403 for replayed nonce, got %d: %s", w.Code, w.Body.String())
	}
}

func TestShortLivedTokenAuth(t *testing.T) {
	srv, adminToken := setupTestServer(t)
	ti, _ := token.NewIssuer(5 * time.Minute)
	srv.SetTokenIssuer(ti)

	// Seed a secret
	body, _ := json.Marshal(setSecretRequest{Value: "token-accessible"})
	req := httptest.NewRequest("PUT", "/v1/secrets/test/token-key", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Mint a short-lived token for "reader"
	tok, _, err := ti.Mint("reader", nil, "")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// Use the short-lived token to read a secret
	req = httptest.NewRequest("GET", "/v1/secrets/test/token-key", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("short-lived token GET: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var secret store.Secret
	json.NewDecoder(w.Body).Decode(&secret)
	if secret.Value != "token-accessible" {
		t.Fatalf("expected 'token-accessible', got %q", secret.Value)
	}
}

func TestShortLivedTokenFreshAttestationOnResolve(t *testing.T) {
	srv, adminToken := setupTestServer(t)
	ti, _ := token.NewIssuer(5 * time.Minute)
	srv.SetTokenIssuer(ti)

	// Seed a secret
	body, _ := json.Marshal(setSecretRequest{Value: "fresh-only"})
	req := httptest.NewRequest("PUT", "/v1/secrets/critical/key", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Configure fresh attestation policy
	p, _ := policy.Load([]byte(`{
		"attestation": {
			"critical/*": {
				"require_fresh_attestation": true,
				"credential_ttl": "10m"
			}
		}
	}`))
	srv.SetPolicy(p)

	// Mint a token for "admin" and resolve — should succeed (token is fresh)
	tok, _, _ := ti.Mint("admin", nil, "")

	body, _ = json.Marshal(map[string]interface{}{
		"refs": []string{"phoenix://critical/key"},
	})
	req = httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	values := resp["values"].(map[string]interface{})
	if values["phoenix://critical/key"] != "fresh-only" {
		t.Fatalf("expected fresh-only value, got: %v", resp)
	}

	// Resolve with bearer (no TokenIssuedAt) — should fail attestation
	body, _ = json.Marshal(map[string]interface{}{
		"refs": []string{"phoenix://critical/key"},
	})
	req = httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	resp = map[string]interface{}{}
	json.NewDecoder(w.Body).Decode(&resp)
	errors, _ := resp["errors"].(map[string]interface{})
	if errors["phoenix://critical/key"] != "attestation required" {
		t.Fatalf("expected attestation required for bearer without timestamp, got: %v", resp)
	}
}

func TestProcessAttestationViaToken(t *testing.T) {
	srv, adminToken := setupTestServer(t)
	ti, _ := token.NewIssuer(5 * time.Minute)
	srv.SetTokenIssuer(ti)

	// Seed a secret
	body, _ := json.Marshal(setSecretRequest{Value: "process-guarded"})
	req := httptest.NewRequest("PUT", "/v1/secrets/agent/key", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Configure process attestation policy requiring UID 1001
	uid := 1001
	p, _ := policy.Load([]byte(`{
		"attestation": {
			"agent/*": {
				"process": {
					"uid": 1001
				}
			}
		}
	}`))
	srv.SetPolicy(p)

	// Mint token WITH matching process UID — should succeed
	tok, _, _ := ti.Mint("admin", &uid, "")
	body, _ = json.Marshal(map[string]interface{}{
		"refs": []string{"phoenix://agent/key"},
	})
	req = httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	values := resp["values"].(map[string]interface{})
	if values["phoenix://agent/key"] != "process-guarded" {
		t.Fatalf("expected process-guarded, got: %v", resp)
	}

	// Mint token WITH wrong process UID — should fail
	wrongUID := 9999
	tok2, _, _ := ti.Mint("admin", &wrongUID, "")
	body, _ = json.Marshal(map[string]interface{}{
		"refs": []string{"phoenix://agent/key"},
	})
	req = httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok2)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	resp = map[string]interface{}{}
	json.NewDecoder(w.Body).Decode(&resp)
	errors, _ := resp["errors"].(map[string]interface{})
	if errors["phoenix://agent/key"] != "attestation required" {
		t.Fatalf("expected attestation required for wrong UID, got: %v", resp)
	}

	// Mint token WITHOUT process claims — should fail
	tok3, _, _ := ti.Mint("admin", nil, "")
	body, _ = json.Marshal(map[string]interface{}{
		"refs": []string{"phoenix://agent/key"},
	})
	req = httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok3)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	resp = map[string]interface{}{}
	json.NewDecoder(w.Body).Decode(&resp)
	errors, _ = resp["errors"].(map[string]interface{})
	if errors["phoenix://agent/key"] != "attestation required" {
		t.Fatalf("expected attestation required without process claims, got: %v", resp)
	}

	// Bearer token (no process context at all) — should fail
	body, _ = json.Marshal(map[string]interface{}{
		"refs": []string{"phoenix://agent/key"},
	})
	req = httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	resp = map[string]interface{}{}
	json.NewDecoder(w.Body).Decode(&resp)
	errors, _ = resp["errors"].(map[string]interface{})
	if errors["phoenix://agent/key"] != "attestation required" {
		t.Fatalf("expected attestation required for bearer, got: %v", resp)
	}
}

// --- Signed resolve tests ---

// signResolvePayload builds a canonical payload and signs it with the given key.
func signResolvePayload(t *testing.T, key *ecdsa.PrivateKey, nonceVal, timestamp string, refs []string) string {
	t.Helper()
	sorted := make([]string, len(refs))
	copy(sorted, refs)
	sort.Strings(sorted)
	canonical, _ := json.Marshal(map[string]interface{}{
		"nonce":     nonceVal,
		"refs":      sorted,
		"timestamp": timestamp,
	})
	hash := sha256.Sum256(canonical)
	sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func TestSignedResolveValid(t *testing.T) {
	srv, authority, adminToken := setupTestServerWithCA(t)
	ns := nonce.NewStore(30 * time.Second)
	defer ns.Stop()
	srv.SetNonceStore(ns)

	// Seed a secret BEFORE setting policy (writes are now attested too)
	body, _ := json.Marshal(setSecretRequest{Value: "signed-secret"})
	req := httptest.NewRequest("PUT", "/v1/secrets/signed/key", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Configure require_signed policy
	p, _ := policy.Load([]byte(`{
		"attestation": {
			"signed/*": {
				"require_nonce": true,
				"require_signed": true,
				"require_mtls": true
			}
		}
	}`))
	srv.SetPolicy(p)

	// Issue admin cert
	bundle, _ := authority.IssueAgentCert("admin")
	block, _ := pem.Decode(bundle.CertPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	// Parse private key
	keyBlock, _ := pem.Decode(bundle.KeyPEM)
	ecKey, _ := x509.ParseECPrivateKey(keyBlock.Bytes)

	// Get nonce
	entry, _ := ns.Generate()
	nonceVal := entry.Nonce
	timestamp := time.Now().UTC().Format(time.RFC3339)

	refs := []string{"phoenix://signed/key"}
	sig := signResolvePayload(t, ecKey, nonceVal, timestamp, refs)

	body, _ = json.Marshal(map[string]interface{}{
		"refs":      refs,
		"nonce":     nonceVal,
		"timestamp": timestamp,
		"signature": sig,
	})
	req = httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	values := resp["values"].(map[string]interface{})
	if values["phoenix://signed/key"] != "signed-secret" {
		t.Fatalf("expected signed-secret, got: %v", resp)
	}
}

func TestSignedResolveInvalidSignature(t *testing.T) {
	srv, authority, adminToken := setupTestServerWithCA(t)
	ns := nonce.NewStore(30 * time.Second)
	defer ns.Stop()
	srv.SetNonceStore(ns)

	// Seed secret
	body, _ := json.Marshal(setSecretRequest{Value: "val"})
	req := httptest.NewRequest("PUT", "/v1/secrets/signed/key2", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	bundle, _ := authority.IssueAgentCert("admin")
	block, _ := pem.Decode(bundle.CertPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	entry, _ := ns.Generate()
	timestamp := time.Now().UTC().Format(time.RFC3339)

	// Send a garbage signature
	body, _ = json.Marshal(map[string]interface{}{
		"refs":      []string{"phoenix://signed/key2"},
		"nonce":     entry.Nonce,
		"timestamp": timestamp,
		"signature": base64.StdEncoding.EncodeToString([]byte("bad-sig")),
	})
	req = httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("expected 403 for bad signature, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSignedResolveStaleTimestamp(t *testing.T) {
	srv, authority, adminToken := setupTestServerWithCA(t)
	ns := nonce.NewStore(30 * time.Second)
	defer ns.Stop()
	srv.SetNonceStore(ns)

	body, _ := json.Marshal(setSecretRequest{Value: "val"})
	req := httptest.NewRequest("PUT", "/v1/secrets/signed/key3", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	bundle, _ := authority.IssueAgentCert("admin")
	block, _ := pem.Decode(bundle.CertPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	keyBlock, _ := pem.Decode(bundle.KeyPEM)
	ecKey, _ := x509.ParseECPrivateKey(keyBlock.Bytes)

	entry, _ := ns.Generate()
	// Timestamp 5 minutes in the past — outside 60s skew window
	staleTS := time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339)

	refs := []string{"phoenix://signed/key3"}
	sig := signResolvePayload(t, ecKey, entry.Nonce, staleTS, refs)

	body, _ = json.Marshal(map[string]interface{}{
		"refs":      refs,
		"nonce":     entry.Nonce,
		"timestamp": staleTS,
		"signature": sig,
	})
	req = httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("expected 403 for stale timestamp, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSignedResolveReplayFails(t *testing.T) {
	srv, authority, adminToken := setupTestServerWithCA(t)
	ns := nonce.NewStore(30 * time.Second)
	defer ns.Stop()
	srv.SetNonceStore(ns)

	body, _ := json.Marshal(setSecretRequest{Value: "replay-val"})
	req := httptest.NewRequest("PUT", "/v1/secrets/signed/replay", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	bundle, _ := authority.IssueAgentCert("admin")
	block, _ := pem.Decode(bundle.CertPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	keyBlock, _ := pem.Decode(bundle.KeyPEM)
	ecKey, _ := x509.ParseECPrivateKey(keyBlock.Bytes)

	entry, _ := ns.Generate()
	timestamp := time.Now().UTC().Format(time.RFC3339)
	refs := []string{"phoenix://signed/replay"}
	sig := signResolvePayload(t, ecKey, entry.Nonce, timestamp, refs)

	makeBody := func() []byte {
		b, _ := json.Marshal(map[string]interface{}{
			"refs":      refs,
			"nonce":     entry.Nonce,
			"timestamp": timestamp,
			"signature": sig,
		})
		return b
	}

	// First request should fail because nonce was already consumed by Generate+Validate
	// Let's generate a fresh nonce and use it properly
	entry2, _ := ns.Generate()
	sig2 := signResolvePayload(t, ecKey, entry2.Nonce, timestamp, refs)
	body2, _ := json.Marshal(map[string]interface{}{
		"refs":      refs,
		"nonce":     entry2.Nonce,
		"timestamp": timestamp,
		"signature": sig2,
	})

	// First request succeeds (nonce is consumed)
	_ = makeBody // suppress unused
	p, _ := policy.Load([]byte(`{
		"attestation": {
			"signed/*": {
				"require_nonce": true,
				"require_signed": true,
				"require_mtls": true
			}
		}
	}`))
	srv.SetPolicy(p)

	req = httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body2))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("first signed resolve expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Replay same request — nonce already consumed
	req = httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body2))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("replay expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestNonceOnlyBackwardCompat(t *testing.T) {
	// Existing nonce-only flow must still work when require_signed is NOT set
	srv, adminToken := setupTestServer(t)
	ns := nonce.NewStore(30 * time.Second)
	defer ns.Stop()
	srv.SetNonceStore(ns)

	// Seed a secret BEFORE setting policy (writes are now attested too)
	body, _ := json.Marshal(setSecretRequest{Value: "compat-val"})
	req := httptest.NewRequest("PUT", "/v1/secrets/compat/key", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Configure require_nonce WITHOUT require_signed
	p, _ := policy.Load([]byte(`{
		"attestation": {
			"compat/*": {
				"require_nonce": true
			}
		}
	}`))
	srv.SetPolicy(p)

	// Get a nonce
	entry, _ := ns.Generate()

	// Resolve with nonce but NO signature — should succeed
	body, _ = json.Marshal(map[string]interface{}{
		"refs":  []string{"phoenix://compat/key"},
		"nonce": entry.Nonce,
	})
	req = httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("nonce-only compat: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	values := resp["values"].(map[string]interface{})
	if values["phoenix://compat/key"] != "compat-val" {
		t.Fatalf("expected compat-val, got: %v", resp)
	}
}

func TestSignedResolveWithoutMTLS(t *testing.T) {
	// Signature provided but no mTLS cert — should fail
	srv, adminToken := setupTestServer(t)
	ns := nonce.NewStore(30 * time.Second)
	defer ns.Stop()
	srv.SetNonceStore(ns)

	entry, _ := ns.Generate()
	timestamp := time.Now().UTC().Format(time.RFC3339)

	body, _ := json.Marshal(map[string]interface{}{
		"refs":      []string{"phoenix://test/key"},
		"nonce":     entry.Nonce,
		"timestamp": timestamp,
		"signature": base64.StdEncoding.EncodeToString([]byte("dummy")),
	})
	req := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("expected 403 without mTLS cert, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateAgentInvalidPermissions(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	tests := []struct {
		name  string
		perms []acl.Permission
	}{
		{"empty path", []acl.Permission{{Path: "", Actions: []acl.Action{acl.ActionRead}}}},
		{"no actions", []acl.Permission{{Path: "ns/*", Actions: []acl.Action{}}}},
		{"invalid action", []acl.Permission{{Path: "ns/*", Actions: []acl.Action{"bogus"}}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(createAgentRequest{
				Name:        "badagent",
				Token:       "badtoken",
				Permissions: tt.perms,
			})
			req := httptest.NewRequest("POST", "/v1/agents", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+adminToken)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, req)

			if w.Code != 400 {
				t.Fatalf("expected 400 for %s, got %d: %s", tt.name, w.Code, w.Body.String())
			}
		})
	}
}

func TestCreateAgentValidPermissions(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	body, _ := json.Marshal(createAgentRequest{
		Name:  "goodagent",
		Token: "goodtoken",
		Permissions: []acl.Permission{
			{Path: "ns/*", Actions: []acl.Action{acl.ActionRead, acl.ActionWrite}},
		},
	})
	req := httptest.NewRequest("POST", "/v1/agents", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// setupTestServerWithGranularACL creates a server with agents using the new
// granular list/read_value permissions plus a legacy "read" agent.
func setupTestServerWithGranularACL(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()

	keyPath := filepath.Join(dir, "master.key")
	masterKey, _ := crypto.GenerateAndSaveMasterKey(keyPath)

	s, err := store.New(filepath.Join(dir, "store.json"), masterKey)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	aclConfig := &acl.ACLConfig{
		Agents: map[string]acl.Agent{
			"admin": {
				Name:      "admin",
				TokenHash: crypto.HashToken("admin-token"),
				Permissions: []acl.Permission{
					{Path: "*", Actions: []acl.Action{acl.ActionAdmin}},
				},
			},
			"lister": {
				Name:      "lister",
				TokenHash: crypto.HashToken("lister-token"),
				Permissions: []acl.Permission{
					{Path: "test/*", Actions: []acl.Action{acl.ActionList}},
				},
			},
			"value-reader": {
				Name:      "value-reader",
				TokenHash: crypto.HashToken("value-reader-token"),
				Permissions: []acl.Permission{
					{Path: "test/*", Actions: []acl.Action{acl.ActionReadValue}},
				},
			},
			"legacy-reader": {
				Name:      "legacy-reader",
				TokenHash: crypto.HashToken("legacy-reader-token"),
				Permissions: []acl.Permission{
					{Path: "test/*", Actions: []acl.Action{acl.ActionRead}},
				},
			},
		},
	}
	a := acl.NewFromConfig(aclConfig)

	auditPath := filepath.Join(dir, "audit.log")
	al, _ := audit.NewLogger(auditPath)

	fb := store.NewFileBackend(s)
	srv := NewServer(fb, a, al, auditPath)
	srv.SetMasterKeyPath(keyPath)

	// Seed a test secret
	body, _ := json.Marshal(setSecretRequest{Value: "secret-value"})
	req := httptest.NewRequest("PUT", "/v1/secrets/test/key", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 && w.Code != 201 {
		t.Fatalf("seed secret: expected 200/201, got %d: %s", w.Code, w.Body.String())
	}

	return srv
}

func TestListOnlyAgentCannotReadValue(t *testing.T) {
	srv := setupTestServerWithGranularACL(t)

	// Lister can list secrets
	req := httptest.NewRequest("GET", "/v1/secrets/test/", nil)
	req.Header.Set("Authorization", "Bearer lister-token")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("list: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var listResp struct {
		Paths []string `json:"paths"`
	}
	json.NewDecoder(w.Body).Decode(&listResp)
	if len(listResp.Paths) == 0 {
		t.Fatal("lister should see at least one path")
	}

	// Lister cannot read a secret value
	req2 := httptest.NewRequest("GET", "/v1/secrets/test/key", nil)
	req2.Header.Set("Authorization", "Bearer lister-token")
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, req2)

	if w2.Code != 403 {
		t.Fatalf("read value: expected 403, got %d: %s", w2.Code, w2.Body.String())
	}
	if !strings.Contains(w2.Body.String(), "read_value") {
		t.Fatalf("error should mention read_value, got: %s", w2.Body.String())
	}

	// Lister cannot resolve refs
	resolveBody, _ := json.Marshal(map[string]interface{}{
		"refs": []string{"phoenix://test/key"},
	})
	req3 := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(resolveBody))
	req3.Header.Set("Authorization", "Bearer lister-token")
	w3 := httptest.NewRecorder()
	srv.ServeHTTP(w3, req3)

	if w3.Code != 200 {
		t.Fatalf("resolve: expected 200 (with per-ref errors), got %d: %s", w3.Code, w3.Body.String())
	}
	var resolveResp struct {
		Values map[string]string `json:"values"`
		Errors map[string]string `json:"errors"`
	}
	json.NewDecoder(w3.Body).Decode(&resolveResp)
	if len(resolveResp.Errors) == 0 {
		t.Fatal("resolve should have per-ref errors for lister agent")
	}
	if len(resolveResp.Values) > 0 {
		t.Fatal("resolve should not return values for lister agent")
	}
}

func TestLegacyReadAgentBackcompat(t *testing.T) {
	srv := setupTestServerWithGranularACL(t)

	// Legacy reader can list
	req := httptest.NewRequest("GET", "/v1/secrets/test/", nil)
	req.Header.Set("Authorization", "Bearer legacy-reader-token")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("list: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Legacy reader can read values
	req2 := httptest.NewRequest("GET", "/v1/secrets/test/key", nil)
	req2.Header.Set("Authorization", "Bearer legacy-reader-token")
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, req2)

	if w2.Code != 200 {
		t.Fatalf("read value: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestProxyStub(t *testing.T) {
	srv := setupTestServerWithGranularACL(t)

	req := httptest.NewRequest("POST", "/v1/proxy", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 501 {
		t.Fatalf("proxy: expected 501, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "not yet implemented") {
		t.Fatalf("proxy should say not yet implemented, got: %s", w.Body.String())
	}
}

// --- Sealed Responses Tests (Phase 3) ---

func setupSealedTestServer(t *testing.T) (*Server, string, *crypto.SealKeyPair) {
	t.Helper()
	srv, adminToken := setupTestServer(t)

	// Create a test secret
	body, _ := json.Marshal(setSecretRequest{Value: "sealed-test-value"})
	req := httptest.NewRequest("PUT", "/v1/secrets/test/sealed-secret", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("setup secret: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Generate a seal keypair for the reader agent
	kp, _ := crypto.GenerateSealKeyPair()
	pubEncoded := crypto.EncodeSealKey(&kp.PublicKey)
	srv.acl.SetAgentSealKey("reader", pubEncoded)

	return srv, adminToken, kp
}

func TestGenerateKeyPairSuccess(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	body, _ := json.Marshal(generateKeyPairRequest{AgentName: "reader"})
	req := httptest.NewRequest("POST", "/v1/keypair", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["agent_name"] != "reader" {
		t.Errorf("agent_name = %q, want %q", resp["agent_name"], "reader")
	}
	if resp["seal_public_key"] == "" {
		t.Error("seal_public_key is empty")
	}
	if resp["seal_private_key"] == "" {
		t.Error("seal_private_key is empty")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", w.Header().Get("Cache-Control"), "no-store")
	}

	// Verify the key was actually stored
	stored, _ := srv.acl.GetAgentSealKey("reader")
	if stored != resp["seal_public_key"] {
		t.Error("stored key doesn't match returned key")
	}
}

func TestGenerateKeyPairRotationRequiresForce(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// First generation
	body, _ := json.Marshal(generateKeyPairRequest{AgentName: "reader"})
	req := httptest.NewRequest("POST", "/v1/keypair", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("first gen: expected 200, got %d", w.Code)
	}

	// Second generation without force should fail
	body, _ = json.Marshal(generateKeyPairRequest{AgentName: "reader"})
	req = httptest.NewRequest("POST", "/v1/keypair", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 409 {
		t.Fatalf("second gen without force: expected 409, got %d: %s", w.Code, w.Body.String())
	}

	// With force=true should succeed
	body, _ = json.Marshal(generateKeyPairRequest{AgentName: "reader"})
	req = httptest.NewRequest("POST", "/v1/keypair?force=true", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("gen with force: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGenerateKeyPairNonAdmin(t *testing.T) {
	srv, _ := setupTestServer(t)

	body, _ := json.Marshal(generateKeyPairRequest{AgentName: "reader"})
	req := httptest.NewRequest("POST", "/v1/keypair", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer reader-token")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestGenerateKeyPairAgentNotFound(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	body, _ := json.Marshal(generateKeyPairRequest{AgentName: "nonexistent"})
	req := httptest.NewRequest("POST", "/v1/keypair", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 404 {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGetSealKey(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Generate a keypair first
	body, _ := json.Marshal(generateKeyPairRequest{AgentName: "reader"})
	req := httptest.NewRequest("POST", "/v1/keypair", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var genResp map[string]string
	json.NewDecoder(w.Body).Decode(&genResp)

	// Now get the seal key
	req = httptest.NewRequest("GET", "/v1/agents/reader/seal-key", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["agent_name"] != "reader" {
		t.Errorf("agent_name = %q, want %q", resp["agent_name"], "reader")
	}
	if resp["seal_public_key"] != genResp["seal_public_key"] {
		t.Error("returned public key doesn't match generated key")
	}
	// Must never return private key
	if _, ok := resp["seal_private_key"]; ok {
		t.Error("seal_private_key must not be returned by GET seal-key")
	}
}

func TestSealedGetResponse(t *testing.T) {
	srv, _, kp := setupSealedTestServer(t)

	req := httptest.NewRequest("GET", "/v1/secrets/test/sealed-secret", nil)
	req.Header.Set("Authorization", "Bearer reader-token")
	req.Header.Set("X-Phoenix-Seal-Key", crypto.EncodeSealKey(&kp.PublicKey))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	// Should have sealed_value, not value
	if _, ok := resp["sealed_value"]; !ok {
		t.Fatal("expected sealed_value in response")
	}
	if _, ok := resp["value"]; ok {
		t.Fatal("value should not be present in sealed response")
	}
	if resp["path"] != "test/sealed-secret" {
		t.Errorf("path = %v, want %q", resp["path"], "test/sealed-secret")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", w.Header().Get("Cache-Control"), "no-store")
	}

	// Verify we can decrypt the sealed value
	envJSON, _ := json.Marshal(resp["sealed_value"])
	var env crypto.SealedEnvelope
	json.Unmarshal(envJSON, &env)

	payload, err := crypto.OpenSealedEnvelope(&env, &kp.PrivateKey)
	if err != nil {
		t.Fatalf("OpenSealedEnvelope: %v", err)
	}
	if payload.Value != "sealed-test-value" {
		t.Errorf("decrypted value = %q, want %q", payload.Value, "sealed-test-value")
	}
}

func TestSealedGetResponseLogsSealedSuccess(t *testing.T) {
	srv, adminToken, kp := setupSealedTestServer(t)

	req := httptest.NewRequest("GET", "/v1/secrets/test/sealed-secret", nil)
	req.Header.Set("Authorization", "Bearer reader-token")
	req.Header.Set("X-Phoenix-Seal-Key", crypto.EncodeSealKey(&kp.PublicKey))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest("GET", "/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("audit query: expected 200, got %d", w.Code)
	}

	var auditResp struct {
		Entries []struct {
			Action string `json:"action"`
			Path   string `json:"path"`
			Status string `json:"status"`
			Sealed bool   `json:"sealed"`
		} `json:"entries"`
	}
	json.NewDecoder(w.Body).Decode(&auditResp)

	var found bool
	for _, e := range auditResp.Entries {
		if e.Action == "read_value" && e.Path == "test/sealed-secret" && e.Status == "allowed" {
			found = true
			if !e.Sealed {
				t.Fatalf("read_value allowed entry should have sealed=true: %+v", e)
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected allowed sealed read_value audit entry for test/sealed-secret; entries: %+v", auditResp.Entries)
	}
}

func TestGetResponseWithoutSealLogsUnsealedSuccess(t *testing.T) {
	srv, adminToken, _ := setupSealedTestServer(t)

	req := httptest.NewRequest("GET", "/v1/secrets/test/sealed-secret", nil)
	req.Header.Set("Authorization", "Bearer reader-token")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest("GET", "/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("audit query: expected 200, got %d", w.Code)
	}

	var auditResp struct {
		Entries []struct {
			Action string `json:"action"`
			Path   string `json:"path"`
			Status string `json:"status"`
			Sealed bool   `json:"sealed"`
		} `json:"entries"`
	}
	json.NewDecoder(w.Body).Decode(&auditResp)

	var found bool
	for _, e := range auditResp.Entries {
		if e.Action == "read_value" && e.Path == "test/sealed-secret" && e.Status == "allowed" {
			found = true
			if e.Sealed {
				t.Fatalf("read_value allowed entry should have sealed=false: %+v", e)
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected allowed unsealed read_value audit entry for test/sealed-secret; entries: %+v", auditResp.Entries)
	}
}

func TestSealedResolveResponse(t *testing.T) {
	srv, _, kp := setupSealedTestServer(t)

	body, _ := json.Marshal(resolveRequest{
		Refs: []string{"phoenix://test/sealed-secret"},
	})
	req := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer reader-token")
	req.Header.Set("X-Phoenix-Seal-Key", crypto.EncodeSealKey(&kp.PublicKey))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	// Should have sealed_values, not values
	if _, ok := resp["sealed_values"]; !ok {
		t.Fatal("expected sealed_values in response")
	}
	if _, ok := resp["values"]; ok {
		t.Fatal("values should not be present in sealed response")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", w.Header().Get("Cache-Control"), "no-store")
	}

	// Verify we can decrypt
	sealedMap := resp["sealed_values"].(map[string]interface{})
	envJSON, _ := json.Marshal(sealedMap["phoenix://test/sealed-secret"])
	var env crypto.SealedEnvelope
	json.Unmarshal(envJSON, &env)

	payload, err := crypto.OpenSealedEnvelope(&env, &kp.PrivateKey)
	if err != nil {
		t.Fatalf("OpenSealedEnvelope: %v", err)
	}
	if payload.Value != "sealed-test-value" {
		t.Errorf("decrypted value = %q, want %q", payload.Value, "sealed-test-value")
	}
	if payload.Ref != "phoenix://test/sealed-secret" {
		t.Errorf("ref = %q, want %q", payload.Ref, "phoenix://test/sealed-secret")
	}
}

func TestSealedResolveResponseLogsSealedSuccess(t *testing.T) {
	srv, adminToken, kp := setupSealedTestServer(t)

	body, _ := json.Marshal(resolveRequest{
		Refs: []string{"phoenix://test/sealed-secret"},
	})
	req := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer reader-token")
	req.Header.Set("X-Phoenix-Seal-Key", crypto.EncodeSealKey(&kp.PublicKey))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest("GET", "/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("audit query: expected 200, got %d", w.Code)
	}

	var auditResp struct {
		Entries []struct {
			Action string `json:"action"`
			Path   string `json:"path"`
			Status string `json:"status"`
			Sealed bool   `json:"sealed"`
		} `json:"entries"`
	}
	json.NewDecoder(w.Body).Decode(&auditResp)

	var found bool
	for _, e := range auditResp.Entries {
		if e.Action == "resolve" && e.Path == "test/sealed-secret" && e.Status == "allowed" {
			found = true
			if !e.Sealed {
				t.Fatalf("resolve allowed entry should have sealed=true: %+v", e)
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected allowed sealed resolve audit entry for test/sealed-secret; entries: %+v", auditResp.Entries)
	}
}

func TestResolveResponseWithoutSealLogsUnsealedSuccess(t *testing.T) {
	srv, adminToken, _ := setupSealedTestServer(t)

	body, _ := json.Marshal(resolveRequest{
		Refs: []string{"phoenix://test/sealed-secret"},
	})
	req := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer reader-token")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest("GET", "/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("audit query: expected 200, got %d", w.Code)
	}

	var auditResp struct {
		Entries []struct {
			Action string `json:"action"`
			Path   string `json:"path"`
			Status string `json:"status"`
			Sealed bool   `json:"sealed"`
		} `json:"entries"`
	}
	json.NewDecoder(w.Body).Decode(&auditResp)

	var found bool
	for _, e := range auditResp.Entries {
		if e.Action == "resolve" && e.Path == "test/sealed-secret" && e.Status == "allowed" {
			found = true
			if e.Sealed {
				t.Fatalf("resolve allowed entry should have sealed=false: %+v", e)
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected allowed unsealed resolve audit entry for test/sealed-secret; entries: %+v", auditResp.Entries)
	}
}

func TestPlaintextFallbackWithoutSealHeader(t *testing.T) {
	srv, _, _ := setupSealedTestServer(t)

	// GET without seal header should return plaintext
	req := httptest.NewRequest("GET", "/v1/secrets/test/sealed-secret", nil)
	req.Header.Set("Authorization", "Bearer reader-token")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	if _, ok := resp["sealed_value"]; ok {
		t.Fatal("sealed_value should not be present without seal header")
	}
	if resp["value"] != "sealed-test-value" {
		t.Errorf("value = %v, want %q", resp["value"], "sealed-test-value")
	}
}

func TestMalformedSealHeaderRejected(t *testing.T) {
	srv, _, _ := setupSealedTestServer(t)

	req := httptest.NewRequest("GET", "/v1/secrets/test/sealed-secret", nil)
	req.Header.Set("Authorization", "Bearer reader-token")
	req.Header.Set("X-Phoenix-Seal-Key", "not-valid-base64!!!")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMismatchedSealKeyRejected(t *testing.T) {
	srv, _, _ := setupSealedTestServer(t)

	// Generate a different key pair
	otherKP, _ := crypto.GenerateSealKeyPair()

	req := httptest.NewRequest("GET", "/v1/secrets/test/sealed-secret", nil)
	req.Header.Set("Authorization", "Bearer reader-token")
	req.Header.Set("X-Phoenix-Seal-Key", crypto.EncodeSealKey(&otherKP.PublicKey))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "does not match") {
		t.Errorf("expected 'does not match' error, got: %s", w.Body.String())
	}
}

func TestUnregisteredAgentSealKeyRejected(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Set a secret that admin can read
	body, _ := json.Marshal(setSecretRequest{Value: "test-val"})
	req := httptest.NewRequest("PUT", "/v1/secrets/test/s", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// reader has no seal key registered — presenting one should fail
	kp, _ := crypto.GenerateSealKeyPair()
	req = httptest.NewRequest("GET", "/v1/secrets/test/s", nil)
	req.Header.Set("Authorization", "Bearer reader-token")
	req.Header.Set("X-Phoenix-Seal-Key", crypto.EncodeSealKey(&kp.PublicKey))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "no registered seal key") {
		t.Errorf("expected 'no registered seal key' error, got: %s", w.Body.String())
	}
}

func TestRequireSealedPolicyDeniesWithoutKey(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	// Set a secret
	body, _ := json.Marshal(setSecretRequest{Value: "policy-test"})
	req := httptest.NewRequest("PUT", "/v1/secrets/test/sealed-pol", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Set require_sealed policy
	policyJSON := `{"attestation":{"test/*":{"require_sealed":true}}}`
	e, _ := policy.Load([]byte(policyJSON))
	srv.SetPolicy(e)

	// Reader without seal key should be denied
	req = httptest.NewRequest("GET", "/v1/secrets/test/sealed-pol", nil)
	req.Header.Set("Authorization", "Bearer reader-token")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "sealed response required") {
		t.Errorf("expected 'sealed response required' in error, got: %s", w.Body.String())
	}
}

func TestRequireSealedPolicyAllowsWithKey(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	body, _ := json.Marshal(setSecretRequest{Value: "policy-test"})
	req := httptest.NewRequest("PUT", "/v1/secrets/test/sealed-pol", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Register seal key for reader
	kp, _ := crypto.GenerateSealKeyPair()
	srv.acl.SetAgentSealKey("reader", crypto.EncodeSealKey(&kp.PublicKey))

	// Set require_sealed policy
	policyJSON := `{"attestation":{"test/*":{"require_sealed":true}}}`
	e, _ := policy.Load([]byte(policyJSON))
	srv.SetPolicy(e)

	// Reader with valid seal key should be allowed
	req = httptest.NewRequest("GET", "/v1/secrets/test/sealed-pol", nil)
	req.Header.Set("Authorization", "Bearer reader-token")
	req.Header.Set("X-Phoenix-Seal-Key", crypto.EncodeSealKey(&kp.PublicKey))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDryRunUnchangedWithSealKey(t *testing.T) {
	srv, _, kp := setupSealedTestServer(t)

	body, _ := json.Marshal(resolveRequest{
		Refs: []string{"phoenix://test/sealed-secret"},
	})
	req := httptest.NewRequest("POST", "/v1/resolve?dry_run=true", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer reader-token")
	req.Header.Set("X-Phoenix-Seal-Key", crypto.EncodeSealKey(&kp.PublicKey))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	// dry_run should still return values map with "ok", not sealed_values
	vals, ok := resp["values"].(map[string]interface{})
	if !ok {
		t.Fatal("expected values map in dry_run response")
	}
	if vals["phoenix://test/sealed-secret"] != "ok" {
		t.Errorf("dry_run value = %v, want %q", vals["phoenix://test/sealed-secret"], "ok")
	}
	if _, ok := resp["sealed_values"]; ok {
		t.Fatal("sealed_values should not be present in dry_run response")
	}
}

// --- Policy check endpoint tests ---

func TestPolicyCheckAllowUnseal(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	pe, _ := policy.Load([]byte(`{"rules":[{"path":"test/*","allow_unseal":true}]}`))
	srv.SetPolicy(pe)

	req := httptest.NewRequest("GET", "/v1/policy/check?path=test/secret&check=allow_unseal", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["allowed"] != true {
		t.Fatalf("allowed = %v, want true", resp["allowed"])
	}
}

func TestPolicyCheckDenyUnseal(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	pe, _ := policy.Load([]byte(`{"rules":[{"path":"other/*","allow_unseal":true}]}`))
	srv.SetPolicy(pe)

	req := httptest.NewRequest("GET", "/v1/policy/check?path=test/secret&check=allow_unseal", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["allowed"] != false {
		t.Fatalf("allowed = %v, want false", resp["allowed"])
	}
}

func TestPolicyCheckNoPolicy(t *testing.T) {
	srv, adminToken := setupTestServer(t)
	// No policy set — should return allowed=false

	req := httptest.NewRequest("GET", "/v1/policy/check?path=test/secret&check=allow_unseal", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["allowed"] != false {
		t.Fatalf("allowed = %v, want false (no policy)", resp["allowed"])
	}
}

func TestPolicyCheckRequiresAuth(t *testing.T) {
	srv, _ := setupTestServer(t)

	req := httptest.NewRequest("GET", "/v1/policy/check?path=test/secret&check=allow_unseal", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestPolicyCheckMissingParams(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	req := httptest.NewRequest("GET", "/v1/policy/check?path=test/secret", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestPolicyCheckUnsupportedCheck(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	req := httptest.NewRequest("GET", "/v1/policy/check?path=test/secret&check=bogus", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

// setupTestServerWithSessions creates a test server with session identity enabled.
func setupTestServerWithSessions(t *testing.T) (*Server, string) {
	t.Helper()
	srv, adminToken := setupTestServer(t)

	ss, err := session.NewStore(time.Hour)
	if err != nil {
		t.Fatalf("session store: %v", err)
	}
	t.Cleanup(ss.Stop)
	srv.SetSessionStore(ss)
	srv.SetSessionRoles(map[string]config.RoleConfig{
		"dev": {
			Namespaces:     []string{"test/*"},
			Actions:        []string{"list", "read_value"},
			BootstrapTrust: []string{"bearer"},
		},
		"writer": {
			Namespaces:     []string{"test/*"},
			Actions:        []string{"list", "read_value", "write"},
			BootstrapTrust: []string{"bearer"},
		},
	})
	return srv, adminToken
}

func mintTestSession(t *testing.T, srv *Server, adminToken, role string) string {
	t.Helper()
	body := `{"role":"` + role + `"}`
	req := httptest.NewRequest("POST", "/v1/session/mint", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("session mint: status %d, body: %s", w.Code, w.Body.String())
	}
	var result struct {
		SessionToken string `json:"session_token"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	return result.SessionToken
}

func TestHandleSessionRenew(t *testing.T) {
	srv, adminToken := setupTestServerWithSessions(t)
	sessionToken := mintTestSession(t, srv, adminToken, "dev")

	req := httptest.NewRequest("POST", "/v1/session/renew", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("renew: status %d, body: %s", w.Code, w.Body.String())
	}

	var result struct {
		SessionToken string `json:"session_token"`
		Renewed      bool   `json:"renewed"`
		Role         string `json:"role"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)

	if !result.Renewed {
		t.Error("expected renewed=true")
	}
	if result.Role != "dev" {
		t.Errorf("role = %q, want %q", result.Role, "dev")
	}
	if result.SessionToken == "" {
		t.Error("expected non-empty session_token")
	}
	if result.SessionToken == sessionToken {
		t.Error("expected new token to differ from original")
	}

	// Verify Cache-Control header
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", cc, "no-store")
	}
}

func TestHandleSessionRenewNonSession(t *testing.T) {
	srv, adminToken := setupTestServerWithSessions(t)

	// Try to renew using a bearer token (not a session token)
	req := httptest.NewRequest("POST", "/v1/session/renew", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("status = %d, want 400", w.Code)
	}

	var result struct {
		Code string `json:"code"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.Code != "SESSION_REQUIRED" {
		t.Errorf("code = %q, want SESSION_REQUIRED", result.Code)
	}
}

func TestSessionActionDeniedCode(t *testing.T) {
	srv, adminToken := setupTestServerWithSessions(t)

	// Store a secret
	body := `{"value":"secret123"}`
	req := httptest.NewRequest("PUT", "/v1/secrets/test/mysecret", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("set secret: status %d", w.Code)
	}

	// Mint a read-only session
	sessionToken := mintTestSession(t, srv, adminToken, "dev")

	// Try to write using session (should fail with ACTION_DENIED)
	req = httptest.NewRequest("PUT", "/v1/secrets/test/newsecret", strings.NewReader(`{"value":"nope"}`))
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("status = %d, want 403", w.Code)
	}

	var result struct {
		Code string `json:"code"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.Code != "ACTION_DENIED" {
		t.Errorf("code = %q, want ACTION_DENIED", result.Code)
	}
}

func TestSessionMintCacheControl(t *testing.T) {
	srv, adminToken := setupTestServerWithSessions(t)

	body := `{"role":"dev"}`
	req := httptest.NewRequest("POST", "/v1/session/mint", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", cc, "no-store")
	}
}

func TestSessionMintAttestationEnforced(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	ss, err := session.NewStore(time.Hour)
	if err != nil {
		t.Fatalf("session store: %v", err)
	}
	t.Cleanup(ss.Stop)
	srv.SetSessionStore(ss)
	srv.SetSessionRoles(map[string]config.RoleConfig{
		"secure": {
			Namespaces:     []string{"prod/*"},
			BootstrapTrust: []string{"bearer"},
			Attestation:    []string{"require_mtls"},
		},
	})

	// Try to mint with bearer auth (should fail because role requires mTLS)
	body := `{"role":"secure"}`
	req := httptest.NewRequest("POST", "/v1/session/mint", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("status = %d, want 403, body: %s", w.Code, w.Body.String())
	}

	var result struct {
		Code string `json:"code"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.Code != "ATTESTATION_FAILED" {
		t.Errorf("code = %q, want ATTESTATION_FAILED", result.Code)
	}
}

func TestSessionRenewLocalityRecheck(t *testing.T) {
	// This test verifies that renewal checks the CURRENT request's locality,
	// not the original mint-time source IP.
	srv, adminToken := setupTestServer(t)

	ss, err := session.NewStore(time.Hour)
	if err != nil {
		t.Fatalf("session store: %v", err)
	}
	t.Cleanup(ss.Stop)
	srv.SetSessionStore(ss)
	srv.SetSessionRoles(map[string]config.RoleConfig{
		"local-only": {
			Namespaces:     []string{"dev/*"},
			BootstrapTrust: []string{"local"},
		},
	})

	// Mint a session from loopback (simulated via httptest which uses 192.0.2.1)
	// This will fail because httptest uses non-loopback, showing the local check works
	body := `{"role":"local-only"}`
	req := httptest.NewRequest("POST", "/v1/session/mint", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// httptest uses 192.0.2.1 (non-loopback), so "local" bootstrap should fail
	if w.Code != 403 {
		t.Fatalf("expected 403 for non-local mint with local-only trust, got %d: %s", w.Code, w.Body.String())
	}

	var result struct {
		Code string `json:"code"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.Code != "BOOTSTRAP_FAILED" {
		t.Errorf("code = %q, want BOOTSTRAP_FAILED", result.Code)
	}
}

func TestSessionRenewCertFingerprintContinuity(t *testing.T) {
	srv, authority, _ := setupTestServerWithCA(t)

	ss, err := session.NewStore(time.Hour)
	if err != nil {
		t.Fatalf("session store: %v", err)
	}
	t.Cleanup(ss.Stop)
	srv.SetSessionStore(ss)
	srv.SetSessionRoles(map[string]config.RoleConfig{
		"secure": {
			Namespaces:     []string{"test/*"},
			BootstrapTrust: []string{"mtls"},
			Attestation:    []string{"cert_fingerprint"},
		},
	})

	bundle1, err := authority.IssueAgentCert("admin")
	if err != nil {
		t.Fatalf("issuing cert1: %v", err)
	}
	bundle2, err := authority.IssueAgentCert("reader")
	if err != nil {
		t.Fatalf("issuing cert2: %v", err)
	}

	// Mint with cert1.
	req := makeMTLSRequest("POST", "/v1/session/mint", []byte(`{"role":"secure"}`), bundle1.CertPEM)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("mint: status %d, body: %s", w.Code, w.Body.String())
	}
	var mint struct {
		SessionToken string `json:"session_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &mint); err != nil {
		t.Fatalf("unmarshal mint: %v", err)
	}

	// Renew with a different cert: should fail continuity check.
	req = makeMTLSRequest("POST", "/v1/session/renew", []byte(`{}`), bundle2.CertPEM)
	req.Header.Set("Authorization", "Bearer "+mint.SessionToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("renew with wrong cert: status %d, body: %s", w.Code, w.Body.String())
	}
	var denied struct {
		Code string `json:"code"`
	}
	json.Unmarshal(w.Body.Bytes(), &denied)
	if denied.Code != "ATTESTATION_FAILED" {
		t.Fatalf("code = %q, want ATTESTATION_FAILED", denied.Code)
	}

	// Renew with the original cert: should succeed.
	req = makeMTLSRequest("POST", "/v1/session/renew", []byte(`{}`), bundle1.CertPEM)
	req.Header.Set("Authorization", "Bearer "+mint.SessionToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("renew with original cert: status %d, body: %s", w.Code, w.Body.String())
	}
}

func TestHandleSessionRenewExpired(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	ss, err := session.NewStore(5 * time.Millisecond)
	if err != nil {
		t.Fatalf("session store: %v", err)
	}
	t.Cleanup(ss.Stop)
	srv.SetSessionStore(ss)
	srv.SetSessionRoles(map[string]config.RoleConfig{
		"dev": {
			Namespaces:     []string{"test/*"},
			Actions:        []string{"list", "read_value"},
			BootstrapTrust: []string{"bearer"},
		},
	})

	// Mint with short TTL
	sessionToken := mintTestSession(t, srv, adminToken, "dev")

	// Wait for session to expire
	time.Sleep(10 * time.Millisecond)

	// Try to renew expired session
	req := httptest.NewRequest("POST", "/v1/session/renew", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Should fail with 401 (token expired during auth)
	if w.Code != 401 {
		t.Fatalf("status = %d, want 401, body: %s", w.Code, w.Body.String())
	}
}

// --- Step-up approval tests ---

func setupTestServerWithStepUp(t *testing.T) (*Server, string) {
	t.Helper()
	srv, adminToken := setupTestServer(t)

	ss, err := session.NewStore(time.Hour)
	if err != nil {
		t.Fatalf("session store: %v", err)
	}
	t.Cleanup(ss.Stop)
	srv.SetSessionStore(ss)

	as := approval.NewStore(5 * time.Minute)
	t.Cleanup(as.Stop)
	srv.SetApprovalStore(as)

	srv.SetSessionRoles(map[string]config.RoleConfig{
		"dev": {
			Namespaces:     []string{"test/*"},
			Actions:        []string{"list", "read_value"},
			BootstrapTrust: []string{"bearer"},
		},
		"deploy": {
			Namespaces:     []string{"prod/*"},
			Actions:        []string{"list", "read_value"},
			BootstrapTrust: []string{"bearer"},
			StepUp:         true,
			StepUpTTL:      "2m",
		},
	})
	return srv, adminToken
}

func TestSessionMintStepUp(t *testing.T) {
	srv, adminToken := setupTestServerWithStepUp(t)

	body := `{"role":"deploy"}`
	req := httptest.NewRequest("POST", "/v1/session/mint", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 202 {
		t.Fatalf("status = %d, want 202, body: %s", w.Code, w.Body.String())
	}

	var result struct {
		Status     string `json:"status"`
		ApprovalID string `json:"approval_id"`
		Code       string `json:"code"`
		ApproveCmd string `json:"approve_command"`
		ExpiresAt  string `json:"expires_at"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)

	if result.Status != "approval_required" {
		t.Errorf("status = %q, want approval_required", result.Status)
	}
	if result.Code != "APPROVAL_REQUIRED" {
		t.Errorf("code = %q, want APPROVAL_REQUIRED", result.Code)
	}
	if result.ApprovalID == "" || result.ApprovalID[:4] != "apr_" {
		t.Errorf("approval_id = %q, want apr_ prefix", result.ApprovalID)
	}
	if result.ApproveCmd == "" {
		t.Error("approve_command should not be empty")
	}
	if result.ExpiresAt == "" {
		t.Error("expires_at should not be empty")
	}
}

func TestSessionMintNoStepUp(t *testing.T) {
	srv, adminToken := setupTestServerWithStepUp(t)

	// Non-step-up role should still mint directly
	body := `{"role":"dev"}`
	req := httptest.NewRequest("POST", "/v1/session/mint", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}

	var result struct {
		SessionToken string `json:"session_token"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.SessionToken == "" {
		t.Error("expected session_token for non-step-up role")
	}
}

func TestApprovalApproveFullFlow(t *testing.T) {
	srv, adminToken := setupTestServerWithStepUp(t)

	// 1. Mint → 202 approval_required
	body := `{"role":"deploy"}`
	req := httptest.NewRequest("POST", "/v1/session/mint", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 202 {
		t.Fatalf("mint: status %d, want 202", w.Code)
	}
	var mintResult struct {
		ApprovalID string `json:"approval_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &mintResult)

	// 2. Check status → pending
	req = httptest.NewRequest("GET", "/v1/approval/"+mintResult.ApprovalID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status check: %d, body: %s", w.Code, w.Body.String())
	}
	var statusResult struct {
		Status string `json:"status"`
	}
	json.Unmarshal(w.Body.Bytes(), &statusResult)
	if statusResult.Status != "pending" {
		t.Errorf("status = %q, want pending", statusResult.Status)
	}

	// 3. Approve
	req = httptest.NewRequest("POST", "/v1/approval/"+mintResult.ApprovalID+"/approve", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("approve: status %d, body: %s", w.Code, w.Body.String())
	}
	var approveResult struct {
		Status    string `json:"status"`
		SessionID string `json:"session_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &approveResult)
	if approveResult.Status != "approved" {
		t.Errorf("approve status = %q, want approved", approveResult.Status)
	}
	if approveResult.SessionID == "" {
		t.Error("expected session_id after approval")
	}

	// 4. Poll → approved with token
	req = httptest.NewRequest("GET", "/v1/approval/"+mintResult.ApprovalID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("poll: status %d", w.Code)
	}
	var pollResult struct {
		Status       string `json:"status"`
		SessionToken string `json:"session_token"`
		SessionID    string `json:"session_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &pollResult)
	if pollResult.Status != "approved" {
		t.Errorf("poll status = %q, want approved", pollResult.Status)
	}
	if pollResult.SessionToken == "" {
		t.Error("expected session_token in poll after approval")
	}
	if !strings.HasPrefix(pollResult.SessionToken, "phxs_") {
		t.Errorf("session_token = %q, want phxs_ prefix", pollResult.SessionToken)
	}
}

func TestApprovalDeny(t *testing.T) {
	srv, adminToken := setupTestServerWithStepUp(t)

	// Mint → 202
	body := `{"role":"deploy"}`
	req := httptest.NewRequest("POST", "/v1/session/mint", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var mintResult struct {
		ApprovalID string `json:"approval_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &mintResult)

	// Deny
	req = httptest.NewRequest("POST", "/v1/approval/"+mintResult.ApprovalID+"/deny", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("deny: status %d, body: %s", w.Code, w.Body.String())
	}

	// Poll → denied
	req = httptest.NewRequest("GET", "/v1/approval/"+mintResult.ApprovalID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var pollResult struct {
		Status string `json:"status"`
	}
	json.Unmarshal(w.Body.Bytes(), &pollResult)
	if pollResult.Status != "denied" {
		t.Errorf("status = %q, want denied", pollResult.Status)
	}
}

func TestApprovalExpired(t *testing.T) {
	srv, adminToken := setupTestServer(t)

	ss, err := session.NewStore(time.Hour)
	if err != nil {
		t.Fatalf("session store: %v", err)
	}
	t.Cleanup(ss.Stop)
	srv.SetSessionStore(ss)

	// Use a very short step-up TTL
	as := approval.NewStore(50 * time.Millisecond)
	t.Cleanup(as.Stop)
	srv.SetApprovalStore(as)
	srv.SetSessionRoles(map[string]config.RoleConfig{
		"deploy": {
			Namespaces:     []string{"prod/*"},
			BootstrapTrust: []string{"bearer"},
			StepUp:         true,
			StepUpTTL:      "50ms",
		},
	})

	// Mint → 202
	body := `{"role":"deploy"}`
	req := httptest.NewRequest("POST", "/v1/session/mint", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 202 {
		t.Fatalf("status = %d, want 202", w.Code)
	}
	var mintResult struct {
		ApprovalID string `json:"approval_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &mintResult)

	// Wait for expiry
	time.Sleep(60 * time.Millisecond)

	// Poll → expired
	req = httptest.NewRequest("GET", "/v1/approval/"+mintResult.ApprovalID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var pollResult struct {
		Status string `json:"status"`
	}
	json.Unmarshal(w.Body.Bytes(), &pollResult)
	if pollResult.Status != "expired" {
		t.Errorf("status = %q, want expired", pollResult.Status)
	}
}

func TestApprovalApproveRequiresAdmin(t *testing.T) {
	srv, adminToken := setupTestServerWithStepUp(t)

	// Mint step-up → 202
	body := `{"role":"deploy"}`
	req := httptest.NewRequest("POST", "/v1/session/mint", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var mintResult struct {
		ApprovalID string `json:"approval_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &mintResult)

	// Mint a session token (non-step-up role)
	sessionToken := mintTestSession(t, srv, adminToken, "dev")

	// Try to approve with session token — should be rejected
	req = httptest.NewRequest("POST", "/v1/approval/"+mintResult.ApprovalID+"/approve", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("status = %d, want 403, body: %s", w.Code, w.Body.String())
	}
	var result struct {
		Code string `json:"code"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.Code != "ADMIN_AUTH_REQUIRED" {
		t.Errorf("code = %q, want ADMIN_AUTH_REQUIRED", result.Code)
	}
}

func TestApprovalSameTTYWarning(t *testing.T) {
	srv, adminToken := setupTestServerWithStepUp(t)

	// Mint with requester_tty
	body := `{"role":"deploy","requester_tty":"/dev/pts/0"}`
	req := httptest.NewRequest("POST", "/v1/session/mint", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 202 {
		t.Fatalf("status = %d, want 202", w.Code)
	}
	var mintResult struct {
		ApprovalID string `json:"approval_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &mintResult)

	// Approve with same TTY
	approveBody := `{"approver_tty":"/dev/pts/0"}`
	req = httptest.NewRequest("POST", "/v1/approval/"+mintResult.ApprovalID+"/approve", strings.NewReader(approveBody))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("approve: status %d, body: %s", w.Code, w.Body.String())
	}
	var result struct {
		SameTTYWarning bool `json:"same_tty_warning"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if !result.SameTTYWarning {
		t.Error("expected same_tty_warning=true when TTYs match")
	}
}

func TestApprovalListPending(t *testing.T) {
	srv, adminToken := setupTestServerWithStepUp(t)

	// Create two pending approvals
	for i := 0; i < 2; i++ {
		body := `{"role":"deploy"}`
		req := httptest.NewRequest("POST", "/v1/session/mint", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != 202 {
			t.Fatalf("mint %d: status %d", i, w.Code)
		}
	}

	// List
	req := httptest.NewRequest("GET", "/v1/approvals", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("list: status %d, body: %s", w.Code, w.Body.String())
	}
	var result struct {
		Approvals []struct {
			ID   string `json:"id"`
			Role string `json:"role"`
		} `json:"approvals"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result.Approvals) != 2 {
		t.Errorf("pending count = %d, want 2", len(result.Approvals))
	}
}

// --- Blocker fix tests: ACL admin required, status token gating, stale role re-check ---

func TestApprovalApproveRejectsNonAdmin(t *testing.T) {
	srv, adminToken := setupTestServerWithStepUp(t)

	// Mint step-up → 202
	body := `{"role":"deploy"}`
	req := httptest.NewRequest("POST", "/v1/session/mint", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var mintResult struct {
		ApprovalID string `json:"approval_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &mintResult)

	// Try to approve with reader token (non-admin) — should be rejected
	req = httptest.NewRequest("POST", "/v1/approval/"+mintResult.ApprovalID+"/approve", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer reader-token")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("status = %d, want 403, body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "admin required") {
		t.Errorf("expected 'admin required' in body, got: %s", w.Body.String())
	}
}

func TestApprovalDenyRejectsNonAdmin(t *testing.T) {
	srv, adminToken := setupTestServerWithStepUp(t)

	body := `{"role":"deploy"}`
	req := httptest.NewRequest("POST", "/v1/session/mint", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var mintResult struct {
		ApprovalID string `json:"approval_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &mintResult)

	// Reader tries to deny
	req = httptest.NewRequest("POST", "/v1/approval/"+mintResult.ApprovalID+"/deny", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer reader-token")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("status = %d, want 403, body: %s", w.Code, w.Body.String())
	}
}

func TestApprovalListRejectsNonAdmin(t *testing.T) {
	srv, _ := setupTestServerWithStepUp(t)

	req := httptest.NewRequest("GET", "/v1/approvals", nil)
	req.Header.Set("Authorization", "Bearer reader-token")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("status = %d, want 403, body: %s", w.Code, w.Body.String())
	}
}

func TestApprovalStatusHidesTokenFromNonRequester(t *testing.T) {
	srv, adminToken := setupTestServerWithStepUp(t)

	// Mint step-up with admin (who becomes the "requester" agent "admin")
	body := `{"role":"deploy"}`
	req := httptest.NewRequest("POST", "/v1/session/mint", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var mintResult struct {
		ApprovalID string `json:"approval_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &mintResult)

	// Approve it
	req = httptest.NewRequest("POST", "/v1/approval/"+mintResult.ApprovalID+"/approve", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("approve: %d", w.Code)
	}

	// Reader (non-admin, not the requester) tries to poll — should be rejected
	req = httptest.NewRequest("GET", "/v1/approval/"+mintResult.ApprovalID, nil)
	req.Header.Set("Authorization", "Bearer reader-token")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("status = %d, want 403, body: %s", w.Code, w.Body.String())
	}
}

func TestApprovalRejectsStaleRole(t *testing.T) {
	srv, adminToken := setupTestServerWithStepUp(t)

	// Mint step-up → 202
	body := `{"role":"deploy"}`
	req := httptest.NewRequest("POST", "/v1/session/mint", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var mintResult struct {
		ApprovalID string `json:"approval_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &mintResult)

	// Remove the deploy role from config while approval is pending
	srv.SetSessionRoles(map[string]config.RoleConfig{
		"dev": {
			Namespaces:     []string{"test/*"},
			Actions:        []string{"list", "read_value"},
			BootstrapTrust: []string{"bearer"},
		},
		// deploy role is gone
	})

	// Try to approve — should fail because role no longer exists
	req = httptest.NewRequest("POST", "/v1/approval/"+mintResult.ApprovalID+"/approve", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("status = %d, want 403, body: %s", w.Code, w.Body.String())
	}
	var result struct {
		Code string `json:"code"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.Code != "ROLE_NOT_FOUND" {
		t.Errorf("code = %q, want ROLE_NOT_FOUND", result.Code)
	}
}

func TestApprovalRejectsRoleNoLongerStepUp(t *testing.T) {
	srv, adminToken := setupTestServerWithStepUp(t)

	// Mint step-up → 202
	body := `{"role":"deploy"}`
	req := httptest.NewRequest("POST", "/v1/session/mint", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var mintResult struct {
		ApprovalID string `json:"approval_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &mintResult)

	// Change deploy role to no longer require step-up
	srv.SetSessionRoles(map[string]config.RoleConfig{
		"dev": {
			Namespaces:     []string{"test/*"},
			Actions:        []string{"list", "read_value"},
			BootstrapTrust: []string{"bearer"},
		},
		"deploy": {
			Namespaces:     []string{"prod/*"},
			Actions:        []string{"list", "read_value"},
			BootstrapTrust: []string{"bearer"},
			StepUp:         false, // no longer step-up
		},
	})

	// Try to approve — should fail because role no longer requires step-up
	req = httptest.NewRequest("POST", "/v1/approval/"+mintResult.ApprovalID+"/approve", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 409 {
		t.Fatalf("status = %d, want 409, body: %s", w.Code, w.Body.String())
	}
	var result struct {
		Code string `json:"code"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.Code != "ROLE_CHANGED" {
		t.Errorf("code = %q, want ROLE_CHANGED", result.Code)
	}
}

func TestApprovalRejectsBootstrapTrustTightened(t *testing.T) {
	srv, adminToken := setupTestServerWithStepUp(t)

	// Mint step-up with bearer auth → 202
	body := `{"role":"deploy"}`
	req := httptest.NewRequest("POST", "/v1/session/mint", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 202 {
		t.Fatalf("status = %d, want 202", w.Code)
	}
	var mintResult struct {
		ApprovalID string `json:"approval_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &mintResult)

	// Tighten bootstrap trust to mTLS only
	srv.SetSessionRoles(map[string]config.RoleConfig{
		"dev": {
			Namespaces:     []string{"test/*"},
			BootstrapTrust: []string{"bearer"},
		},
		"deploy": {
			Namespaces:     []string{"prod/*"},
			BootstrapTrust: []string{"mtls"}, // was "bearer", now "mtls"
			StepUp:         true,
			StepUpTTL:      "2m",
		},
	})

	// Approve — should fail because original bootstrap "bearer" no longer allowed
	req = httptest.NewRequest("POST", "/v1/approval/"+mintResult.ApprovalID+"/approve", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("status = %d, want 403, body: %s", w.Code, w.Body.String())
	}
	var result struct {
		Code string `json:"code"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.Code != "BOOTSTRAP_FAILED" {
		t.Errorf("code = %q, want BOOTSTRAP_FAILED", result.Code)
	}
}

func TestApprovalRejectsAttestationTightened(t *testing.T) {
	srv, adminToken := setupTestServerWithStepUp(t)

	// Mint step-up → 202 (no attestation required at request time)
	body := `{"role":"deploy"}`
	req := httptest.NewRequest("POST", "/v1/session/mint", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var mintResult struct {
		ApprovalID string `json:"approval_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &mintResult)

	// Add mTLS attestation requirement to deploy role
	srv.SetSessionRoles(map[string]config.RoleConfig{
		"dev": {
			Namespaces:     []string{"test/*"},
			BootstrapTrust: []string{"bearer"},
		},
		"deploy": {
			Namespaces:     []string{"prod/*"},
			BootstrapTrust: []string{"bearer"},
			Attestation:    []string{"require_mtls"}, // new requirement
			StepUp:         true,
			StepUpTTL:      "2m",
		},
	})

	// Approve — should fail because original request was bearer, not mTLS
	req = httptest.NewRequest("POST", "/v1/approval/"+mintResult.ApprovalID+"/approve", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("status = %d, want 403, body: %s", w.Code, w.Body.String())
	}
	var result struct {
		Code string `json:"code"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.Code != "ATTESTATION_FAILED" {
		t.Errorf("code = %q, want ATTESTATION_FAILED", result.Code)
	}
}

func TestApprovalRejectsSealKeyTightened(t *testing.T) {
	srv, adminToken := setupTestServerWithStepUp(t)

	// Mint step-up without seal key → 202
	body := `{"role":"deploy"}`
	req := httptest.NewRequest("POST", "/v1/session/mint", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var mintResult struct {
		ApprovalID string `json:"approval_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &mintResult)

	// Add seal key requirement
	srv.SetSessionRoles(map[string]config.RoleConfig{
		"dev": {
			Namespaces:     []string{"test/*"},
			BootstrapTrust: []string{"bearer"},
		},
		"deploy": {
			Namespaces:     []string{"prod/*"},
			BootstrapTrust: []string{"bearer"},
			RequireSealKey: true, // new requirement
			StepUp:         true,
			StepUpTTL:      "2m",
		},
	})

	// Approve — should fail because no seal key was provided at request time
	req = httptest.NewRequest("POST", "/v1/approval/"+mintResult.ApprovalID+"/approve", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("status = %d, want 403, body: %s", w.Code, w.Body.String())
	}
	var result struct {
		Code string `json:"code"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.Code != "SEAL_KEY_REQUIRED" {
		t.Errorf("code = %q, want SEAL_KEY_REQUIRED", result.Code)
	}
}

func TestSessionListAdmin(t *testing.T) {
	srv, adminToken := setupTestServerWithSessions(t)
	// Mint two sessions for different roles
	mintTestSession(t, srv, adminToken, "dev")
	mintTestSession(t, srv, adminToken, "writer")

	req := httptest.NewRequest("GET", "/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}

	var result struct {
		Sessions []map[string]interface{} `json:"sessions"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result.Sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(result.Sessions))
	}
}

func TestSessionListSelfOnly(t *testing.T) {
	srv, adminToken := setupTestServerWithSessions(t)

	// Add a non-admin agent that can mint sessions but has no admin on sessions
	srv.acl = acl.NewFromConfig(&acl.ACLConfig{
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
	})

	// Mint sessions as different agents
	mintTestSession(t, srv, adminToken, "dev")     // admin's session
	mintTestSession(t, srv, "reader-token", "dev") // reader's session

	// Reader should only see their own
	req := httptest.NewRequest("GET", "/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer reader-token")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}

	var result struct {
		Sessions []map[string]interface{} `json:"sessions"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result.Sessions) != 1 {
		t.Fatalf("expected 1 session (own only), got %d", len(result.Sessions))
	}
	if result.Sessions[0]["agent"] != "reader" {
		t.Errorf("expected agent=reader, got %v", result.Sessions[0]["agent"])
	}
}

func TestSessionListSessionToken(t *testing.T) {
	srv, adminToken := setupTestServerWithSessions(t)
	sessionToken := mintTestSession(t, srv, adminToken, "dev")

	// Mint another session to ensure it's not visible
	mintTestSession(t, srv, adminToken, "writer")

	// Session token caller should only see their own session
	req := httptest.NewRequest("GET", "/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}

	var result struct {
		Sessions []map[string]interface{} `json:"sessions"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result.Sessions) != 1 {
		t.Fatalf("expected 1 session (own only), got %d", len(result.Sessions))
	}
}

func TestSessionRevokeAdmin(t *testing.T) {
	srv, adminToken := setupTestServerWithSessions(t)
	sessionToken := mintTestSession(t, srv, adminToken, "dev")

	// Extract session ID from the session list
	req := httptest.NewRequest("GET", "/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var listResult struct {
		Sessions []struct {
			SessionID string `json:"session_id"`
		} `json:"sessions"`
	}
	json.Unmarshal(w.Body.Bytes(), &listResult)
	if len(listResult.Sessions) == 0 {
		t.Fatal("no sessions to revoke")
	}
	sessionID := listResult.Sessions[0].SessionID

	// Admin revokes the session
	req = httptest.NewRequest("POST", "/v1/sessions/"+sessionID+"/revoke", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("revoke: status = %d, want 200, body: %s", w.Code, w.Body.String())
	}

	var revokeResult struct {
		Status    string `json:"status"`
		SessionID string `json:"session_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &revokeResult)
	if revokeResult.Status != "revoked" {
		t.Errorf("status = %q, want 'revoked'", revokeResult.Status)
	}

	// Verify the revoked session token is rejected
	_ = sessionToken
	req = httptest.NewRequest("GET", "/v1/secrets/test/secret1", nil)
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401 for revoked session, got %d", w.Code)
	}
}

func TestSessionRevokeSelf(t *testing.T) {
	srv, adminToken := setupTestServerWithSessions(t)
	sessionToken := mintTestSession(t, srv, adminToken, "dev")

	// List to get session ID via the session token itself
	req := httptest.NewRequest("GET", "/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var listResult struct {
		Sessions []struct {
			SessionID string `json:"session_id"`
		} `json:"sessions"`
	}
	json.Unmarshal(w.Body.Bytes(), &listResult)
	if len(listResult.Sessions) == 0 {
		t.Fatal("no sessions found")
	}
	sessionID := listResult.Sessions[0].SessionID

	// Session token revokes itself
	req = httptest.NewRequest("POST", "/v1/sessions/"+sessionID+"/revoke", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("self-revoke: status = %d, want 200, body: %s", w.Code, w.Body.String())
	}
}

func TestSessionRevokeOtherDenied(t *testing.T) {
	srv, adminToken := setupTestServerWithSessions(t)

	// Reconfigure ACL with a non-admin reader
	srv.acl = acl.NewFromConfig(&acl.ACLConfig{
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
	})

	// Admin mints a session
	mintTestSession(t, srv, adminToken, "dev")

	// Get admin's session ID
	req := httptest.NewRequest("GET", "/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var listResult struct {
		Sessions []struct {
			SessionID string `json:"session_id"`
		} `json:"sessions"`
	}
	json.Unmarshal(w.Body.Bytes(), &listResult)
	if len(listResult.Sessions) == 0 {
		t.Fatal("no sessions found")
	}
	sessionID := listResult.Sessions[0].SessionID

	// Reader tries to revoke admin's session - should fail
	req = httptest.NewRequest("POST", "/v1/sessions/"+sessionID+"/revoke", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer reader-token")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("expected 403, got %d, body: %s", w.Code, w.Body.String())
	}
}

func TestSessionInfo(t *testing.T) {
	srv, adminToken := setupTestServerWithSessions(t)
	mintTestSession(t, srv, adminToken, "dev")

	// Get session ID
	req := httptest.NewRequest("GET", "/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var listResult struct {
		Sessions []struct {
			SessionID string `json:"session_id"`
		} `json:"sessions"`
	}
	json.Unmarshal(w.Body.Bytes(), &listResult)
	sessionID := listResult.Sessions[0].SessionID

	// Get session info
	req = httptest.NewRequest("GET", "/v1/sessions/"+sessionID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("info: status = %d, want 200, body: %s", w.Code, w.Body.String())
	}

	var info struct {
		SessionID string `json:"session_id"`
		Role      string `json:"role"`
		Agent     string `json:"agent"`
	}
	json.Unmarshal(w.Body.Bytes(), &info)
	if info.SessionID != sessionID {
		t.Errorf("session_id = %q, want %q", info.SessionID, sessionID)
	}
	if info.Role != "dev" {
		t.Errorf("role = %q, want 'dev'", info.Role)
	}
	if info.Agent != "admin" {
		t.Errorf("agent = %q, want 'admin'", info.Agent)
	}
}

func TestSessionRevokedDeniesAccess(t *testing.T) {
	srv, adminToken := setupTestServerWithSessions(t)

	// Store a test secret first
	body := `{"value":"secret123"}`
	req := httptest.NewRequest("PUT", "/v1/secrets/test/mysecret", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 && w.Code != 201 {
		t.Fatalf("set secret: status %d", w.Code)
	}

	sessionToken := mintTestSession(t, srv, adminToken, "dev")

	// Use session to read secret - should work
	req = httptest.NewRequest("GET", "/v1/secrets/test/mysecret", nil)
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("get before revoke: status %d, body: %s", w.Code, w.Body.String())
	}

	// Get session ID and revoke
	req = httptest.NewRequest("GET", "/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var listResult struct {
		Sessions []struct {
			SessionID string `json:"session_id"`
		} `json:"sessions"`
	}
	json.Unmarshal(w.Body.Bytes(), &listResult)
	// Find the session we minted (most recent)
	sessionID := listResult.Sessions[len(listResult.Sessions)-1].SessionID

	req = httptest.NewRequest("POST", "/v1/sessions/"+sessionID+"/revoke", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("revoke: status %d", w.Code)
	}

	// Try to use revoked session - should fail
	req = httptest.NewRequest("GET", "/v1/secrets/test/mysecret", nil)
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("expected 401 for revoked session, got %d, body: %s", w.Code, w.Body.String())
	}
}

func TestSessionListRoleFilter(t *testing.T) {
	srv, adminToken := setupTestServerWithSessions(t)
	mintTestSession(t, srv, adminToken, "dev")
	mintTestSession(t, srv, adminToken, "writer")

	// Filter by role=dev
	req := httptest.NewRequest("GET", "/v1/sessions?role=dev", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var result struct {
		Sessions []map[string]interface{} `json:"sessions"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result.Sessions) != 1 {
		t.Fatalf("expected 1 session with role=dev, got %d", len(result.Sessions))
	}
	if result.Sessions[0]["role"] != "dev" {
		t.Errorf("expected role=dev, got %v", result.Sessions[0]["role"])
	}
}

func TestSessionTokenCannotInspectSiblingSession(t *testing.T) {
	srv, adminToken := setupTestServerWithSessions(t)

	// Mint two sessions for the same agent (admin)
	sessionToken1 := mintTestSession(t, srv, adminToken, "dev")
	mintTestSession(t, srv, adminToken, "writer")

	// Get session IDs via admin bearer
	req := httptest.NewRequest("GET", "/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var listResult struct {
		Sessions []struct {
			SessionID string `json:"session_id"`
			Role      string `json:"role"`
		} `json:"sessions"`
	}
	json.Unmarshal(w.Body.Bytes(), &listResult)
	if len(listResult.Sessions) < 2 {
		t.Fatalf("expected 2 sessions, got %d", len(listResult.Sessions))
	}

	// Find the "writer" session (the sibling)
	var siblingID string
	for _, s := range listResult.Sessions {
		if s.Role == "writer" {
			siblingID = s.SessionID
			break
		}
	}
	if siblingID == "" {
		t.Fatal("could not find writer session")
	}

	// Session token 1 (dev) tries to inspect the writer session — should be denied
	req = httptest.NewRequest("GET", "/v1/sessions/"+siblingID, nil)
	req.Header.Set("Authorization", "Bearer "+sessionToken1)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("expected 403 for sibling session info, got %d, body: %s", w.Code, w.Body.String())
	}

	// Session token 1 (dev) tries to revoke the writer session — should be denied
	req = httptest.NewRequest("POST", "/v1/sessions/"+siblingID+"/revoke", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+sessionToken1)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("expected 403 for sibling session revoke, got %d, body: %s", w.Code, w.Body.String())
	}
}

func TestSessionExpiredStructuredDenial(t *testing.T) {
	srv, _ := setupTestServer(t)

	// Create a session store with a very short TTL
	ss, err := session.NewStore(1 * time.Second)
	if err != nil {
		t.Fatalf("session store: %v", err)
	}
	t.Cleanup(ss.Stop)
	srv.SetSessionStore(ss)
	srv.SetSessionRoles(map[string]config.RoleConfig{
		"dev": {
			Namespaces:     []string{"test/*"},
			Actions:        []string{"list", "read_value"},
			BootstrapTrust: []string{"bearer"},
		},
	})

	// Mint a session with the short TTL
	sessionToken := mintTestSession(t, srv, "admin-token", "dev")

	// Wait for it to expire
	time.Sleep(2 * time.Second)

	// Try to use the expired session
	req := httptest.NewRequest("GET", "/v1/secrets/test/secret1", nil)
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401, got %d, body: %s", w.Code, w.Body.String())
	}

	var result struct {
		Code string `json:"code"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.Code != "SESSION_EXPIRED" {
		t.Errorf("code = %q, want SESSION_EXPIRED", result.Code)
	}
}

func TestSessionRevokedStructuredDenial(t *testing.T) {
	srv, adminToken := setupTestServerWithSessions(t)
	sessionToken := mintTestSession(t, srv, adminToken, "dev")

	// Get session ID and revoke it
	req := httptest.NewRequest("GET", "/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var listResult struct {
		Sessions []struct {
			SessionID string `json:"session_id"`
		} `json:"sessions"`
	}
	json.Unmarshal(w.Body.Bytes(), &listResult)
	sessionID := listResult.Sessions[len(listResult.Sessions)-1].SessionID

	// Revoke
	req = httptest.NewRequest("POST", "/v1/sessions/"+sessionID+"/revoke", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Try to use the revoked session
	req = httptest.NewRequest("GET", "/v1/secrets/test/secret1", nil)
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401, got %d, body: %s", w.Code, w.Body.String())
	}

	var result struct {
		Code string `json:"code"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.Code != "SESSION_REVOKED" {
		t.Errorf("code = %q, want SESSION_REVOKED", result.Code)
	}
}

func TestSessionTokenBlockedOnAdminEndpoints(t *testing.T) {
	srv, adminToken := setupTestServerWithSessions(t)
	sessionToken := mintTestSession(t, srv, adminToken, "dev")

	// Admin endpoints that use authenticate() should all reject session tokens
	adminEndpoints := []struct {
		method string
		path   string
		body   string
	}{
		{"GET", "/v1/audit", ""},
		{"GET", "/v1/agents", ""},
		{"POST", "/v1/agents", `{"name":"x","token":"y","permissions":[]}`},
		{"GET", "/v1/status", ""},
		{"POST", "/v1/rotate-master", ""},
		{"GET", "/v1/policy/check?path=test/x&check=allow_unseal", ""},
	}

	for _, ep := range adminEndpoints {
		var req *http.Request
		if ep.body != "" {
			req = httptest.NewRequest(ep.method, ep.path, strings.NewReader(ep.body))
		} else {
			req = httptest.NewRequest(ep.method, ep.path, nil)
		}
		req.Header.Set("Authorization", "Bearer "+sessionToken)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != 401 {
			t.Errorf("%s %s: expected 401, got %d, body: %s", ep.method, ep.path, w.Code, w.Body.String())
			continue
		}

		var result struct {
			Code string `json:"code"`
		}
		json.Unmarshal(w.Body.Bytes(), &result)
		if result.Code != "ADMIN_AUTH_REQUIRED" {
			t.Errorf("%s %s: code = %q, want ADMIN_AUTH_REQUIRED", ep.method, ep.path, result.Code)
		}
	}
}
