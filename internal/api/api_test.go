package api

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.home/vector/phoenix/internal/acl"
	"git.home/vector/phoenix/internal/audit"
	"git.home/vector/phoenix/internal/ca"
	"git.home/vector/phoenix/internal/crypto"
	"git.home/vector/phoenix/internal/nonce"
	"git.home/vector/phoenix/internal/policy"
	"git.home/vector/phoenix/internal/store"
	"git.home/vector/phoenix/internal/token"
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

	srv := NewServer(s, a, al, auditPath)
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

	provider := srv.store.Provider().(*crypto.FileKeyProvider)
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
			"phoenix://test/exists",       // exists
			"phoenix://test/missing",      // not found
			"not-a-ref",                   // invalid scheme
			"phoenix://noslash",           // invalid path
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
	if errors["phoenix://other/hidden"] != "access denied" {
		t.Fatalf("hidden error = %v, want 'access denied'", errors["phoenix://other/hidden"])
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
			"phoenix://test/audited",  // success
			"phoenix://test/missing",  // not found
			"not-a-ref",               // malformed
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
