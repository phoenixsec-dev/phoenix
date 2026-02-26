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

	"git.home/vector/phoenix/internal/acl"
	"git.home/vector/phoenix/internal/audit"
	"git.home/vector/phoenix/internal/ca"
	"git.home/vector/phoenix/internal/crypto"
	"git.home/vector/phoenix/internal/store"
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
