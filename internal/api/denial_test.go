package api

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/nonce"
	"github.com/phoenixsec/phoenix/internal/policy"
	"github.com/phoenixsec/phoenix/internal/session"
)

// Closed set of next steps; must match docs/denial-codes.md.
var allowedNextSteps = map[string]bool{
	NextRequestUse: true, NextWait: true, NextUseExec: true,
	NextRemintSession: true, NextAskUser: true, NextNone: true,
}

func TestDenialNextStepsAreFromClosedSet(t *testing.T) {
	for code, step := range denialNextStep {
		if !allowedNextSteps[step] {
			t.Errorf("code %s has next_step %q outside the closed set", code, step)
		}
	}
	if got := nextStepFor("SOME_FUTURE_CODE"); got != NextAskUser {
		t.Fatalf("unknown code next_step = %q, want %q", got, NextAskUser)
	}
	// request_use is never static: it depends on the current settings and
	// the path, so it only comes from Server.denialNextStep (see
	// TestRequestUseFollowsCurrentSettingsEverywhere in access_test.go).
	for code, step := range denialNextStep {
		if step == NextRequestUse {
			t.Errorf("code %s advertises request_use statically; it must go through denialNextStep", code)
		}
	}
}

func seedSecret(t *testing.T, srv *Server, adminToken, path, value string) {
	t.Helper()
	body, _ := json.Marshal(setSecretRequest{Value: value})
	req := httptest.NewRequest("PUT", "/v1/secrets/"+path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("seed %s: %d %s", path, w.Code, w.Body.String())
	}
}

func decodeDenial(t *testing.T, w *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var d map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
		t.Fatalf("decode denial: %v (%s)", err, w.Body.String())
	}
	return d
}

func TestACLDenialHasCodeAndDoesNotRevealExistence(t *testing.T) {
	srv, adminToken := setupTestServer(t)
	seedSecret(t, srv, adminToken, "other/exists", "v")

	cases := []struct{ method, path, action string }{
		{"GET", "/v1/secrets/other/exists", "read_value"},
		{"GET", "/v1/secrets/other/missing", "read_value"},
		{"PUT", "/v1/secrets/other/exists", "write"},
		{"DELETE", "/v1/secrets/other/exists", "delete"},
	}
	var readBodies []string
	for _, c := range cases {
		var body *bytes.Reader
		if c.method == "PUT" {
			b, _ := json.Marshal(setSecretRequest{Value: "x"})
			body = bytes.NewReader(b)
		} else {
			body = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(c.method, c.path, body)
		req.Header.Set("Authorization", "Bearer reader-token")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s %s: status %d, want 403", c.method, c.path, w.Code)
		}
		d := decodeDenial(t, w)
		if d["code"] != CodeACLDenied || d["next_step"] != NextAskUser {
			t.Fatalf("%s %s: denial = %v", c.method, c.path, d)
		}
		if !strings.Contains(d["detail"], c.action) {
			t.Fatalf("%s %s: detail %q does not name action %s", c.method, c.path, d["detail"], c.action)
		}
		if c.method == "GET" {
			readBodies = append(readBodies, w.Body.String())
		}
	}
	if readBodies[0] != readBodies[1] {
		t.Fatalf("denial differs for existing vs missing path:\n%s\n%s", readBodies[0], readBodies[1])
	}
}

func TestAttestationDenialDetailGoesToAuditOnly(t *testing.T) {
	srv, adminToken := setupTestServer(t)
	seedSecret(t, srv, adminToken, "secure/key", "v")
	p, err := policy.Load([]byte(`{"attestation": {"secure/*": {"deny_bearer": true, "require_mtls": true}}}`))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	srv.SetPolicy(p)

	req := httptest.NewRequest("GET", "/v1/secrets/secure/key", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", w.Code)
	}
	if strings.Contains(w.Body.String(), "secure/*") || strings.Contains(w.Body.String(), "mTLS") {
		t.Fatalf("response leaks policy text: %s", w.Body.String())
	}

	entries, _ := queryAPIAuditEntries(t, srv, adminToken)
	e := findAPIAuditEntry(entries, "read_value", "secure/key", "denied", "attestation")
	if e == nil {
		t.Fatalf("no attestation denial audit entry: %+v", entries)
	}
	if !strings.Contains(e.Metadata["denial.detail"], "secure/*") {
		t.Fatalf("audit metadata missing policy detail: %+v", e.Metadata)
	}
}

func TestResolveErrorCodesForMixedRefs(t *testing.T) {
	srv, adminToken := setupTestServer(t)
	seedSecret(t, srv, adminToken, "test/ok", "visible")
	seedSecret(t, srv, adminToken, "other/hidden", "v")
	seedSecret(t, srv, adminToken, "test/locked", "v")
	p, err := policy.Load([]byte(`{"attestation": {"test/locked": {"require_sealed": true}}}`))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	srv.SetPolicy(p)

	body, _ := json.Marshal(map[string]interface{}{"refs": []string{
		"phoenix://test/ok",
		"phoenix://other/hidden",
		"phoenix://test/locked",
		"phoenix://test/missing",
		"not-a-ref",
	}})
	req := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer reader-token")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Values     map[string]string    `json:"values"`
		Errors     map[string]string    `json:"errors"`
		ErrorCodes map[string]refDenial `json:"error_codes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Values["phoenix://test/ok"] != "visible" || len(resp.Values) != 1 {
		t.Fatalf("values = %v", resp.Values)
	}
	want := map[string]refDenial{
		"phoenix://other/hidden": {CodeACLDenied, NextAskUser},
		"phoenix://test/locked":  {CodeSealedRequired, NextUseExec},
		"phoenix://test/missing": {CodeNotFound, NextNone},
		"not-a-ref":              {CodeInvalidRef, NextNone},
	}
	if len(resp.ErrorCodes) != len(want) {
		t.Fatalf("error_codes = %v, want %v", resp.ErrorCodes, want)
	}
	for ref, w := range want {
		if resp.ErrorCodes[ref] != w {
			t.Errorf("error_codes[%s] = %v, want %v", ref, resp.ErrorCodes[ref], w)
		}
		if resp.Errors[ref] == "" {
			t.Errorf("legacy errors[%s] missing", ref)
		}
	}
}

func TestSessionDenialCarriesNextStep(t *testing.T) {
	srv, adminToken := setupTestServerWithSessions(t)
	token := mintTestSession(t, srv, adminToken, "dev")

	req := httptest.NewRequest("GET", "/v1/secrets/prod/outside", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", w.Code, w.Body.String())
	}
	d := decodeDenial(t, w)
	if d["code"] != CodeScopeExceeded || d["next_step"] != NextRemintSession {
		t.Fatalf("denial = %v", d)
	}
}

// Request-level attestation failures in /v1/resolve (nonce, timestamp skew,
// missing mTLS cert, bad signature) must use the denial contract and keep
// the specific reason in the audit log only.
func TestResolveEarlyAttestationFailuresAreCoded(t *testing.T) {
	srv, authority, adminToken := setupTestServerWithCA(t)
	ns := nonce.NewStore(30 * time.Second)
	defer ns.Stop()
	srv.SetNonceStore(ns)
	seedSecret(t, srv, adminToken, "signed/key", "v")

	bundle, err := authority.IssueAgentCert("admin")
	if err != nil {
		t.Fatalf("issue cert: %v", err)
	}
	block, _ := pem.Decode(bundle.CertPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	keyBlock, _ := pem.Decode(bundle.KeyPEM)
	ecKey, _ := x509.ParseECPrivateKey(keyBlock.Bytes)
	refs := []string{"phoenix://signed/key", "phoenix://signed/key", "phoenix://signed/other"}
	fresh := func() string { return time.Now().UTC().Format(time.RFC3339) }
	newNonce := func() string {
		e, err := ns.Generate()
		if err != nil {
			t.Fatalf("nonce: %v", err)
		}
		return e.Nonce
	}

	cases := []struct {
		name       string
		body       func() map[string]interface{}
		withCert   bool
		auditMatch string
	}{
		{"bad nonce", func() map[string]interface{} {
			return map[string]interface{}{"refs": refs, "nonce": "not-a-real-nonce"}
		}, false, "nonce validation failed"},
		{"stale timestamp", func() map[string]interface{} {
			n, ts := newNonce(), time.Now().Add(-5*time.Minute).UTC().Format(time.RFC3339)
			return map[string]interface{}{"refs": refs, "nonce": n, "timestamp": ts, "signature": signResolvePayload(t, ecKey, n, ts, refs)}
		}, true, "skew"},
		{"no mTLS cert", func() map[string]interface{} {
			n, ts := newNonce(), fresh()
			return map[string]interface{}{"refs": refs, "nonce": n, "timestamp": ts, "signature": signResolvePayload(t, ecKey, n, ts, refs)}
		}, false, "mTLS client certificate"},
		{"bad signature", func() map[string]interface{} {
			return map[string]interface{}{"refs": refs, "nonce": newNonce(), "timestamp": fresh(), "signature": base64.StdEncoding.EncodeToString([]byte("bad-sig"))}
		}, true, "signature verification failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body, _ := json.Marshal(c.body())
			req := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
			if c.withCert {
				req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
			} else {
				req.Header.Set("Authorization", "Bearer "+adminToken)
			}
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status %d, want 403: %s", w.Code, w.Body.String())
			}
			d := decodeDenial(t, w)
			if d["code"] != CodeAttestationRequired || d["next_step"] != NextAskUser {
				t.Fatalf("denial = %v", d)
			}
			if strings.Contains(w.Body.String(), c.auditMatch) {
				t.Fatalf("response leaks specific reason %q: %s", c.auditMatch, w.Body.String())
			}
			entries, _ := queryAPIAuditEntries(t, srv, adminToken)
			e := findAPIAuditEntry(entries, "resolve", "signed/key", "denied", "attestation")
			if e == nil || !strings.Contains(e.Metadata["denial.detail"], c.auditMatch) {
				t.Fatalf("audit entry missing detail %q: %+v", c.auditMatch, e)
			}
			// One entry per request, not per ref, so a caller cannot inflate the log.
			n := 0
			for _, en := range entries {
				if strings.Contains(en.Metadata["denial.detail"], c.auditMatch) {
					n++
					if en.Metadata["resolve.refs"] != strconv.Itoa(len(refs)) {
						t.Fatalf("resolve.refs = %q, want %d", en.Metadata["resolve.refs"], len(refs))
					}
				}
			}
			if n != 1 {
				t.Fatalf("%d audit entries for one request, want 1", n)
			}
		})
	}
}

// policyTerms are role attestation names that must not reach a session
// mint/renew caller.
var policyTerms = []string{"require_mtls", "source_ip", "cert_fingerprint", "mTLS", "fingerprint", "loopback"}

func assertNoPolicyTerms(t *testing.T, body string) {
	t.Helper()
	for _, term := range policyTerms {
		if strings.Contains(body, term) {
			t.Fatalf("response leaks policy term %q: %s", term, body)
		}
	}
}

func TestSessionMintAttestationFailureIsGeneric(t *testing.T) {
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
			Attestation:    []string{"require_mtls", "source_ip", "cert_fingerprint"},
		},
	})

	req := httptest.NewRequest("POST", "/v1/session/mint", strings.NewReader(`{"role":"secure"}`))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if d := decodeDenial(t, w); d["code"] != "ATTESTATION_FAILED" || d["next_step"] != NextAskUser {
		t.Fatalf("denial = %v", d)
	}
	assertNoPolicyTerms(t, w.Body.String())

	entries, _ := queryAPIAuditEntries(t, srv, adminToken)
	e := findAPIAuditEntry(entries, "session.mint", "secure", "denied", "attestation_failed")
	if e == nil || !strings.Contains(e.Metadata["denial.detail"], "mTLS") || !strings.Contains(e.Metadata["denial.detail"], "require_mtls") {
		t.Fatalf("audit entry missing attestation detail: %+v", e)
	}
}

func TestSessionRenewAttestationFailureIsGeneric(t *testing.T) {
	srv, authority, adminToken := setupTestServerWithCA(t)
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
			Attestation:    []string{"require_mtls", "cert_fingerprint"},
		},
	})
	bundle1, _ := authority.IssueAgentCert("admin")
	bundle2, _ := authority.IssueAgentCert("reader")

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, makeMTLSRequest("POST", "/v1/session/mint", []byte(`{"role":"secure"}`), bundle1.CertPEM))
	if w.Code != http.StatusOK {
		t.Fatalf("mint: %d %s", w.Code, w.Body.String())
	}
	var mint struct {
		SessionToken string `json:"session_token"`
	}
	json.Unmarshal(w.Body.Bytes(), &mint)

	cases := []struct {
		name, reason, auditMatch string
		req                      *http.Request
	}{
		{"missing mTLS", "attestation_failed", "require_mtls", httptest.NewRequest("POST", "/v1/session/renew", strings.NewReader(`{}`))},
		{"different cert", "cert_continuity_failed", "fingerprint", makeMTLSRequest("POST", "/v1/session/renew", []byte(`{}`), bundle2.CertPEM)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.req.Header.Set("Authorization", "Bearer "+mint.SessionToken)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, c.req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if d := decodeDenial(t, w); d["code"] != "ATTESTATION_FAILED" {
				t.Fatalf("denial = %v", d)
			}
			assertNoPolicyTerms(t, w.Body.String())
			entries, _ := queryAPIAuditEntries(t, srv, adminToken)
			e := findAPIAuditEntry(entries, "session.renew", "secure", "denied", c.reason)
			if e == nil || !strings.Contains(e.Metadata["denial.detail"], c.auditMatch) {
				t.Fatalf("audit entry missing detail %q: %+v", c.auditMatch, e)
			}
		})
	}
}

// denial.detail can carry caller-controlled text (e.g. X-Phoenix-Tool); the
// stored copy is capped so one request cannot bloat the audit log.
func TestAuditDeniedDetailIsCapped(t *testing.T) {
	srv, adminToken := setupTestServer(t)
	huge := strings.Repeat("é", 16*1024) // 32 KiB, multi-byte
	req := httptest.NewRequest("GET", "/v1/secrets/x/y", nil)
	srv.auditDeniedDetail(req, &authInfo{Agent: "admin"}, "read_value", "x/y", "192.0.2.1", "attestation", huge)

	entries, _ := queryAPIAuditEntries(t, srv, adminToken)
	e := findAPIAuditEntry(entries, "read_value", "x/y", "denied", "attestation")
	if e == nil {
		t.Fatal("no audit entry")
	}
	got := e.Metadata["denial.detail"]
	if len(got) > maxDenialDetailBytes || !utf8.ValidString(got) || !strings.HasSuffix(got, denialDetailTruncated) {
		t.Fatalf("detail not capped safely: %d bytes, valid=%v, tail=%q", len(got), utf8.ValidString(got), got[max(0, len(got)-20):])
	}
	if short := capDenialDetail("short"); short != "short" {
		t.Fatalf("short detail changed: %q", short)
	}
}
