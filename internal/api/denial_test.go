package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/phoenixsec/phoenix/internal/policy"
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
	p, err := policy.Load([]byte(`{"attestation": {"secure/*": {"source_ip": ["10.9.9.9"]}}}`))
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
	if strings.Contains(w.Body.String(), "secure/*") || strings.Contains(w.Body.String(), "10.9.9.9") {
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
