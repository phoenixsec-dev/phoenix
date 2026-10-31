package phoenix

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/health" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != "GET" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	c := New(srv.URL, "test-token")
	result, err := c.Health()
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if result["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", result["status"])
	}
}

func TestResolve(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/resolve" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("missing auth header")
		}

		var req struct {
			Refs []string `json:"refs"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"values": map[string]string{
				req.Refs[0]: "secret-value",
			},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "test-token")
	val, err := c.Resolve("phoenix://myapp/key")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if val != "secret-value" {
		t.Fatalf("expected secret-value, got %q", val)
	}
}

func TestResolveBatch(t *testing.T) {
	refs := []string{"phoenix://a/key1", "phoenix://a/key2"}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"values": map[string]string{
				"phoenix://a/key1": "val1",
				"phoenix://a/key2": "val2",
			},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "tok")
	result, err := c.ResolveBatch(refs)
	if err != nil {
		t.Fatalf("ResolveBatch: %v", err)
	}
	if result.Values["phoenix://a/key1"] != "val1" {
		t.Fatalf("expected val1, got %q", result.Values["phoenix://a/key1"])
	}
	if result.Values["phoenix://a/key2"] != "val2" {
		t.Fatalf("expected val2, got %q", result.Values["phoenix://a/key2"])
	}
}

func TestResolveError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"values": map[string]string{},
			"errors": map[string]string{
				"phoenix://ns/missing": "secret not found",
			},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "tok")
	_, err := c.Resolve("phoenix://ns/missing")
	if err == nil {
		t.Fatal("expected error for missing secret")
	}
	pe, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected *Error, got %T", err)
	}
	if pe.Message != "secret not found" {
		t.Fatalf("expected 'secret not found', got %q", pe.Message)
	}
}

func TestHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
	}))
	defer srv.Close()

	c := New(srv.URL, "bad-token")
	_, err := c.Health()
	if err == nil {
		t.Fatal("expected error for 401")
	}
	pe, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected *Error, got %T", err)
	}
	if pe.Status != 401 {
		t.Fatalf("expected status 401, got %d", pe.Status)
	}
}

func TestResolveBatchEmpty(t *testing.T) {
	c := New("http://localhost:9999", "tok")
	_, err := c.ResolveBatch(nil)
	if err == nil {
		t.Fatal("expected error for empty refs")
	}
}

func TestServerUnreachable(t *testing.T) {
	c := New("http://127.0.0.1:1", "tok")
	_, err := c.Health()
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
}

func TestResolveBatchPartialErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"values": map[string]string{
				"phoenix://ns/found": "secret-val",
			},
			"errors": map[string]string{
				"phoenix://ns/missing": "secret not found",
			},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "tok")
	result, err := c.ResolveBatch([]string{"phoenix://ns/found", "phoenix://ns/missing"})
	if err != nil {
		t.Fatalf("ResolveBatch: %v", err)
	}

	if result.Values["phoenix://ns/found"] != "secret-val" {
		t.Fatalf("expected 'secret-val', got %q", result.Values["phoenix://ns/found"])
	}
	if result.Errors["phoenix://ns/missing"] != "secret not found" {
		t.Fatalf("expected error for missing ref, got %q", result.Errors["phoenix://ns/missing"])
	}
}

func TestResolveRefInErrorsMap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"values": map[string]string{},
			"errors": map[string]string{
				"phoenix://ns/secret": "access denied",
			},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "tok")
	_, err := c.Resolve("phoenix://ns/secret")
	if err == nil {
		t.Fatal("expected error for ref in errors map")
	}
	pe, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected *Error, got %T", err)
	}
	if pe.Message != "access denied" {
		t.Fatalf("expected 'access denied', got %q", pe.Message)
	}
}

func TestErrorFormat(t *testing.T) {
	tests := []struct {
		name     string
		err      Error
		expected string
	}{
		{"with status", Error{Message: "unauthorized", Status: 401}, "phoenix: HTTP 401: unauthorized"},
		{"without status", Error{Message: "connection refused", Status: 0}, "phoenix: connection refused"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Fatalf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestResolveNoValueReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"values": map[string]string{},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "tok")
	_, err := c.Resolve("phoenix://ns/key")
	if err == nil {
		t.Fatal("expected error when no value returned")
	}
}

func TestNewDefaults(t *testing.T) {
	t.Setenv("PHOENIX_SERVER", "")
	t.Setenv("PHOENIX_TOKEN", "")
	c := New("", "")
	if c.Server != "http://127.0.0.1:9090" {
		t.Fatalf("expected default server, got %q", c.Server)
	}
}

func TestNewWithRoleFailsClosedOnMintError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/session/mint" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "mint denied",
			"code":  "BOOTSTRAP_FAILED",
		})
	}))
	defer srv.Close()

	c, err := NewWithRole(srv.URL, "bootstrap-token", "dev")
	if err == nil {
		t.Fatal("expected mint failure")
	}
	if c != nil {
		t.Fatal("expected nil client on mint failure")
	}
	if got := fmt.Sprint(err); got == "" || !strings.Contains(got, "session mint for role") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestErrorHelpers(t *testing.T) {
	tests := []struct {
		name   string
		err    Error
		check  func(*Error) bool
		expect bool
	}{
		{"approval required true", Error{Code: "APPROVAL_REQUIRED"}, (*Error).IsApprovalRequired, true},
		{"approval reapproval true", Error{Code: "STEP_UP_REAPPROVAL_REQUIRED"}, (*Error).IsApprovalRequired, true},
		{"approval required false", Error{Code: "OTHER"}, (*Error).IsApprovalRequired, false},
		{"session expired true", Error{Code: "SESSION_EXPIRED"}, (*Error).IsSessionExpired, true},
		{"session expired false", Error{Code: "OTHER"}, (*Error).IsSessionExpired, false},
		{"scope exceeded true", Error{Code: "SCOPE_EXCEEDED"}, (*Error).IsScopeExceeded, true},
		{"scope exceeded false", Error{Code: "OTHER"}, (*Error).IsScopeExceeded, false},
		{"action denied true", Error{Code: "ACTION_DENIED"}, (*Error).IsActionDenied, true},
		{"action denied false", Error{Code: "OTHER"}, (*Error).IsActionDenied, false},
		{"session revoked true", Error{Code: "SESSION_REVOKED"}, (*Error).IsSessionRevoked, true},
		{"session revoked false", Error{Code: "OTHER"}, (*Error).IsSessionRevoked, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.check(&tt.err)
			if got != tt.expect {
				t.Errorf("got %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestListSessions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sessions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != "GET" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sessions": []map[string]interface{}{
				{
					"session_id": "ses_abc123",
					"role":       "dev",
					"agent":      "test-agent",
					"created_at": "2026-01-01T00:00:00Z",
					"expires_at": "2026-01-01T01:00:00Z",
				},
			},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "test-token")
	sessions, err := c.ListSessions()
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].SessionID != "ses_abc123" {
		t.Errorf("session_id = %q, want ses_abc123", sessions[0].SessionID)
	}
	if sessions[0].Role != "dev" {
		t.Errorf("role = %q, want dev", sessions[0].Role)
	}
}

func TestRevokeSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sessions/ses_abc123/revoke" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		json.NewEncoder(w).Encode(map[string]string{
			"status":     "revoked",
			"session_id": "ses_abc123",
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "test-token")
	err := c.RevokeSession("ses_abc123")
	if err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
}

func TestIsPlaintextNonLoopback(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"http://127.0.0.1:9090", false},
		{"http://localhost:9090", false},
		{"http://[::1]:9090", false},
		{"http://192.168.1.10:9090", true},
		{"http://0.0.0.0:9090", true},
		{"http://phoenix.internal:9090", true},
		{"https://192.168.1.10:9090", false},
		{"https://phoenix.internal:9090", false},
	}
	for _, tt := range tests {
		if got := isPlaintextNonLoopback(tt.url); got != tt.want {
			t.Errorf("isPlaintextNonLoopback(%q) = %v, want %v", tt.url, got, tt.want)
		}
	}
}

func TestPlaintextAllowed(t *testing.T) {
	tests := []struct {
		url, allow string
		want       bool
	}{
		// Basic named-host matching.
		{"http://192.168.1.10:9090", "192.168.1.10", true},
		{"http://192.168.1.10:9090", " 10.0.0.5 , 192.168.1.10 ", true},
		{"http://192.168.1.10:9090", ", ,192.168.1.10", true},
		{"http://Phoenix.Internal:9090", "phoenix.internal", true},
		{"http://192.168.1.10:8443", "192.168.1.10", true}, // every port on a named host
		{"http://192.168.1.10:9090", "", false},
		{"http://192.168.1.10:9090", "   ", false},
		{"http://192.168.1.10:9090", ",,,", false},
		{"http://192.168.1.10:9090", "192.168.1.11", false},
		{"http://192.168.1.10:9090", "192.168.1.10:9090", false}, // host only, no port
		{"http://192.168.1.10:9090", "192.168.1.1", false},       // no prefix match
		{"http://192.168.1.10:9090", "1", false},                 // not a blanket switch
		{"http://192.168.1.10:9090", "http://192.168.1.10", false},
		{"http://192.168.1.10:9090", "192.168.1.10/", false},
		{"http://192.168.1.10:9090", "::ffff:192.168.1.10", false}, // other spelling warns
		{"not a url %%", "192.168.1.10", false},
		// No wildcards.
		{"http://192.168.1.10:9090", "*", false},
		{"http://a.example.com:9090", "*.example.com", false},
		// IPv6 compares as an address; brackets optional.
		{"http://[fd00::10]:9090", "fd00::10", true},
		{"http://[fd00::10]:9090", "[fd00::10]", true},
		{"http://[fd00::10]:9090", "FD00:0::10", true},
		{"http://[fd00::10]:9090", "fd00::11", false},
		// IPv6 zones are case-sensitive interface names and must match.
		{"http://[fe80::1%25eth0]:9090", "fe80::1%eth0", true},
		{"http://[fe80::1%25ETH0]:9090", "fe80::1%eth0", false},
		{"http://[fe80::1%25eth0]:9090", "fe80::1", false},
		{"http://[fe80::1]:9090", "fe80::1%eth0", false},
		// Non-ASCII names never fold: these are different DNS names.
		{"http://ς.example:9090", "σ.example", false}, // final sigma vs sigma
		{"http://σ.example:9090", "σ.example", true},
		{"http://K.example:9090", "k.example", false}, // Kelvin sign vs k
	}
	for _, tt := range tests {
		if got := plaintextAllowed(tt.url, tt.allow); got != tt.want {
			t.Errorf("plaintextAllowed(%q, %q) = %v, want %v", tt.url, tt.allow, got, tt.want)
		}
	}
}

// TestPlaintextWarningAllowList drives the real New -> warnPlaintextOnce path:
// an allowed host stays quiet, an unlisted host warns exactly once per
// process, and dropping the variable brings the warning back.
func TestPlaintextWarningAllowList(t *testing.T) {
	var out bytes.Buffer
	prev := plaintextWarnOut
	plaintextWarnOut = &out
	plaintextWarned.Clear()
	t.Cleanup(func() {
		plaintextWarnOut = prev
		plaintextWarned.Clear()
	})

	const allowed, other = "http://10.99.0.1:9090", "http://10.99.0.2:9090"
	t.Setenv("PHOENIX_ALLOW_PLAINTEXT", "10.99.0.1")

	New(allowed, "tok")
	if out.Len() != 0 {
		t.Fatalf("allowed host warned:\n%s", out.String())
	}
	New(other, "tok")
	New(other, "tok")
	if n := strings.Count(out.String(), "WARNING"); n != 1 {
		t.Fatalf("unlisted host: got %d warnings, want 1:\n%s", n, out.String())
	}
	if !strings.Contains(out.String(), other) || !strings.Contains(out.String(), "PHOENIX_ALLOW_PLAINTEXT") {
		t.Errorf("warning should name the server and the opt-out:\n%s", out.String())
	}

	out.Reset()
	t.Setenv("PHOENIX_ALLOW_PLAINTEXT", "")
	New(allowed, "tok")
	if !strings.Contains(out.String(), allowed) {
		t.Errorf("host should warn once the variable is unset, got:\n%q", out.String())
	}
}
