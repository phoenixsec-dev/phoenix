package phoenix

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	c := New("", "")
	if c.Server != "http://127.0.0.1:9090" {
		t.Fatalf("expected default server, got %q", c.Server)
	}
}
