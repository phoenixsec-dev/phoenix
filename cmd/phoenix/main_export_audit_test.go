package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func withMockServer(t *testing.T, handler http.HandlerFunc, fn func()) {
	t.Helper()

	ts := httptest.NewServer(handler)
	defer ts.Close()

	oldURL := serverURL
	oldToken := token
	oldClient := httpClient
	serverURL = ts.URL
	token = "test-token"
	httpClient = ts.Client()
	defer func() {
		serverURL = oldURL
		token = oldToken
		httpClient = oldClient
	}()

	fn()
}

func TestCmdExportFailsOnListNon200(t *testing.T) {
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"list failed"}`))
	}, func() {
		err := cmdExport(nil)
		if err == nil {
			t.Fatal("expected error for non-200 list")
		}
		if !strings.Contains(err.Error(), "HTTP 500") {
			t.Fatalf("error = %v, want HTTP 500", err)
		}
	})
}

func TestCmdExportFailsOnSecretGetNon200(t *testing.T) {
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/secrets/":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"paths":["app/key"]}`))
		case "/v1/secrets/app/key":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"denied"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}, func() {
		err := cmdExport(nil)
		if err == nil {
			t.Fatal("expected error for non-200 secret read")
		}
		if !strings.Contains(err.Error(), `exporting "app/key"`) {
			t.Fatalf("error = %v, want exporting context", err)
		}
		if !strings.Contains(err.Error(), "HTTP 403") {
			t.Fatalf("error = %v, want HTTP 403", err)
		}
	})
}

func TestCmdAuditUsesURLEncoding(t *testing.T) {
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/audit" {
			t.Fatalf("path = %q, want /v1/audit", r.URL.Path)
		}
		if got := r.URL.Query().Get("agent"); got != "alice&bob" {
			t.Fatalf("agent query = %q, want %q", got, "alice&bob")
		}
		if got := r.URL.Query().Get("limit"); got != "10" {
			t.Fatalf("limit query = %q, want %q", got, "10")
		}
		if got := r.URL.Query().Get("since"); got != "2026-03-01T05:00:00Z" {
			t.Fatalf("since query = %q, want %q", got, "2026-03-01T05:00:00Z")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"entries":[]}`))
	}, func() {
		err := cmdAudit([]string{"--last", "10", "--agent", "alice&bob", "--since", "2026-03-01T05:00:00Z"})
		if err != nil {
			t.Fatalf("cmdAudit error: %v", err)
		}
	})
}
