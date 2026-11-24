package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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

// Export never asks for, or reports success about, something it cannot export:
// a single secret (whose one-time use the read would spend) or an unknown format.
func TestCmdExportRefusesBeforeAsking(t *testing.T) {
	t.Setenv("PHOENIX_SEAL_KEY", "")
	for _, args := range [][]string{{"app/key"}, {"app"}, {"app/", "-f", "yaml"}, {"app/", "-f", ""}} {
		withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("%q: asked the server", args)
			w.Write([]byte(`{"value":"fake"}`))
		}, func() {
			if err := cmdExport(args); err == nil {
				t.Errorf("%q: no error", args)
			}
		})
	}
}

// A backup that could not be written is an error.
func TestCmdExportReportsWriteErrors(t *testing.T) {
	t.Setenv("PHOENIX_SEAL_KEY", "")
	full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Skip(err)
	}
	defer full.Close()
	for _, format := range []string{"env", "json"} {
		withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/") {
				w.Write([]byte(`{"paths":["app/key"]}`))
				return
			}
			w.Write([]byte(`{"value":"fake"}`))
		}, func() {
			old := os.Stdout
			os.Stdout = full
			err := cmdExport([]string{"app/", "-f", format})
			os.Stdout = old
			if err == nil {
				t.Errorf("%s: no error", format)
			}
		})
	}
}

// Every line of a JSON export is JSON and holds exactly the name and the value.
func TestCmdExportJSONIsJSON(t *testing.T) {
	t.Setenv("PHOENIX_SEAL_KEY", "")
	path, value := "app/A\a\vB=\"é<", "fake\a\v\n\x00\"\\<é"
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			json.NewEncoder(w).Encode(map[string]any{"paths": []string{path}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"value": value})
	}, func() {
		var err error
		out := captureStdout(t, func() { err = cmdExport([]string{"app/", "-f", "json"}) })
		var rec map[string]string
		if err != nil || json.Unmarshal([]byte(out), &rec) != nil || strings.Count(out, "\n") != 1 {
			t.Fatalf("not one line of JSON (%v)", err)
		}
		if len(rec) != 1 || rec["A\a\vB=\"É<"] != value {
			t.Error("wrong name or value")
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

// A search the server cut short prints a note on stderr, not silence.
func TestCmdAuditWarnsWhenTruncated(t *testing.T) {
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"entries":[],"truncated":true}`))
	}, func() {
		out := captureStderr(t, func() {
			if err := cmdAudit([]string{"--agent", "nobody"}); err != nil {
				t.Fatalf("cmdAudit error: %v", err)
			}
		})
		if !strings.Contains(out, "only the newest part") {
			t.Fatalf("stderr = %q", out)
		}
	})
}
