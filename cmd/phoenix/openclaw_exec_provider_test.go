package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phoenixsec/phoenix/internal/crypto"
)

func TestParseOpenClawExecProviderRequest(t *testing.T) {
	req, err := parseOpenClawExecProviderRequest(strings.NewReader(`{"protocolVersion":1,"provider":"phoenix","ids":["api/openrouter","phoenix://bot/token"]}`))
	if err != nil {
		t.Fatalf("parseOpenClawExecProviderRequest error: %v", err)
	}
	if req.ProtocolVersion != 1 || req.Provider != "phoenix" {
		t.Fatalf("unexpected request header: %#v", req)
	}
	if got, want := strings.Join(req.IDs, ","), "api/openrouter,phoenix://bot/token"; got != want {
		t.Fatalf("ids = %q, want %q", got, want)
	}
}

func TestParseOpenClawExecProviderRequestRejectsBadProtocol(t *testing.T) {
	_, err := parseOpenClawExecProviderRequest(strings.NewReader(`{"protocolVersion":2,"provider":"phoenix","ids":["api/key"]}`))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "protocolVersion must be 1") {
		t.Fatalf("error = %v, want protocolVersion message", err)
	}
}

func TestParseOpenClawExecProviderRequestRejectsNonPhoenixProvider(t *testing.T) {
	_, err := parseOpenClawExecProviderRequest(strings.NewReader(`{"protocolVersion":1,"provider":"other","ids":["api/key"]}`))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "provider must be phoenix") {
		t.Fatalf("error = %v, want provider message", err)
	}
}

func TestParseOpenClawExecProviderRequestRejectsTrailingData(t *testing.T) {
	_, err := parseOpenClawExecProviderRequest(strings.NewReader(`{"protocolVersion":1,"provider":"phoenix","ids":["api/key"]}{"extra":true}`))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("error = %v, want trailing data message", err)
	}
}

func TestParseOpenClawExecProviderRequestAllowsTrailingWhitespace(t *testing.T) {
	_, err := parseOpenClawExecProviderRequest(strings.NewReader(`{"protocolVersion":1,"provider":"phoenix","ids":["api/key"]}` + "\n  \n"))
	if err != nil {
		t.Fatalf("parseOpenClawExecProviderRequest error: %v", err)
	}
}

func TestCmdOpenClawExecProviderEmptyIDsSkipsAPICall(t *testing.T) {
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected API call to %s for empty ids", r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}, func() {
		out := runOpenClawExecProviderWithStdin(t, `{"protocolVersion":1,"provider":"phoenix","ids":[]}`)
		var resp openClawExecProviderResponse
		if err := json.Unmarshal([]byte(out), &resp); err != nil {
			t.Fatalf("decode stdout: %v; stdout=%q", err, out)
		}
		if resp.ProtocolVersion != 1 {
			t.Fatalf("protocolVersion = %d, want 1", resp.ProtocolVersion)
		}
		if resp.Values == nil || len(resp.Values) != 0 {
			t.Fatalf("values = %#v, want empty map", resp.Values)
		}
		if len(resp.Errors) != 0 {
			t.Fatalf("errors = %#v, want none", resp.Errors)
		}
	})
}

func TestCmdOpenClawExecProviderSealedValues(t *testing.T) {
	kp, err := crypto.GenerateSealKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "seal.key")
	if err := os.WriteFile(keyPath, []byte(crypto.EncodeSealKey(&kp.PrivateKey)), 0600); err != nil {
		t.Fatal(err)
	}

	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		pub, err := crypto.DecodeSealKey(r.Header.Get("X-Phoenix-Seal-Key"))
		if err != nil {
			t.Errorf("decode request seal key: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		env, _ := crypto.SealValue("api/key", "phoenix://api/key", "sealed-secret", pub)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sealed_values": map[string]interface{}{"phoenix://api/key": env},
		})
	}, func() {
		t.Setenv("PHOENIX_ROLE", "")
		t.Setenv("PHOENIX_SEAL_KEY", keyPath)

		out := runOpenClawExecProviderWithStdin(t, `{"protocolVersion":1,"provider":"phoenix","ids":["api/key"]}`)
		var resp openClawExecProviderResponse
		if err := json.Unmarshal([]byte(out), &resp); err != nil {
			t.Fatalf("decode stdout: %v; stdout=%q", err, out)
		}
		if got := resp.Values["api/key"]; got != "sealed-secret" {
			t.Fatalf("api/key value = %q, want decrypted sealed value", got)
		}
		if len(resp.Errors) != 0 {
			t.Fatalf("errors = %#v, want none", resp.Errors)
		}
	})
}

func TestCmdOpenClawExecProviderServerErrorFails(t *testing.T) {
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"access denied"}`))
	}, func() {
		out, err := runOpenClawExecProviderCommandWithStdinResult(t, `{"protocolVersion":1,"provider":"phoenix","ids":["api/key"]}`, func() error {
			return cmdOpenClawExecProvider(nil)
		})
		if err == nil {
			t.Fatalf("expected error for non-200 response, stdout=%q", out)
		}
		if strings.TrimSpace(out) != "" {
			t.Fatalf("stdout = %q, want no output on server error", out)
		}
	})
}

func TestCmdOpenClawExecProviderStdoutShape(t *testing.T) {
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/resolve" {
			t.Fatalf("path = %q, want /v1/resolve", r.URL.Path)
		}
		var body struct {
			Refs []string `json:"refs"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if got, want := strings.Join(body.Refs, ","), "phoenix://api/openrouter,phoenix://bot/token"; got != want {
			t.Fatalf("refs = %q, want %q", got, want)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"values":{"phoenix://api/openrouter":"openrouter-value","phoenix://bot/token":"bot-token"}}`))
	}, func() {
		out := runOpenClawExecProviderWithStdin(t, `{"protocolVersion":1,"provider":"phoenix","ids":["api/openrouter","phoenix://bot/token"]}`)
		var resp openClawExecProviderResponse
		if err := json.Unmarshal([]byte(out), &resp); err != nil {
			t.Fatalf("decode stdout: %v; stdout=%q", err, out)
		}
		if resp.ProtocolVersion != 1 {
			t.Fatalf("protocolVersion = %d, want 1", resp.ProtocolVersion)
		}
		if got := resp.Values["api/openrouter"]; got != "openrouter-value" {
			t.Fatalf("api/openrouter value = %q", got)
		}
		if got := resp.Values["phoenix://bot/token"]; got != "bot-token" {
			t.Fatalf("phoenix://bot/token value = %q", got)
		}
		if len(resp.Errors) != 0 {
			t.Fatalf("errors = %#v, want none", resp.Errors)
		}
	})
}

func TestCmdResolveStdinJSONAlias(t *testing.T) {
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"values":{"phoenix://api/key":"key-value"}}`))
	}, func() {
		out := runOpenClawExecProviderCommandWithStdin(t, `{"protocolVersion":1,"provider":"phoenix","ids":["api/key"]}`, func() error {
			return cmdResolve([]string{"--stdin-json"})
		})
		var resp openClawExecProviderResponse
		if err := json.Unmarshal([]byte(out), &resp); err != nil {
			t.Fatalf("decode stdout: %v; stdout=%q", err, out)
		}
		if got := resp.Values["api/key"]; got != "key-value" {
			t.Fatalf("api/key value = %q", got)
		}
	})
}

func TestCmdOpenClawExecProviderPartialFailure(t *testing.T) {
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"values":{"phoenix://ok":"ok-value"},"errors":{"phoenix://missing":"access denied"}}`))
	}, func() {
		out := runOpenClawExecProviderWithStdin(t, `{"protocolVersion":1,"provider":"phoenix","ids":["ok","missing"]}`)
		var resp openClawExecProviderResponse
		if err := json.Unmarshal([]byte(out), &resp); err != nil {
			t.Fatalf("decode stdout: %v; stdout=%q", err, out)
		}
		if got := resp.Values["ok"]; got != "ok-value" {
			t.Fatalf("ok value = %q", got)
		}
		errEntry, ok := resp.Errors["missing"]
		if !ok {
			t.Fatalf("missing error absent: %#v", resp.Errors)
		}
		if errEntry.Message != "access denied" {
			t.Fatalf("missing error = %q", errEntry.Message)
		}
		if _, leaked := resp.Values["missing"]; leaked {
			t.Fatal("missing id unexpectedly has a value")
		}
	})
}

func runOpenClawExecProviderWithStdin(t *testing.T, stdin string) string {
	t.Helper()
	return runOpenClawExecProviderCommandWithStdin(t, stdin, func() error {
		return cmdOpenClawExecProvider(nil)
	})
}

func runOpenClawExecProviderCommandWithStdin(t *testing.T, stdin string, run func() error) string {
	t.Helper()

	out, cmdErr := runOpenClawExecProviderCommandWithStdinResult(t, stdin, run)
	if cmdErr != nil {
		t.Fatalf("cmdOpenClawExecProvider error: %v", cmdErr)
	}
	return out
}

func runOpenClawExecProviderCommandWithStdinResult(t *testing.T, stdin string, run func() error) (string, error) {
	t.Helper()

	origStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	if _, err := io.Copy(w, bytes.NewBufferString(stdin)); err != nil {
		t.Fatalf("write stdin pipe: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close stdin writer: %v", err)
	}
	os.Stdin = r
	defer func() {
		os.Stdin = origStdin
		_ = r.Close()
	}()

	var cmdErr error
	out := captureStdout(t, func() {
		cmdErr = run()
	})
	return out, cmdErr
}
