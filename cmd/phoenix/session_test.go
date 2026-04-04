package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phoenixsec/phoenix/internal/crypto"
)

func TestAutoMintSessionReusesCachedTokenWithoutMint(t *testing.T) {
	role := "deploy-role"

	var mintCount int32
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/session/mint" {
			atomic.AddInt32(&mintCount, 1)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/v1/session/renew" {
			t.Fatalf("renew should not be called when cached token is safely valid")
		}
	}, func() {
		t.Setenv("PHOENIX_ROLE", role)
		t.Setenv("HOME", t.TempDir())
		t.Setenv("PHOENIX_TOKEN", "bootstrap-token")
		token = "bootstrap-token"

		cache := map[string]*tokenCacheEntry{
			sessionCacheKey(role): {
				Token:     "phxs_cached-token",
				Agent:     "session:" + role,
				ExpiresAt: time.Now().Add(20 * time.Minute),
			},
		}
		if err := saveTokenCache(cache); err != nil {
			t.Fatalf("saveTokenCache: %v", err)
		}

		if err := requireAuth(); err != nil {
			t.Fatalf("first requireAuth: %v", err)
		}
		if atomic.LoadInt32(&mintCount) != 0 {
			t.Fatalf("expected no mint call, got %d", atomic.LoadInt32(&mintCount))
		}
		if token != "phxs_cached-token" {
			t.Fatalf("token = %q, want cached token", token)
		}

		// Repeated invocation should also reuse cache and not mint.
		if err := requireAuth(); err != nil {
			t.Fatalf("second requireAuth: %v", err)
		}
		if atomic.LoadInt32(&mintCount) != 0 {
			t.Fatalf("expected no mint call on second invocation, got %d", atomic.LoadInt32(&mintCount))
		}
	})
}

func TestAutoMintSessionRenewsNearExpiryTokenInsteadOfMinting(t *testing.T) {
	role := "deploy-role"

	var mintCount, renewCount int32
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/session/mint":
			atomic.AddInt32(&mintCount, 1)
			w.WriteHeader(http.StatusUnauthorized)
		case "/v1/session/renew":
			atomic.AddInt32(&renewCount, 1)
			resp := map[string]interface{}{
				"session_token": "phxs_renewed-token",
				"expires_at":    time.Now().Add(30 * time.Minute).Format(time.RFC3339),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}
	}, func() {
		t.Setenv("PHOENIX_ROLE", role)
		t.Setenv("HOME", t.TempDir())
		t.Setenv("PHOENIX_TOKEN", "bootstrap-token")
		token = "bootstrap-token"

		cache := map[string]*tokenCacheEntry{
			sessionCacheKey(role): {
				Token:     "phxs_near-expiry",
				Agent:     "session:" + role,
				ExpiresAt: time.Now().Add(2 * time.Minute),
			},
		}
		if err := saveTokenCache(cache); err != nil {
			t.Fatalf("saveTokenCache: %v", err)
		}

		if err := requireAuth(); err != nil {
			t.Fatalf("requireAuth: %v", err)
		}
		if atomic.LoadInt32(&mintCount) != 0 {
			t.Fatalf("expected no mint call, got %d", atomic.LoadInt32(&mintCount))
		}
		if atomic.LoadInt32(&renewCount) != 1 {
			t.Fatalf("expected one renew call, got %d", atomic.LoadInt32(&renewCount))
		}
		if token != "phxs_renewed-token" {
			t.Fatalf("token = %q, want renewed token", token)
		}
	})
}

func TestCmdGetUsesRoleSessionSealKey(t *testing.T) {
	role := "deploy-role"
	kp, err := crypto.GenerateSealKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	home := t.TempDir()
	keyPath := filepath.Join(home, ".phoenix", "session-seal-"+role+".key")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(crypto.EncodeSealKey(&kp.PrivateKey)), 0600); err != nil {
		t.Fatal(err)
	}

	hdrPublic := crypto.EncodeSealKey(&kp.PublicKey)

	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/session/mint":
			resp := map[string]string{
				"session_token": "phxs_session",
				"expires_at":    time.Now().Add(30 * time.Minute).Format(time.RFC3339),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		case "/v1/secrets/ns/secret":
			if got := r.Header.Get("X-Phoenix-Seal-Key"); got != hdrPublic {
				t.Fatalf("expected X-Phoenix-Seal-Key %q, got %q", hdrPublic, got)
			}
			pub, err := crypto.DecodeSealKey(r.Header.Get("X-Phoenix-Seal-Key"))
			if err != nil {
				t.Fatalf("decode request seal key: %v", err)
			}
			env, _ := crypto.SealValue("ns/secret", "", "hello", pub)
			json.NewEncoder(w).Encode(map[string]interface{}{"sealed_value": env})
		default:
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
	}, func() {
		t.Setenv("PHOENIX_ROLE", role)
		t.Setenv("HOME", home)
		t.Setenv("PHOENIX_TOKEN", "bootstrap-token")
		token = "bootstrap-token"

		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := cmdGet([]string{"ns/secret"})

		w.Close()
		os.Stdout = oldStdout
		if err != nil {
			t.Fatalf("cmdGet: %v", err)
		}

		out, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("read stdout: %v", err)
		}
		if got := string(out); got != "hello" {
			t.Fatalf("output = %q, want hello", got)
		}
	})
}

func TestCmdListUsesRoleSessionSealKey(t *testing.T) {
	role := "deploy-role"
	kp, err := crypto.GenerateSealKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	home := t.TempDir()
	keyPath := filepath.Join(home, ".phoenix", "session-seal-"+role+".key")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(crypto.EncodeSealKey(&kp.PrivateKey)), 0600); err != nil {
		t.Fatal(err)
	}

	hdrPublic := crypto.EncodeSealKey(&kp.PublicKey)

	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/session/mint":
			resp := map[string]string{
				"session_token": "phxs_session",
				"expires_at":    time.Now().Add(30 * time.Minute).Format(time.RFC3339),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		case "/v1/secrets/":
			if got := r.Header.Get("X-Phoenix-Seal-Key"); got != hdrPublic {
				t.Fatalf("expected X-Phoenix-Seal-Key %q, got %q", hdrPublic, got)
			}
			json.NewEncoder(w).Encode(map[string][]string{"paths": []string{"foo", "bar"}})
		default:
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
	}, func() {
		t.Setenv("PHOENIX_ROLE", role)
		t.Setenv("HOME", home)
		t.Setenv("PHOENIX_TOKEN", "bootstrap-token")
		token = "bootstrap-token"

		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := cmdList(nil)

		w.Close()
		os.Stdout = oldStdout
		if err != nil {
			t.Fatalf("cmdList: %v", err)
		}

		out, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("read stdout: %v", err)
		}
		output := string(out)
		if !strings.Contains(output, "foo") || !strings.Contains(output, "bar") {
			t.Fatalf("output = %q, want list containing foo and bar", output)
		}
	})
}
