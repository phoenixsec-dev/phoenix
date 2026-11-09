package main

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// remintFixture is a mock server for the re-mint tests. Secret requests made
// with a token listed in dead get 401 with deadCode; others succeed. Mint
// returns phxs_fresh and records the Authorization it was called with.
type remintFixture struct {
	mu        sync.Mutex
	dead      map[string]bool
	deadCode  string
	mints     int
	mintAuth  []string
	calls     int
	callBodies []string
}

func (f *remintFixture) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if r.URL.Path == "/v1/session/mint" {
		f.mints++
		f.mintAuth = append(f.mintAuth, auth)
		w.Write([]byte(`{"session_token":"phxs_fresh","expires_at":"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `"}`))
		return
	}
	f.calls++
	b, _ := io.ReadAll(r.Body)
	f.callBodies = append(f.callBodies, string(b))
	if f.dead[auth] {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"access_denied","code":"` + f.deadCode + `","detail":"x","next_step":"remint_session"}`))
		return
	}
	w.Write([]byte(`{"ok":true}`))
}

// setupCachedSession points the CLI at a role whose cached session is phxs_old.
func setupCachedSession(t *testing.T, role string) {
	t.Helper()
	t.Setenv("PHOENIX_ROLE", role)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PHOENIX_TOKEN", "bootstrap-token")
	token = "bootstrap-token"
	cacheSessionToken(role, "phxs_old", time.Now().Add(50*time.Minute))
	if err := requireAuth(); err != nil {
		t.Fatalf("requireAuth: %v", err)
	}
	if token != "phxs_old" {
		t.Fatalf("token = %q, want cached phxs_old", token)
	}
}

// After a server restart with an old server, the cached session is dead:
// one re-mint with PHOENIX_TOKEN, one retry with the same body, then success.
func TestRemintOnceAfterSessionInvalid(t *testing.T) {
	f := &remintFixture{dead: map[string]bool{"phxs_old": true}, deadCode: "SESSION_INVALID"}
	withMockServer(t, f.handler, func() {
		setupCachedSession(t, "r1")
		resp, err := apiRequest("POST", "/v1/resolve", strings.NewReader(`{"refs":["a"]}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("status %d after re-mint, want 200", resp.StatusCode)
		}
		if f.mints != 1 || f.mintAuth[0] != "bootstrap-token" {
			t.Errorf("mints = %d with %v, want 1 with bootstrap-token", f.mints, f.mintAuth)
		}
		if f.calls != 2 || f.callBodies[1] != `{"refs":["a"]}` {
			t.Errorf("calls = %d bodies %q, want the request retried once with its body", f.calls, f.callBodies)
		}
		if got := getCachedSessionToken("r1", 0); got != "phxs_fresh" {
			t.Errorf("cache = %q, want phxs_fresh", got)
		}
		if token != "phxs_fresh" {
			t.Errorf("token = %q, want phxs_fresh", token)
		}
	})
}

// If the fresh session fails too, the CLI returns that failure. No loop.
func TestRemintGivesUpAfterSecondFailure(t *testing.T) {
	f := &remintFixture{dead: map[string]bool{"phxs_old": true, "phxs_fresh": true}, deadCode: "SESSION_INVALID"}
	withMockServer(t, f.handler, func() {
		setupCachedSession(t, "r2")
		resp, err := apiRequest("GET", "/v1/secrets/a", nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 401 || !strings.Contains(string(body), "SESSION_INVALID") {
			t.Fatalf("got %d %s, want the second 401 SESSION_INVALID", resp.StatusCode, body)
		}
		if f.mints != 1 || f.calls != 2 {
			t.Errorf("mints = %d calls = %d, want 1 and 2", f.mints, f.calls)
		}
	})
}

// A revoked session is not silently replaced in the same run, but its cache
// entry is dropped so the next run mints a new one.
func TestRevokedSessionNotRetried(t *testing.T) {
	f := &remintFixture{dead: map[string]bool{"phxs_old": true}, deadCode: "SESSION_REVOKED"}
	withMockServer(t, f.handler, func() {
		setupCachedSession(t, "r3")
		resp, err := apiRequest("GET", "/v1/secrets/a", nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 401 || !strings.Contains(string(body), "SESSION_REVOKED") {
			t.Fatalf("got %d %s, want 401 SESSION_REVOKED passed through", resp.StatusCode, body)
		}
		if f.mints != 0 || f.calls != 1 {
			t.Errorf("mints = %d calls = %d, want 0 and 1", f.mints, f.calls)
		}
		if got := getCachedSessionToken("r3", 0); got != "" {
			t.Errorf("revoked session still cached: %q", got)
		}
	})
}
