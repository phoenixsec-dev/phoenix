package api

import (
	"bytes"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/session"
)

// serverWithSavedSessions builds a test server whose session store is opened
// from path with a fixed derived key, the way phoenix-server does at start.
// Calling it twice with the same path is a server restart.
func serverWithSavedSessions(t *testing.T, path string) (*Server, *session.Store, string) {
	t.Helper()
	srv, adminToken := setupTestServer(t)
	key, err := session.DeriveSigningKey(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ss, err := session.OpenStore(session.Options{TTL: time.Hour, SigningKey: key, Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ss.Stop)
	srv.SetSessionStore(ss)
	srv.SetSessionRoles(map[string]config.RoleConfig{
		"dev": {Namespaces: []string{"test/*"}, BootstrapTrust: []string{"bearer"}},
	})
	return srv, ss, adminToken
}

// renewWith calls /v1/session/renew with tok and returns status and body.
func renewWith(srv *Server, tok string) (int, string) {
	req := httptest.NewRequest("POST", "/v1/session/renew", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func TestSessionWorksAfterServerRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "role-sessions.json")
	before, _, admin := serverWithSavedSessions(t, path)
	tok := mintTestSession(t, before, admin, "dev")

	after, _, _ := serverWithSavedSessions(t, path)
	if code, body := renewWith(after, tok); code != 200 {
		t.Fatalf("session from before restart: %d %s", code, body)
	}
}

func TestRevokedSessionStaysRevokedAfterServerRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "role-sessions.json")
	before, ss, admin := serverWithSavedSessions(t, path)
	tok := mintTestSession(t, before, admin, "dev")
	for _, s := range ss.List() {
		if err := ss.Revoke(s.ID); err != nil {
			t.Fatal(err)
		}
	}

	after, _, _ := serverWithSavedSessions(t, path)
	code, body := renewWith(after, tok)
	if code == 200 || !strings.Contains(body, "SESSION_REVOKED") {
		t.Fatalf("revoked session after restart: %d %s, want SESSION_REVOKED", code, body)
	}
}
