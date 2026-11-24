package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/api"
	"github.com/phoenixsec/phoenix/internal/audit"
	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/session"
	"github.com/phoenixsec/phoenix/internal/store"
)

// realRoleServer is a real Phoenix API server with role "dev", an admin, and
// an agent "worker" (token "old-token") that may read test/*.
func realRoleServer(t *testing.T) *api.Server {
	t.Helper()
	dir := t.TempDir()
	st, err := store.New(filepath.Join(dir, "store.json"), bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Set("test/a", "synthetic-value", "admin", "", nil); err != nil {
		t.Fatal(err)
	}
	a := acl.NewFromConfig(&acl.ACLConfig{Agents: map[string]acl.Agent{}})
	for name, perm := range map[string]acl.Permission{
		"admin":  {Path: "*", Actions: []acl.Action{acl.ActionAdmin}},
		"worker": {Path: "test/*", Actions: []acl.Action{acl.ActionReadValue}},
	} {
		tok := map[string]string{"admin": "admin-token", "worker": "old-token"}[name]
		if err := a.AddAgent(name, tok, []acl.Permission{perm}); err != nil {
			t.Fatal(err)
		}
	}
	al, err := audit.NewLogger(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	srv := api.NewServer(store.NewFileBackend(st), a, al, filepath.Join(dir, "audit.log"))
	ss, err := session.NewStore(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ss.Stop)
	if err := srv.SetSessionStore(ss); err != nil {
		t.Fatal(err)
	}
	srv.SetSessionRoles(map[string]config.RoleConfig{"dev": {Namespaces: []string{"test/*"}, BootstrapTrust: []string{"bearer"}}})
	return srv
}

// After the agent's token is replaced and PHOENIX_TOKEN holds the new one, the
// CLI and the MCP server get past their dead cached session on their own.
func TestRoleSessionRecoversAfterOwnTokenReplaced(t *testing.T) {
	callers := map[string]func(t *testing.T) string{
		"cli": func(t *testing.T) string {
			resp, err := apiRequest("GET", "/v1/secrets/test/a", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return string(b)
		},
		"mcp": func(t *testing.T) string {
			var out bytes.Buffer
			mcpHandleRequest(mcpRequest{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/call",
				Params: json.RawMessage(`{"name":"phoenix_get","arguments":{"path":"test/a"}}`)},
				json.NewEncoder(&out), log.New(os.Stderr, "", 0))
			return out.String()
		},
	}
	for name, read := range callers {
		for _, how := range []string{"force", "delete and create"} {
			t.Run(name+" "+how, func(t *testing.T) {
				srv := realRoleServer(t)
				withMockServer(t, func(w http.ResponseWriter, r *http.Request) { srv.ServeHTTP(w, r) }, func() {
					t.Setenv("HOME", t.TempDir())
					t.Setenv("PHOENIX_ROLE", "dev")
					t.Setenv("PHOENIX_TOKEN", "old-token")
					token = "old-token"
					if err := requireAuth(); err != nil {
						t.Fatal(err)
					}
					first := currentToken()
					if got := read(t); !strings.Contains(got, "synthetic-value") {
						t.Fatalf("before: %s", got)
					}

					admin := func(method, path, body string) {
						resp, err := sendAPIRequest(t.Context(), "admin-token", method, path, []byte(body), true, nil)
						if err != nil {
							t.Fatal(err)
						}
						resp.Body.Close()
						if resp.StatusCode != 200 {
							t.Fatalf("%s %s: %d", method, path, resp.StatusCode)
						}
					}
					if how != "force" {
						admin("DELETE", "/v1/agents/worker", "")
					}
					admin("POST", "/v1/agents?force=true", `{"name":"worker","token":"new-token","permissions":[{"path":"test/*","actions":["read_value"]}]}`)

					t.Setenv("PHOENIX_TOKEN", "new-token")
					if got := read(t); !strings.Contains(got, "synthetic-value") {
						t.Errorf("after the token was replaced: %s", got)
					}
					if now := currentToken(); now == first || !strings.HasPrefix(now, "phxs_") {
						t.Error("the dead session was not replaced by a new one")
					}
				})
			})
		}
	}
}
