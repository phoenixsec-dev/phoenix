package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// putSecret stores a secret through the API as the given token.
func putSecret(t *testing.T, srv *Server, token, path string, req setSecretRequest) map[string]string {
	t.Helper()
	body, _ := json.Marshal(req)
	r := httptest.NewRequest("PUT", "/v1/secrets/"+path, bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT %s: %d %s", path, w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	return resp
}

// getMetadata calls GET /v1/metadata/<path> and returns the status and raw body.
func getMetadata(srv *Server, token, path string) (int, string) {
	r := httptest.NewRequest("GET", "/v1/metadata/"+path, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

func TestMetadataNeverReturnsValue(t *testing.T) {
	srv, admin := setupTestServer(t)
	putSecret(t, srv, admin, "test/a", setSecretRequest{Value: "s3cret-value-xyz", Description: "the A key", Tags: []string{"mail"}})

	for _, p := range []string{"", "test/", "test/a"} {
		code, body := getMetadata(srv, admin, p)
		if code != http.StatusOK {
			t.Fatalf("%q: %d %s", p, code, body)
		}
		if strings.Contains(body, "s3cret-value-xyz") || strings.Contains(body, `"value"`) {
			t.Fatalf("%q: metadata response leaked the value: %s", p, body)
		}
		if !strings.Contains(body, "the A key") {
			t.Fatalf("%q: description missing: %s", p, body)
		}
	}

	var one secretInfo
	_, body := getMetadata(srv, admin, "test/a")
	json.Unmarshal([]byte(body), &one)
	if one.Path != "test/a" || one.CreatedBy != "admin" || one.UpdatedBy != "admin" ||
		one.Created == nil || one.Updated == nil || len(one.Tags) != 1 || one.Tags[0] != "mail" {
		t.Fatalf("unexpected info: %+v", one)
	}
}

func TestMetadataRespectsACL(t *testing.T) {
	srv, admin := setupTestServer(t)
	putSecret(t, srv, admin, "test/a", setSecretRequest{Value: "v", Description: "visible"})
	putSecret(t, srv, admin, "other/c", setSecretRequest{Value: "v", Description: "hidden one"})

	_, body := getMetadata(srv, "reader-token", "")
	if !strings.Contains(body, "visible") || strings.Contains(body, "hidden one") {
		t.Fatalf("reader list should show only test/*: %s", body)
	}

	// Single path outside the ACL is denied whether or not it exists.
	for _, p := range []string{"other/c", "other/missing"} {
		if code, body := getMetadata(srv, "reader-token", p); code != http.StatusForbidden || strings.Contains(body, "hidden one") {
			t.Fatalf("%s: want 403 without metadata, got %d %s", p, code, body)
		}
	}
	if code, _ := getMetadata(srv, "reader-token", "test/missing"); code != http.StatusNotFound {
		t.Fatalf("missing allowed path: want 404, got %d", code)
	}

	// Audited as list, allowed and denied.
	entries, _ := queryAPIAuditEntries(t, srv, admin)
	if findAPIAuditEntry(entries, "list", "", "allowed", "") == nil {
		t.Error("no allowed list audit entry for the metadata list")
	}
	if findAPIAuditEntry(entries, "list", "other/c", "denied", "acl") == nil {
		t.Error("no denied list audit entry for other/c")
	}
}

func TestMetadataTagFilter(t *testing.T) {
	srv, admin := setupTestServer(t)
	putSecret(t, srv, admin, "test/a", setSecretRequest{Value: "v", Tags: []string{"mail", "prod"}})
	putSecret(t, srv, admin, "test/b", setSecretRequest{Value: "v", Tags: []string{"prod"}})
	putSecret(t, srv, admin, "test/c", setSecretRequest{Value: "v"})

	_, body := getMetadata(srv, admin, "?tag=mail")
	var resp struct {
		Secrets []secretInfo `json:"secrets"`
	}
	json.Unmarshal([]byte(body), &resp)
	if len(resp.Secrets) != 1 || resp.Secrets[0].Path != "test/a" {
		t.Fatalf("tag=mail: %s", body)
	}
	_, body = getMetadata(srv, admin, "?tag=nope")
	if !strings.Contains(body, `"secrets":[]`) {
		t.Fatalf("no match should be an empty array: %s", body)
	}
}

// PUT returns the description stored after the write; `phoenix set` nudges
// on it.
func TestSetEchoesStoredDescription(t *testing.T) {
	srv, admin := setupTestServer(t)
	resp := putSecret(t, srv, admin, "test/a", setSecretRequest{Value: "v1", Description: "first"})
	if resp["description"] != "first" {
		t.Fatalf("PUT should echo the stored description: %v", resp)
	}
	resp = putSecret(t, srv, admin, "test/a", setSecretRequest{Value: "v2"})
	if resp["description"] != "first" {
		t.Fatalf("update without -d should keep and echo the old description: %v", resp)
	}
	resp = putSecret(t, srv, admin, "test/b", setSecretRequest{Value: "v"})
	if d, ok := resp["description"]; !ok || d != "" {
		t.Fatalf("PUT should return an empty description field when there is none: %v", resp)
	}
}
