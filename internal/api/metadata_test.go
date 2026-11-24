package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/store"
)

// putSecret stores a secret through the API as the given token.
func putSecret(t *testing.T, srv *Server, token, path string, req setSecretRequest) map[string]interface{} {
	t.Helper()
	body, _ := json.Marshal(req)
	r := httptest.NewRequest("PUT", "/v1/secrets/"+path, bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT %s: %d %s", path, w.Code, w.Body.String())
	}
	var resp map[string]interface{}
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

// PUT says whether the secret ends up with a description; `phoenix set`
// nudges on it. Never the text, and only to callers who may list the path.
func TestSetReportsHasDescription(t *testing.T) {
	srv, admin := setupTestServer(t)
	resp := putSecret(t, srv, admin, "test/a", setSecretRequest{Value: "v1", Description: "private first"})
	if resp["has_description"] != true {
		t.Fatalf("want has_description true: %v", resp)
	}
	resp = putSecret(t, srv, admin, "test/a", setSecretRequest{Value: "v2"})
	if resp["has_description"] != true {
		t.Fatalf("update without -d keeps the old description: %v", resp)
	}
	resp = putSecret(t, srv, admin, "test/b", setSecretRequest{Value: "v"})
	if resp["has_description"] != false {
		t.Fatalf("want has_description false: %v", resp)
	}

	// R1-1: a writer without list learns nothing about the description.
	if err := srv.acl.AddAgent("writer", "writer-token", []acl.Permission{{Path: "test/*", Actions: []acl.Action{acl.ActionWrite}}}); err != nil {
		t.Fatal(err)
	}
	resp = putSecret(t, srv, "writer-token", "test/a", setSecretRequest{Value: "v3"})
	if _, ok := resp["has_description"]; ok {
		t.Fatalf("write-only caller got description info: %v", resp)
	}
	for _, v := range resp {
		if s, _ := v.(string); strings.Contains(s, "private first") {
			t.Fatalf("write-only caller got the description: %v", resp)
		}
	}
}

// countingBackend counts List calls, to pin one backend scan per request.
type countingBackend struct {
	stubBackend
	lists int
}

func (b *countingBackend) List(prefix string) ([]string, error) {
	b.lists++
	return b.stubBackend.List(prefix)
}

// R1-2: listing metadata must not rescan the backend per secret (a scan
// is a full 1Password vault walk).
func TestMetadataScansBackendOncePerRequest(t *testing.T) {
	b := &countingBackend{stubBackend: stubBackend{secrets: map[string]*store.Secret{
		"ns/a": {Path: "ns/a"}, "ns/b": {Path: "ns/b"}, "ns/c": {Path: "ns/c"},
	}}}
	srv, token := setupStubServer(t, b)
	if code, body := getMetadata(srv, token, ""); code != http.StatusOK || strings.Count(body, `"path"`) != 3 {
		t.Fatalf("list: %d %s", code, body)
	}
	if b.lists != 1 {
		t.Fatalf("list request made %d backend scans, want 1", b.lists)
	}
	b.lists = 0
	if code, _ := getMetadata(srv, token, "ns/a"); code != http.StatusOK || b.lists != 1 {
		t.Fatalf("info: code %d, %d scans, want 200 and 1", code, b.lists)
	}
	if code, _ := getMetadata(srv, token, "ns/zz"); code != http.StatusNotFound {
		t.Fatalf("missing path: want 404, got %d", code)
	}
}

// patchMetadata calls PATCH /v1/metadata/<path> with a raw JSON body.
func patchMetadata(srv *Server, token, path, body string) (int, string) {
	r := httptest.NewRequest("PATCH", "/v1/metadata/"+path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

// Write permission is enough to describe a secret and nothing less is. The
// reply and the audit line carry field names only.
func TestDescribeSecret(t *testing.T) {
	srv, admin := setupTestServer(t)
	srv.acl.AddAgent("writeonly", "writeonly-token", []acl.Permission{{Path: "test/*", Actions: []acl.Action{acl.ActionWrite}}})
	putSecret(t, srv, admin, "test/a", setSecretRequest{Value: "the-value", Description: "old"})

	code, body := patchMetadata(srv, "writeonly-token", "test/a", `{"description":"new text","username":"me@example.com","url":"https://example.com/x"}`)
	if code != http.StatusOK || strings.Contains(body, "new text") || strings.Contains(body, "me@example.com") || strings.Contains(body, "the-value") {
		t.Fatalf("describe: %d %s", code, body)
	}
	if code, _ := patchMetadata(srv, "reader-token", "test/a", `{"description":"no"}`); code != http.StatusForbidden {
		t.Fatalf("reader could describe: %d", code)
	}
	var si secretInfo
	_, body = getMetadata(srv, admin, "test/a")
	json.Unmarshal([]byte(body), &si)
	if si.Description != "new text" || si.Username != "me@example.com" || si.URL != "https://example.com/x" ||
		si.CreatedBy != "admin" || si.UpdatedBy != "admin" {
		t.Fatalf("after describe: %s", body)
	}

	for body, want := range map[string]int{
		`{}`:                            http.StatusBadRequest,
		`{"value":"x"}`:                 http.StatusBadRequest,
		`{"url":"javascript:alert(1)"}`: http.StatusBadRequest,
		`{"description":"x"} {"description":"y"}`: http.StatusBadRequest,
		`{"description":"x"} junk`:                http.StatusBadRequest,
		`nonsense`:                                http.StatusBadRequest,
	} {
		if code, got := patchMetadata(srv, admin, "test/a", body); code != want {
			t.Errorf("%s: %d %s", body, code, got)
		}
	}
	if code, _ := patchMetadata(srv, admin, "test/missing", `{"description":"x"}`); code != http.StatusNotFound {
		t.Errorf("missing secret: %d", code)
	}

	entries, raw := queryAPIAuditEntries(t, srv, admin)
	if e := findAPIAuditEntry(entries, "describe", "test/a", "allowed", ""); e == nil || e.Agent != "writeonly" || e.Metadata["changed"] != "description,username,url" {
		t.Errorf("describe audit entry = %+v", e)
	}
	if strings.Contains(raw, "new text") || strings.Contains(raw, "me@example.com") {
		t.Error("the audit log holds metadata text")
	}
}

// The login is for callers who may list the path: it never travels with the
// value, and a value write without it keeps it.
func TestLoginIsNeverMixedWithTheValue(t *testing.T) {
	srv, admin := setupTestServer(t)
	user, link := "me@example.com", "https://example.com/x"
	putSecret(t, srv, admin, "test/a", setSecretRequest{Value: "v1", Username: &user, URL: &link})
	putSecret(t, srv, admin, "test/a", setSecretRequest{Value: "v2"})

	r := httptest.NewRequest("GET", "/v1/secrets/test/a", nil)
	r.Header.Set("Authorization", "Bearer "+admin)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if body := w.Body.String(); !strings.Contains(body, "v2") || strings.Contains(body, user) || strings.Contains(body, link) {
		t.Fatalf("value read: %s", body)
	}
	if _, body := getMetadata(srv, admin, "test/a"); !strings.Contains(body, user) || !strings.Contains(body, link) {
		t.Fatalf("login lost on a value write: %s", body)
	}

	bad := "javascript:alert(1)"
	body, _ := json.Marshal(setSecretRequest{Value: "v3", URL: &bad})
	r = httptest.NewRequest("PUT", "/v1/secrets/test/a", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+admin)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad link accepted: %d", w.Code)
	}
}
