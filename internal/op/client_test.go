package op

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeFakeOP creates a shell script that mimics the op CLI.
// It returns the path to the script.
func writeFakeOP(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "op")
	content := "#!/bin/sh\n" + script
	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		t.Fatalf("writing fake op: %v", err)
	}
	return path
}

func TestAvailableSuccess(t *testing.T) {
	fakeOP := writeFakeOP(t, `echo "ok"`)
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "test-token-value")

	c := New("", WithOPPath(fakeOP))
	if err := c.Available(); err != nil {
		t.Fatalf("Available() should succeed: %v", err)
	}
}

func TestAvailableMissingBinary(t *testing.T) {
	c := New("", WithOPPath("/nonexistent/op-binary-xyz"))
	err := c.Available()
	if err == nil {
		t.Fatal("Available() should fail with missing binary")
	}
	if !errors.Is(err, ErrNotAvailable) {
		t.Fatalf("expected ErrNotAvailable, got: %v", err)
	}
}

func TestAvailableMissingToken(t *testing.T) {
	fakeOP := writeFakeOP(t, `echo "ok"`)
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "")

	c := New("OP_SERVICE_ACCOUNT_TOKEN", WithOPPath(fakeOP))
	err := c.Available()
	if err == nil {
		t.Fatal("Available() should fail with missing token")
	}
	if !errors.Is(err, ErrTokenMissing) {
		t.Fatalf("expected ErrTokenMissing, got: %v", err)
	}
}

func TestReadSuccess(t *testing.T) {
	fakeOP := writeFakeOP(t, `echo "my-secret-value"`)
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "test-token")

	c := New("", WithOPPath(fakeOP))
	val, err := c.Read("op://Vault/Item/Field")
	if err != nil {
		t.Fatalf("Read() failed: %v", err)
	}
	if val != "my-secret-value" {
		t.Fatalf("expected 'my-secret-value', got %q", val)
	}
}

func TestReadNotFound(t *testing.T) {
	fakeOP := writeFakeOP(t, `echo "\"Item\" isn't an item in vault" >&2; exit 1`)
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "test-token")

	c := New("", WithOPPath(fakeOP))
	_, err := c.Read("op://Vault/Nonexistent/Field")
	if err == nil {
		t.Fatal("Read() should fail for missing item")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestReadPermissionDenied(t *testing.T) {
	fakeOP := writeFakeOP(t, `echo "unauthorized: Authentication required" >&2; exit 1`)
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "test-token")

	c := New("", WithOPPath(fakeOP))
	_, err := c.Read("op://Vault/Item/Field")
	if err == nil {
		t.Fatal("Read() should fail for permission denied")
	}
	if !errors.Is(err, ErrPermission) {
		t.Fatalf("expected ErrPermission, got: %v", err)
	}
}

func TestReadTimeout(t *testing.T) {
	fakeOP := writeFakeOP(t, `sleep 10`)
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "test-token")

	c := New("", WithOPPath(fakeOP), WithTimeout(100*time.Millisecond))
	_, err := c.Read("op://Vault/Item/Field")
	if err == nil {
		t.Fatal("Read() should fail on timeout")
	}
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("expected ErrTimeout, got: %v", err)
	}
}

func TestReadTokenRedacted(t *testing.T) {
	secretToken := "ops_SUPERSECRETTOKEN123"
	fakeOP := writeFakeOP(t, `echo "error with ops_SUPERSECRETTOKEN123 in output" >&2; exit 1`)
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", secretToken)

	c := New("", WithOPPath(fakeOP))
	_, err := c.Read("op://Vault/Item/Field")
	if err == nil {
		t.Fatal("Read() should fail")
	}
	errMsg := err.Error()
	if contains(errMsg, secretToken) {
		t.Fatalf("error message should not contain token, got: %s", errMsg)
	}
	if !contains(errMsg, "[REDACTED]") {
		t.Fatalf("error message should contain [REDACTED], got: %s", errMsg)
	}
}

func TestListVaults(t *testing.T) {
	fakeOP := writeFakeOP(t, `echo '[{"id":"abc","name":"Engineering"},{"id":"def","name":"Personal"}]'`)
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "test-token")

	c := New("", WithOPPath(fakeOP))
	vaults, err := c.ListVaults()
	if err != nil {
		t.Fatalf("ListVaults() failed: %v", err)
	}
	if len(vaults) != 2 {
		t.Fatalf("expected 2 vaults, got %d", len(vaults))
	}
	if vaults[0].Name != "Engineering" {
		t.Fatalf("expected 'Engineering', got %q", vaults[0].Name)
	}
}

func TestListItems(t *testing.T) {
	fakeOP := writeFakeOP(t, `echo '[{"id":"item1","title":"Database Creds","category":"LOGIN"},{"id":"item2","title":"API Key","category":"PASSWORD"}]'`)
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "test-token")

	c := New("", WithOPPath(fakeOP))
	items, err := c.ListItems("Engineering")
	if err != nil {
		t.Fatalf("ListItems() failed: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
	if items[0].Title != "Database Creds" {
		t.Fatalf("expected 'Database Creds', got %q", items[0].Title)
	}
}

func TestGetItem(t *testing.T) {
	itemJSON := `{
		"id": "item1",
		"title": "Database Creds",
		"vault": {"id": "v1", "name": "Engineering"},
		"category": "LOGIN",
		"fields": [
			{"id": "f1", "type": "STRING", "label": "username", "value": "admin"},
			{"id": "f2", "type": "CONCEALED", "label": "password", "value": "hunter2"}
		]
	}`
	fakeOP := writeFakeOP(t, `echo '`+itemJSON+`'`)
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "test-token")

	c := New("", WithOPPath(fakeOP))
	item, err := c.GetItem("Engineering", "item1")
	if err != nil {
		t.Fatalf("GetItem() failed: %v", err)
	}
	if item.Title != "Database Creds" {
		t.Fatalf("expected 'Database Creds', got %q", item.Title)
	}
	if len(item.Fields) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(item.Fields))
	}
	if item.Fields[1].Value != "hunter2" {
		t.Fatalf("expected 'hunter2', got %q", item.Fields[1].Value)
	}
}

func TestCustomTokenEnv(t *testing.T) {
	fakeOP := writeFakeOP(t, `echo "ok"`)
	t.Setenv("MY_CUSTOM_TOKEN", "test-token")

	c := New("MY_CUSTOM_TOKEN", WithOPPath(fakeOP))
	if err := c.Available(); err != nil {
		t.Fatalf("Available() with custom token env should succeed: %v", err)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
