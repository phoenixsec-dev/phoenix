package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/phoenixsec/phoenix/internal/op"
)

// writeFakeOP creates a shell script that mimics the op CLI.
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

func TestOPBackendGet(t *testing.T) {
	fakeOP := writeFakeOP(t, `echo "secret-value-123"`)
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "test-token")

	client := op.New("", op.WithOPPath(fakeOP))
	backend := NewOPBackend(client, "Engineering", 0)

	secret, err := backend.Get("myapp/api-key")
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}
	if secret.Value != "secret-value-123" {
		t.Fatalf("expected 'secret-value-123', got %q", secret.Value)
	}
	if secret.Path != "myapp/api-key" {
		t.Fatalf("expected path 'myapp/api-key', got %q", secret.Path)
	}
}

func TestOPBackendGetNotFound(t *testing.T) {
	fakeOP := writeFakeOP(t, `echo "\"myapp\" isn't an item in vault" >&2; exit 1`)
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "test-token")

	client := op.New("", op.WithOPPath(fakeOP))
	backend := NewOPBackend(client, "Engineering", 0)

	_, err := backend.Get("myapp/api-key")
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("expected ErrSecretNotFound, got: %v", err)
	}
}

func TestOPBackendGetInvalidPath(t *testing.T) {
	client := op.New("")
	backend := NewOPBackend(client, "Engineering", 0)

	_, err := backend.Get("no-slash")
	if !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("expected ErrInvalidPath, got: %v", err)
	}
}

func TestOPBackendCacheHit(t *testing.T) {
	// First call returns value, second call would fail — but cache should serve.
	callCount := 0
	dir := t.TempDir()
	counterFile := filepath.Join(dir, "count")
	os.WriteFile(counterFile, []byte("0"), 0644)

	// Script that returns a value only on first call.
	fakeOP := writeFakeOP(t, `
COUNT=$(cat `+counterFile+`)
COUNT=$((COUNT + 1))
echo $COUNT > `+counterFile+`
if [ "$COUNT" -eq 1 ]; then
  echo "cached-value"
else
  echo "should not be called" >&2
  exit 1
fi
`)
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "test-token")

	client := op.New("", op.WithOPPath(fakeOP))
	backend := NewOPBackend(client, "Vault", 5*time.Minute)

	// First call — populates cache
	s1, err := backend.Get("ns/key")
	if err != nil {
		t.Fatalf("first Get() failed: %v", err)
	}
	if s1.Value != "cached-value" {
		t.Fatalf("expected 'cached-value', got %q", s1.Value)
	}

	// Second call — should come from cache
	s2, err := backend.Get("ns/key")
	if err != nil {
		t.Fatalf("second Get() failed (should hit cache): %v", err)
	}
	if s2.Value != "cached-value" {
		t.Fatalf("expected 'cached-value' from cache, got %q", s2.Value)
	}

	// Verify op was only called once
	countData, _ := os.ReadFile(counterFile)
	_ = callCount
	if string(countData) != "1\n" {
		t.Fatalf("expected op to be called once, counter file: %q", string(countData))
	}
}

func TestOPBackendCacheExpiry(t *testing.T) {
	dir := t.TempDir()
	counterFile := filepath.Join(dir, "count")
	os.WriteFile(counterFile, []byte("0"), 0644)

	fakeOP := writeFakeOP(t, `
COUNT=$(cat `+counterFile+`)
COUNT=$((COUNT + 1))
echo $COUNT > `+counterFile+`
echo "value-$COUNT"
`)
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "test-token")

	client := op.New("", op.WithOPPath(fakeOP))
	backend := NewOPBackend(client, "Vault", 50*time.Millisecond)

	// First call
	s1, err := backend.Get("ns/key")
	if err != nil {
		t.Fatalf("first Get() failed: %v", err)
	}
	if s1.Value != "value-1" {
		t.Fatalf("expected 'value-1', got %q", s1.Value)
	}

	// Wait for cache to expire
	time.Sleep(100 * time.Millisecond)

	// Second call — cache expired, should call op again
	s2, err := backend.Get("ns/key")
	if err != nil {
		t.Fatalf("second Get() failed: %v", err)
	}
	if s2.Value != "value-2" {
		t.Fatalf("expected 'value-2' after cache expiry, got %q", s2.Value)
	}
}

func TestOPBackendSetDeleteReadOnly(t *testing.T) {
	client := op.New("")
	backend := NewOPBackend(client, "Vault", 0)

	if err := backend.Set("ns/key", "v", "agent", "", nil); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("Set should return ErrReadOnly, got: %v", err)
	}
	if err := backend.Delete("ns/key"); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("Delete should return ErrReadOnly, got: %v", err)
	}
}

func TestOPBackendProperties(t *testing.T) {
	client := op.New("")
	backend := NewOPBackend(client, "Vault", 0)

	if !backend.ReadOnly() {
		t.Fatal("OPBackend should be read-only")
	}
	if backend.Name() != "1password" {
		t.Fatalf("expected name '1password', got %q", backend.Name())
	}
	if backend.Count() != -1 {
		t.Fatalf("expected count -1, got %d", backend.Count())
	}
}

func TestOPBackendList(t *testing.T) {
	// Realistic fake: `op item list` returns metadata-only (no fields),
	// `op item get <id>` returns the full item with fields populated.
	fakeOP := writeFakeOP(t, `
if [ "$1" = "item" ] && [ "$2" = "list" ]; then
  echo '[
    {"id":"i1","title":"Database Creds","category":"LOGIN"},
    {"id":"i2","title":"API Key","category":"PASSWORD"},
    {"id":"i3","title":"SSH Access","category":"SSH_KEY"}
  ]'
elif [ "$1" = "item" ] && [ "$2" = "get" ]; then
  case "$3" in
    i1)
      echo '{"id":"i1","title":"Database Creds","category":"LOGIN","vault":{"id":"v1"},"fields":[
        {"id":"f1","type":"STRING","label":"username","value":"admin"},
        {"id":"f2","type":"CONCEALED","label":"password","value":"pw"}
      ]}'
      ;;
    i2)
      echo '{"id":"i2","title":"API Key","category":"PASSWORD","vault":{"id":"v1"},"fields":[
        {"id":"f3","type":"CONCEALED","label":"key","value":"sk-123"}
      ]}'
      ;;
    *)
      echo "not found" >&2; exit 1
      ;;
  esac
else
  echo "unknown command" >&2; exit 1
fi
`)
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "test-token")

	client := op.New("", op.WithOPPath(fakeOP))
	backend := NewOPBackend(client, "Vault", 0)

	paths, err := backend.List("")
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}

	// SSH_KEY should be skipped (not even fetched). We expect:
	// database-creds/username, database-creds/password, api-key/key
	if len(paths) != 3 {
		t.Fatalf("expected 3 paths, got %d: %v", len(paths), paths)
	}

	// Test with prefix filter
	paths2, err := backend.List("database-creds/")
	if err != nil {
		t.Fatalf("List(prefix) failed: %v", err)
	}
	if len(paths2) != 2 {
		t.Fatalf("expected 2 paths with prefix, got %d: %v", len(paths2), paths2)
	}
}

func TestOPBackendListCache(t *testing.T) {
	// Verify that List() caches results and doesn't re-fetch.
	dir := t.TempDir()
	counterFile := filepath.Join(dir, "count")
	os.WriteFile(counterFile, []byte("0"), 0644)

	fakeOP := writeFakeOP(t, `
COUNT=$(cat `+counterFile+`)
COUNT=$((COUNT + 1))
echo $COUNT > `+counterFile+`
if [ "$1" = "item" ] && [ "$2" = "list" ]; then
  echo '[{"id":"i1","title":"Test Item","category":"LOGIN"}]'
elif [ "$1" = "item" ] && [ "$2" = "get" ]; then
  echo '{"id":"i1","title":"Test Item","category":"LOGIN","vault":{"id":"v1"},"fields":[
    {"id":"f1","type":"CONCEALED","label":"secret","value":"val"}
  ]}'
fi
`)
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "test-token")

	client := op.New("", op.WithOPPath(fakeOP))
	backend := NewOPBackend(client, "Vault", 5*time.Minute)

	// First list — fetches from op
	p1, err := backend.List("")
	if err != nil {
		t.Fatalf("first List() failed: %v", err)
	}
	if len(p1) != 1 {
		t.Fatalf("expected 1 path, got %d", len(p1))
	}

	// Second list — should come from cache (no additional op calls)
	p2, err := backend.List("")
	if err != nil {
		t.Fatalf("second List() failed: %v", err)
	}
	if len(p2) != 1 {
		t.Fatalf("expected 1 path from cache, got %d", len(p2))
	}

	// op was called twice for first list (item list + item get), zero for second
	countData, _ := os.ReadFile(counterFile)
	if string(countData) != "2\n" {
		t.Fatalf("expected op called 2 times total (list + get), counter: %q", string(countData))
	}
}

func TestSlugify(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Database Creds", "database-creds"},
		{"API Key", "api-key"},
		{"my_app", "my_app"},
		{"Hello World!", "hello-world"},
		{"Stripe (Live)", "stripe-live"},
		{"simple", "simple"},
	}
	for _, tc := range tests {
		got := slugify(tc.input)
		if got != tc.want {
			t.Errorf("slugify(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestSkipCategory(t *testing.T) {
	skip := []string{"SSH_KEY", "DOCUMENT", "CREDIT_CARD", "BANK_ACCOUNT"}
	keep := []string{"LOGIN", "PASSWORD", "API_CREDENTIAL", "SECURE_NOTE"}

	for _, cat := range skip {
		if !skipCategory(cat) {
			t.Errorf("expected skipCategory(%q) = true", cat)
		}
	}
	for _, cat := range keep {
		if skipCategory(cat) {
			t.Errorf("expected skipCategory(%q) = false", cat)
		}
	}
}

func TestIsSecretField(t *testing.T) {
	secret := []string{"CONCEALED", "STRING", "PASSWORD", "EMAIL", "URL"}
	notSecret := []string{"OTP", "SECTION_HEADER", "MENU", "REFERENCE"}

	for _, ft := range secret {
		if !isSecretField(ft) {
			t.Errorf("expected isSecretField(%q) = true", ft)
		}
	}
	for _, ft := range notSecret {
		if isSecretField(ft) {
			t.Errorf("expected isSecretField(%q) = false", ft)
		}
	}
}
