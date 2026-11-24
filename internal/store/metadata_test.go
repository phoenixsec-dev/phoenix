package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phoenixsec/phoenix/internal/crypto"
)

func strp(s string) *string { return &s }

// Describe changes only what it was given, keeps who wrote the value and
// when, and carries the ciphertext over byte for byte.
func TestDescribeLeavesTheValueAlone(t *testing.T) {
	s := newTestStore(t)
	if err := s.Set("a/b", "v1", "maker", "old", []string{"x"}); err != nil {
		t.Fatal(err)
	}
	before := s.data.Secrets["a/b"]

	if err := s.Describe("a/b", MetadataChange{Username: strp("me@example.com"), URL: strp("https://example.com/login")}); err != nil {
		t.Fatal(err)
	}
	after := s.data.Secrets["a/b"]
	if after.Value.Ciphertext != before.Value.Ciphertext || after.Value.Nonce != before.Value.Nonce {
		t.Error("the ciphertext changed")
	}
	m := after.Metadata
	if m.Username != "me@example.com" || m.URL != "https://example.com/login" || m.Description != "old" || len(m.Tags) != 1 {
		t.Errorf("metadata = %+v", m)
	}
	if m.CreatedBy != "maker" || m.UpdatedBy != "maker" || !m.Updated.Equal(before.Metadata.Updated) || !m.Created.Equal(before.Metadata.Created) {
		t.Errorf("authors or times changed: %+v", m)
	}

	// Empty clears; a value write keeps the login; a missing secret is an error.
	if err := s.Describe("a/b", MetadataChange{Description: strp(""), Tags: &[]string{}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("a/b", "v2", "other", "", nil); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("a/b")
	if err != nil || got.Value != "v2" || got.Metadata.Username != "me@example.com" || got.Metadata.Description != "" || len(got.Metadata.Tags) != 0 {
		t.Errorf("after set: %+v, %v", got.Metadata, err)
	}
	if err := s.Describe("a/none", MetadataChange{Username: strp("x")}); err != ErrSecretNotFound {
		t.Errorf("missing secret: %v", err)
	}
}

func TestWriteModes(t *testing.T) {
	s := newTestStore(t)
	if err := s.Write("a/b", "v", "me", MetadataChange{}, WriteExisting); err != ErrSecretNotFound {
		t.Errorf("WriteExisting on a new path: %v", err)
	}
	if err := s.Write("a/b", "v", "me", MetadataChange{}, WriteNew); err != nil {
		t.Fatal(err)
	}
	if err := s.Write("a/b", "w", "me", MetadataChange{}, WriteNew); err != ErrSecretExists {
		t.Errorf("WriteNew on a taken path: %v", err)
	}
	if got, _ := s.Get("a/b"); got.Value != "v" {
		t.Error("WriteNew overwrote a secret")
	}
}

// A save that fails changes nothing, in the file or in memory.
func TestFailedSaveChangesNothing(t *testing.T) {
	s := newTestStore(t)
	if err := s.Set("a/b", "v1", "me", "d", nil); err != nil {
		t.Fatal(err)
	}
	disk, err := os.ReadFile(s.filePath)
	if err != nil {
		t.Fatal(err)
	}
	orig := writeFileAtomic
	writeFileAtomic = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	defer func() { writeFileAtomic = orig }()

	if s.Describe("a/b", MetadataChange{Username: strp("x")}) == nil {
		t.Error("Describe reported success")
	}
	if s.Write("a/b", "v2", "me", MetadataChange{}, WriteExisting) == nil {
		t.Error("Write reported success")
	}
	if s.Write("a/new", "v", "me", MetadataChange{}, WriteNew) == nil {
		t.Error("Write of a new secret reported success")
	}
	if got, err := s.Get("a/b"); err != nil || got.Value != "v1" || got.Metadata.Username != "" {
		t.Errorf("memory changed: %v", err)
	}
	if _, err := s.Get("a/new"); err != ErrSecretNotFound {
		t.Errorf("new secret stayed in memory: %v", err)
	}
	if now, _ := os.ReadFile(s.filePath); string(now) != string(disk) {
		t.Error("the file changed")
	}
}

// A store file from before username and url loads unchanged, and a server
// from before them opens a new file and keeps every value (it drops only the
// two fields, on its next write).
func TestStoreFileOldAndNewServers(t *testing.T) {
	s := newTestStore(t)
	if err := s.Set("a/b", "v1", "me", "d", nil); err != nil {
		t.Fatal(err)
	}
	old, _ := os.ReadFile(s.filePath)
	if strings.Contains(string(old), "username") || strings.Contains(string(old), `"url"`) {
		t.Error("a secret without a login writes the new fields")
	}
	if re, err := NewWithProvider(s.filePath, s.provider); err != nil {
		t.Fatal(err)
	} else if got, err := re.Get("a/b"); err != nil || got.Value != "v1" || got.Metadata.Description != "d" {
		t.Fatalf("old file: %v", err)
	}

	if err := s.Describe("a/b", MetadataChange{Username: strp("me")}); err != nil {
		t.Fatal(err)
	}
	// What v0.24 reads: the same structure without the two fields.
	var v24 struct {
		Version int `json:"version"`
		Secrets map[string]struct {
			Path      string               `json:"path"`
			Value     crypto.EncryptedBlob `json:"value"`
			Namespace string               `json:"namespace"`
			Metadata  struct {
				Description string `json:"description,omitempty"`
				CreatedBy   string `json:"created_by"`
			} `json:"metadata"`
		} `json:"secrets"`
		Namespaces map[string]namespaceDEK `json:"namespaces"`
	}
	data, _ := os.ReadFile(s.filePath)
	if err := json.Unmarshal(data, &v24); err != nil {
		t.Fatalf("old server cannot parse the new file: %v", err)
	}
	if v24.Version != 1 {
		t.Errorf("version = %d", v24.Version)
	}
	rewritten, _ := json.Marshal(v24)
	path := filepath.Join(t.TempDir(), "store.json")
	if err := os.WriteFile(path, rewritten, 0600); err != nil {
		t.Fatal(err)
	}
	back, err := NewWithProvider(path, s.provider)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := back.Get("a/b"); err != nil || got.Value != "v1" || got.Metadata.Description != "d" {
		t.Fatalf("after an old server rewrote the file: %v", err)
	}
}

func TestMetadataValidate(t *testing.T) {
	for _, bad := range []string{
		"javascript:alert(1)", "example.com", "//example.com", "https://", "ftp://example.com", "data:text/html,x",
		"https://user:pw@example.com", "https://user@example.com", "https://exa mple.com", "https:\\\\example.com",
		"https://example.com/‮", "https://example.com/\n", "https://" + strings.Repeat("a", 3000),
	} {
		err := MetadataChange{URL: &bad}.Validate()
		if err == nil {
			t.Errorf("accepted link %.40q", bad)
		} else if len(bad) > 8 && strings.Contains(err.Error(), bad) {
			t.Errorf("the error repeats the link: %v", err)
		}
	}
	for _, good := range []string{"", "https://example.com", "http://10.0.0.5:8006/#login", "https://[::1]:9443/a?b=c"} {
		if err := (MetadataChange{URL: &good}).Validate(); err != nil {
			t.Errorf("refused link %q: %v", good, err)
		}
	}
	for _, bad := range []string{"a\nb", "a​b", "\xff", strings.Repeat("a", 300)} {
		if (MetadataChange{Username: &bad}).Validate() == nil {
			t.Errorf("accepted username %.20q", bad)
		}
	}
	if err := (MetadataChange{Username: strp("Zoë@example.com")}).Validate(); err != nil {
		t.Error(err)
	}
}
