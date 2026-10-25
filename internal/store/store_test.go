package store

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phoenixsec/phoenix/internal/crypto"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	masterKey, err := crypto.GenerateAndSaveMasterKey(keyPath)
	if err != nil {
		t.Fatalf("generate master key: %v", err)
	}

	storePath := filepath.Join(dir, "store.json")
	s, err := New(storePath, masterKey)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	return s
}

func TestSetAndGet(t *testing.T) {
	s := newTestStore(t)

	err := s.Set("openclaw/api-key", "sk-12345", "vector", "test key", []string{"test"})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	secret, err := s.Get("openclaw/api-key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if secret.Value != "sk-12345" {
		t.Fatalf("expected 'sk-12345', got %q", secret.Value)
	}
	if secret.Metadata.CreatedBy != "vector" {
		t.Fatalf("expected creator 'vector', got %q", secret.Metadata.CreatedBy)
	}
	if secret.Metadata.Description != "test key" {
		t.Fatalf("expected description 'test key', got %q", secret.Metadata.Description)
	}
}

func TestGetNotFound(t *testing.T) {
	s := newTestStore(t)

	_, err := s.Get("nonexistent/path")
	if err != ErrSecretNotFound {
		t.Fatalf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestUpdate(t *testing.T) {
	s := newTestStore(t)

	s.Set("test/key", "v1", "vector", "version 1", nil)
	s.Set("test/key", "v2", "vector", "", nil) // empty desc = keep existing

	secret, _ := s.Get("test/key")
	if secret.Value != "v2" {
		t.Fatalf("expected 'v2', got %q", secret.Value)
	}
	if secret.Metadata.Description != "version 1" {
		t.Fatalf("expected preserved description 'version 1', got %q", secret.Metadata.Description)
	}
}

func TestDelete(t *testing.T) {
	s := newTestStore(t)

	s.Set("test/key", "value", "vector", "", nil)
	err := s.Delete("test/key")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = s.Get("test/key")
	if err != ErrSecretNotFound {
		t.Fatalf("expected ErrSecretNotFound after delete, got %v", err)
	}
}

func TestDeleteNotFound(t *testing.T) {
	s := newTestStore(t)

	err := s.Delete("nonexistent/path")
	if err != ErrSecretNotFound {
		t.Fatalf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestList(t *testing.T) {
	s := newTestStore(t)

	s.Set("openclaw/key1", "v1", "vector", "", nil)
	s.Set("openclaw/key2", "v2", "vector", "", nil)
	s.Set("monitoring/grafana", "pass", "vector", "", nil)

	all := s.List("")
	if len(all) != 3 {
		t.Fatalf("expected 3 secrets, got %d", len(all))
	}

	oc := s.List("openclaw/")
	if len(oc) != 2 {
		t.Fatalf("expected 2 openclaw secrets, got %d", len(oc))
	}

	mon := s.List("monitoring/")
	if len(mon) != 1 {
		t.Fatalf("expected 1 monitoring secret, got %d", len(mon))
	}

	none := s.List("nonexistent/")
	if len(none) != 0 {
		t.Fatalf("expected 0 secrets, got %d", len(none))
	}
}

func TestCount(t *testing.T) {
	s := newTestStore(t)

	if s.Count() != 0 {
		t.Fatal("expected 0 on empty store")
	}

	s.Set("a/b", "v", "x", "", nil)
	s.Set("c/d", "v", "x", "", nil)

	if s.Count() != 2 {
		t.Fatalf("expected 2, got %d", s.Count())
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	masterKey, _ := crypto.GenerateAndSaveMasterKey(keyPath)
	storePath := filepath.Join(dir, "store.json")

	// Write with one store instance
	s1, _ := New(storePath, masterKey)
	s1.Set("test/persistent", "secret-value", "vector", "persisted", nil)

	// Read with a new store instance (simulates restart)
	s2, err := New(storePath, masterKey)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}

	secret, err := s2.Get("test/persistent")
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if secret.Value != "secret-value" {
		t.Fatalf("expected 'secret-value', got %q", secret.Value)
	}
}

func TestValidatePath(t *testing.T) {
	tests := []struct {
		path  string
		valid bool
	}{
		{"openclaw/key", true},
		{"a/b/c", true},
		{"ns/deep/nested/path", true},
		{"", false},
		{"noslash", false},
		{"/leading", false},
		{"trailing/", false},
		{"double//slash", false},
		{"dot/../traversal", false},
	}

	for _, tt := range tests {
		err := ValidatePath(tt.path)
		if tt.valid && err != nil {
			t.Errorf("path %q should be valid, got error: %v", tt.path, err)
		}
		if !tt.valid && err == nil {
			t.Errorf("path %q should be invalid, got nil error", tt.path)
		}
	}
}

func TestNamespaceIsolation(t *testing.T) {
	s := newTestStore(t)

	// Secrets in different namespaces use different DEKs
	s.Set("ns1/key", "value1", "vector", "", nil)
	s.Set("ns2/key", "value2", "vector", "", nil)

	sec1, _ := s.Get("ns1/key")
	sec2, _ := s.Get("ns2/key")

	if sec1.Value != "value1" || sec2.Value != "value2" {
		t.Fatal("namespace isolation failed")
	}
}

func TestRotateMasterKeySecretsReadable(t *testing.T) {
	s := newTestStore(t)

	// Seed secrets across multiple namespaces
	s.Set("ns1/key1", "value1", "vector", "desc1", []string{"tag1"})
	s.Set("ns1/key2", "value2", "vector", "", nil)
	s.Set("ns2/secret", "s3cr3t", "vector", "important", nil)
	s.Set("ns3/deep/path", "deep-value", "vector", "", nil)

	// Rotate master key
	rotated, err := s.RotateMasterKey(nil)
	if err != nil {
		t.Fatalf("RotateMasterKey: %v", err)
	}
	if rotated != 3 {
		t.Fatalf("expected 3 namespaces rotated, got %d", rotated)
	}

	// Verify all secrets are still readable after rotation
	tests := []struct {
		path, value string
	}{
		{"ns1/key1", "value1"},
		{"ns1/key2", "value2"},
		{"ns2/secret", "s3cr3t"},
		{"ns3/deep/path", "deep-value"},
	}
	for _, tt := range tests {
		sec, err := s.Get(tt.path)
		if err != nil {
			t.Fatalf("Get(%q) after rotation: %v", tt.path, err)
		}
		if sec.Value != tt.value {
			t.Fatalf("Get(%q) = %q, want %q", tt.path, sec.Value, tt.value)
		}
	}

	// Verify metadata preserved
	sec1, _ := s.Get("ns1/key1")
	if sec1.Metadata.Description != "desc1" {
		t.Fatalf("metadata lost: description = %q", sec1.Metadata.Description)
	}
}

func TestRotateMasterKeyEmptyStore(t *testing.T) {
	s := newTestStore(t)

	rotated, err := s.RotateMasterKey(nil)
	if err != nil {
		t.Fatalf("RotateMasterKey on empty store: %v", err)
	}
	if rotated != 0 {
		t.Fatalf("expected 0 namespaces rotated on empty store, got %d", rotated)
	}
}

func TestRotateMasterKeyPersistence(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	masterKey, _ := crypto.GenerateAndSaveMasterKey(keyPath)
	storePath := filepath.Join(dir, "store.json")

	// Create store and seed data
	s1, _ := New(storePath, masterKey)
	s1.Set("test/secret", "original-value", "vector", "", nil)

	// Rotate
	_, err := s1.RotateMasterKey(nil)
	if err != nil {
		t.Fatalf("RotateMasterKey: %v", err)
	}

	// Get the new master key from the provider
	provider := s1.Provider().(*crypto.FileKeyProvider)
	newKey := provider.MasterKey()

	// Open a fresh store with the new key (simulates server restart)
	s2, err := New(storePath, newKey)
	if err != nil {
		t.Fatalf("reopen store with new key: %v", err)
	}

	sec, err := s2.Get("test/secret")
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if sec.Value != "original-value" {
		t.Fatalf("expected 'original-value', got %q", sec.Value)
	}
}

func TestRotateMasterKeyRollback(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	masterKey, _ := crypto.GenerateAndSaveMasterKey(keyPath)
	storePath := filepath.Join(dir, "store.json")

	// Create store and seed data
	s1, _ := New(storePath, masterKey)
	s1.Set("test/secret", "rollback-value", "vector", "", nil)

	// Save old store before rotation for rollback test
	storeBackup := storePath + ".bak"
	data, _ := os.ReadFile(storePath)
	os.WriteFile(storeBackup, data, 0600)

	// Rotate
	s1.RotateMasterKey(nil)

	// Restore old store from backup
	data, _ = os.ReadFile(storeBackup)
	os.WriteFile(storePath, data, 0600)

	// Old key should work with old store
	s2, err := New(storePath, masterKey)
	if err != nil {
		t.Fatalf("reopen store with old key: %v", err)
	}

	sec, err := s2.Get("test/secret")
	if err != nil {
		t.Fatalf("Get after rollback: %v", err)
	}
	if sec.Value != "rollback-value" {
		t.Fatalf("expected 'rollback-value', got %q", sec.Value)
	}
}

func TestRotateMasterKeyNewSecretsWork(t *testing.T) {
	s := newTestStore(t)

	// Seed and rotate
	s.Set("ns1/key", "before", "vector", "", nil)
	s.RotateMasterKey(nil)

	// Write new secrets after rotation
	if err := s.Set("ns1/key2", "after", "vector", "", nil); err != nil {
		t.Fatalf("Set after rotation: %v", err)
	}
	if err := s.Set("ns2/new", "new-ns", "vector", "", nil); err != nil {
		t.Fatalf("Set new namespace after rotation: %v", err)
	}

	// All should be readable
	sec1, _ := s.Get("ns1/key")
	if sec1.Value != "before" {
		t.Fatalf("pre-rotation secret = %q, want 'before'", sec1.Value)
	}
	sec2, _ := s.Get("ns1/key2")
	if sec2.Value != "after" {
		t.Fatalf("post-rotation secret = %q, want 'after'", sec2.Value)
	}
	sec3, _ := s.Get("ns2/new")
	if sec3.Value != "new-ns" {
		t.Fatalf("new namespace secret = %q, want 'new-ns'", sec3.Value)
	}
}

func TestRotateMasterKeyCallbackFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	masterKey, _ := crypto.GenerateAndSaveMasterKey(keyPath)
	storePath := filepath.Join(dir, "store.json")

	s, _ := New(storePath, masterKey)
	s.Set("ns1/key1", "value1", "vector", "", nil)
	s.Set("ns2/key2", "value2", "vector", "", nil)

	// Capture old key
	provider := s.Provider().(*crypto.FileKeyProvider)
	oldKey := make([]byte, len(provider.MasterKey()))
	copy(oldKey, provider.MasterKey())

	// Rotate with a callback that always fails
	callbackErr := fmt.Errorf("simulated key file write failure")
	_, err := s.RotateMasterKey(func() error {
		return callbackErr
	})
	if err == nil {
		t.Fatal("expected error from failing callback")
	}

	// Provider key should NOT have changed (rollback)
	if !bytes.Equal(oldKey, provider.MasterKey()) {
		t.Fatal("provider key changed despite callback failure")
	}

	// Pending key should be cleared
	if provider.PendingMasterKey() != nil {
		t.Fatal("pending key not cleared after callback failure rollback")
	}

	// Pre-rotate backup should be cleaned up
	if _, err := os.Stat(storePath + ".pre-rotate"); !os.IsNotExist(err) {
		t.Fatal("pre-rotate backup was not cleaned up")
	}

	// Secrets should still be readable with old key
	sec1, err := s.Get("ns1/key1")
	if err != nil {
		t.Fatalf("Get ns1/key1 after rollback: %v", err)
	}
	if sec1.Value != "value1" {
		t.Fatalf("ns1/key1 = %q, want 'value1'", sec1.Value)
	}
	sec2, err := s.Get("ns2/key2")
	if err != nil {
		t.Fatalf("Get ns2/key2 after rollback: %v", err)
	}
	if sec2.Value != "value2" {
		t.Fatalf("ns2/key2 = %q, want 'value2'", sec2.Value)
	}

	// Store file should be restored from pre-rotate backup (old DEKs).
	// Verify by opening a new store with the old key.
	s2, err := New(storePath, oldKey)
	if err != nil {
		t.Fatalf("reopen store with old key after rollback: %v", err)
	}
	sec, err := s2.Get("ns1/key1")
	if err != nil {
		t.Fatalf("new store Get after rollback: %v", err)
	}
	if sec.Value != "value1" {
		t.Fatalf("persisted value = %q, want 'value1'", sec.Value)
	}
}

// rotationFailureStore builds a two-secret store for the rotation failure
// tests. With a non-empty passphrase, master.key is written
// passphrase-protected and the provider carries the passphrase, the same
// way the server boots a protected deployment.
func rotationFailureStore(t *testing.T, passphrase string) (s *Store, storePath string, oldKey []byte) {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	var masterKey []byte
	var err error
	if passphrase == "" {
		masterKey, err = crypto.GenerateAndSaveMasterKey(keyPath)
	} else {
		masterKey, err = crypto.GenerateKey()
		if err == nil {
			err = crypto.SaveProtectedMasterKey(keyPath, masterKey, passphrase)
		}
	}
	if err != nil {
		t.Fatalf("create master key: %v", err)
	}
	storePath = filepath.Join(dir, "store.json")
	s, err = New(storePath, masterKey)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.Provider().(*crypto.FileKeyProvider).SetPassphrase(passphrase)
	if err := s.Set("ns1/key1", "value1", "vector", "", nil); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Set("ns2/key2", "value2", "vector", "", nil); err != nil {
		t.Fatalf("Set: %v", err)
	}
	return s, storePath, append([]byte(nil), masterKey...)
}

// assertOpensWithKey checks that the store file at path decrypts with key.
func assertOpensWithKey(t *testing.T, path string, key []byte) {
	t.Helper()
	st, err := New(path, key)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	for p, want := range map[string]string{"ns1/key1": "value1", "ns2/key2": "value2"} {
		sec, err := st.Get(p)
		if err != nil {
			t.Fatalf("%s: Get %s: %v", path, p, err)
		}
		if sec.Value != want {
			t.Fatalf("%s: %s = %q, want %q", path, p, sec.Value, want)
		}
	}
}

// assertNotOpensWithKey checks that key can NOT decrypt the store at path
// (it still holds wrappers for some other key).
func assertNotOpensWithKey(t *testing.T, path string, key []byte) {
	t.Helper()
	st, err := New(path, key)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	if _, err := st.Get("ns1/key1"); err == nil {
		t.Fatalf("%s unexpectedly decrypts with this key", path)
	}
}

// breakStoreDisk makes every store write and the restore rename fail until
// the returned repair func is called. The rotated store file stays on disk
// untouched, like a disk that went read-only mid-rotation. Key files are
// written outside these seams, so the key directory keeps working.
func breakStoreDisk(t *testing.T) (repair func()) {
	t.Helper()
	broken := true
	origWrite, origRename := writeFileAtomic, renameFile
	writeFileAtomic = func(path string, data []byte, perm os.FileMode) error {
		if broken {
			return fmt.Errorf("injected write failure: %s", path)
		}
		return origWrite(path, data, perm)
	}
	renameFile = func(from, to string) error {
		if broken {
			return fmt.Errorf("injected rename failure: %s", to)
		}
		return origRename(from, to)
	}
	t.Cleanup(func() { writeFileAtomic, renameFile = origWrite, origRename })
	return func() { broken = false }
}

// failRotationWithBrokenDisk runs a rotation whose key write fails and whose
// store disk breaks right after the rotated store was saved, so backup
// restore and rewrite both fail. Returns the error and the abandoned new key.
func failRotationWithBrokenDisk(t *testing.T, s *Store) (newKey []byte, repair func(), err error) {
	t.Helper()
	provider := s.Provider().(*crypto.FileKeyProvider)
	_, err = s.RotateMasterKey(func() error {
		newKey = provider.PendingMasterKey()
		repair = breakStoreDisk(t)
		return fmt.Errorf("simulated key file write failure")
	})
	if err == nil || !strings.Contains(err.Error(), "CRITICAL") {
		t.Fatalf("want CRITICAL error, got: %v", err)
	}
	return newKey, repair, err
}

// Callback fails and the backup restore fails, but the store can still be
// rewritten from memory: disk ends up consistent with the old key and no
// emergency key file is needed.
func TestRotateMasterKeyRestoreFailureRewritesStore(t *testing.T) {
	s, storePath, oldKey := rotationFailureStore(t, "")
	provider := s.Provider().(*crypto.FileKeyProvider)

	_, err := s.RotateMasterKey(func() error {
		os.Remove(storePath + ".pre-rotate") // force the restore rename to fail
		return fmt.Errorf("simulated key file write failure")
	})
	if err == nil {
		t.Fatal("expected error from failing callback")
	}
	if strings.Contains(err.Error(), "CRITICAL") {
		t.Fatalf("recovered failure should not be CRITICAL: %v", err)
	}
	if !bytes.Equal(oldKey, provider.MasterKey()) || provider.PendingMasterKey() != nil {
		t.Fatal("provider not rolled back to the old key")
	}
	if _, statErr := os.Stat(storePath + ".emergency-key"); !os.IsNotExist(statErr) {
		t.Fatalf("emergency key written although the store was repaired: %v", statErr)
	}
	assertOpensWithKey(t, storePath, oldKey)
}

// Everything fails and no passphrase is configured (finding M2): the new
// master key must NOT be written to disk. The live store keeps the rotated
// wrappers, the pre-rotate backup matches the old key, and the next
// successful write repairs the live store from memory.
func TestRotateMasterKeyTotalFailureRefusesUnprotectedKey(t *testing.T) {
	s, storePath, oldKey := rotationFailureStore(t, "")
	provider := s.Provider().(*crypto.FileKeyProvider)

	newKey, repair, err := failRotationWithBrokenDisk(t, s)

	entries, _ := os.ReadDir(filepath.Dir(storePath))
	for _, e := range entries {
		if strings.Contains(e.Name(), "emergency-key") {
			t.Fatalf("unprotected emergency key written: %s", e.Name())
		}
	}
	if !bytes.Equal(oldKey, provider.MasterKey()) || provider.PendingMasterKey() != nil {
		t.Fatal("provider not rolled back to the old key")
	}
	if sec, err := s.Get("ns1/key1"); err != nil || sec.Value != "value1" {
		t.Fatalf("in-memory Get after total failure: %v %v", sec, err)
	}
	if !strings.Contains(err.Error(), storePath+".pre-rotate") {
		t.Fatalf("error should name the pre-rotate backup: %v", err)
	}
	assertOpensWithKey(t, storePath+".pre-rotate", oldKey)
	assertNotOpensWithKey(t, storePath, oldKey)
	assertOpensWithKey(t, storePath, newKey) // the abandoned rotation is really on disk

	repair()
	if err := s.Set("ns1/key1", "value1", "vector", "", nil); err != nil {
		t.Fatalf("Set after disk repair: %v", err)
	}
	assertOpensWithKey(t, storePath, oldKey)
}

// Regression (review F1, 2026-10-20): after a total failure, a retry whose
// key write also fails must not destroy the last readable copy. The retry
// used to copy the abandoned-key store over the good backup, roll back to
// it, and leave a store that no key on disk could open after a restart.
func TestRotateMasterKeyRetryAfterTotalFailureKeepsStoreReadable(t *testing.T) {
	s, storePath, oldKey := rotationFailureStore(t, "")

	_, repair, _ := failRotationWithBrokenDisk(t, s)
	repair()

	_, err := s.RotateMasterKey(func() error {
		return fmt.Errorf("key persistence still unavailable")
	})
	if err == nil || strings.Contains(err.Error(), "CRITICAL") {
		t.Fatalf("want ordinary rollback error, got: %v", err)
	}

	// Simulate a restart: load master.key from disk and reopen the store.
	diskKey, err := crypto.LoadMasterKey(filepath.Join(filepath.Dir(storePath), "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(diskKey, oldKey) {
		t.Fatal("master.key changed although no key write succeeded")
	}
	assertOpensWithKey(t, storePath, diskKey)
}

// Everything fails with a protected master.key: the new key is saved,
// passphrase-encrypted, and the pre-rotate backup is kept too. Both
// documented recoveries must work: the backup with the current master.key,
// or the live store with the emergency key put in place of master.key.
func TestRotateMasterKeyTotalFailureWritesEncryptedKey(t *testing.T) {
	const passphrase = "correct horse battery staple"
	s, storePath, oldKey := rotationFailureStore(t, passphrase)
	dir := filepath.Dir(storePath)
	keyPath := filepath.Join(dir, "master.key")
	emergencyPath := storePath + ".emergency-key"

	newKey, _, err := failRotationWithBrokenDisk(t, s)
	if !strings.Contains(err.Error(), emergencyPath) || !strings.Contains(err.Error(), storePath+".pre-rotate") {
		t.Fatalf("error should name both recovery files, got: %v", err)
	}

	raw, err := os.ReadFile(emergencyPath)
	if err != nil {
		t.Fatalf("emergency key not written: %v", err)
	}
	if !crypto.IsProtectedKeyFile(raw) {
		t.Fatal("emergency key file is not passphrase-protected")
	}
	if _, err := crypto.LoadMasterKey(emergencyPath); err != crypto.ErrPassphraseRequired {
		t.Fatalf("LoadMasterKey without passphrase: got %v, want ErrPassphraseRequired", err)
	}

	// Recovery A: .pre-rotate + the current (unchanged) master.key.
	current, err := crypto.LoadMasterKeyWithPassphrase(keyPath, passphrase)
	if err != nil {
		t.Fatalf("load current master.key: %v", err)
	}
	if !bytes.Equal(current, oldKey) {
		t.Fatal("master.key changed although the key write failed")
	}
	assertOpensWithKey(t, storePath+".pre-rotate", current)

	// Recovery B: emergency key moved over master.key opens the live store.
	if err := os.Rename(emergencyPath, keyPath); err != nil {
		t.Fatal(err)
	}
	recovered, err := crypto.LoadMasterKeyWithPassphrase(keyPath, passphrase)
	if err != nil {
		t.Fatalf("load emergency key as master.key: %v", err)
	}
	if !bytes.Equal(recovered, newKey) {
		t.Fatal("emergency key is not the pending rotation key")
	}
	assertOpensWithKey(t, storePath, recovered)
}

func TestRotateMasterKeySaveFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	masterKey, _ := crypto.GenerateAndSaveMasterKey(keyPath)

	// Point the store at a read-only directory to force save() to fail
	readOnlyDir := filepath.Join(dir, "readonly")
	os.MkdirAll(readOnlyDir, 0700)
	storePath := filepath.Join(readOnlyDir, "store.json")

	// Create store and seed data (save works while dir is writable)
	s, _ := New(storePath, masterKey)
	s.Set("ns1/key1", "value1", "vector", "", nil)

	// Make the directory read-only to force save failure
	os.Chmod(readOnlyDir, 0500)
	defer os.Chmod(readOnlyDir, 0700) // cleanup

	provider := s.Provider().(*crypto.FileKeyProvider)
	oldKey := make([]byte, len(provider.MasterKey()))
	copy(oldKey, provider.MasterKey())

	// Rotate should fail on save
	_, err := s.RotateMasterKey(nil)
	if err == nil {
		t.Fatal("expected error from failed save")
	}

	// Provider key should NOT have changed
	if !bytes.Equal(oldKey, provider.MasterKey()) {
		t.Fatal("provider key changed despite save failure")
	}

	// Pending key should be cleared
	if provider.PendingMasterKey() != nil {
		t.Fatal("pending key not cleared after save failure rollback")
	}

	// Secrets should still be readable in memory
	sec, err := s.Get("ns1/key1")
	if err != nil {
		t.Fatalf("Get after save failure: %v", err)
	}
	if sec.Value != "value1" {
		t.Fatalf("value = %q, want 'value1'", sec.Value)
	}
}

func TestRotateMasterKeyCallbackSuccessCommits(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	masterKey, _ := crypto.GenerateAndSaveMasterKey(keyPath)
	storePath := filepath.Join(dir, "store.json")

	s, _ := New(storePath, masterKey)
	s.Set("ns1/key1", "value1", "vector", "", nil)

	provider := s.Provider().(*crypto.FileKeyProvider)
	oldKey := make([]byte, len(provider.MasterKey()))
	copy(oldKey, provider.MasterKey())

	var savedKey []byte

	// Rotate with a callback that captures the pending key (simulates key file write)
	rotated, err := s.RotateMasterKey(func() error {
		pending := provider.PendingMasterKey()
		if pending == nil {
			return fmt.Errorf("no pending key")
		}
		savedKey = make([]byte, len(pending))
		copy(savedKey, pending)
		return crypto.SaveMasterKeyAtomic(keyPath, pending)
	})
	if err != nil {
		t.Fatalf("RotateMasterKey: %v", err)
	}
	if rotated != 1 {
		t.Fatalf("expected 1 namespace rotated, got %d", rotated)
	}

	// Provider key should have changed (committed)
	if bytes.Equal(oldKey, provider.MasterKey()) {
		t.Fatal("provider key did not change after successful rotation")
	}

	// The new key should match what we captured
	if !bytes.Equal(savedKey, provider.MasterKey()) {
		t.Fatal("committed key does not match the pending key we saved")
	}

	// Secrets should be readable
	sec, err := s.Get("ns1/key1")
	if err != nil {
		t.Fatalf("Get after rotation: %v", err)
	}
	if sec.Value != "value1" {
		t.Fatalf("value = %q, want 'value1'", sec.Value)
	}

	// Verify persistence: reopen store with the new key
	s2, err := New(storePath, provider.MasterKey())
	if err != nil {
		t.Fatalf("reopen store with new key: %v", err)
	}
	sec2, err := s2.Get("ns1/key1")
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if sec2.Value != "value1" {
		t.Fatalf("persisted value = %q, want 'value1'", sec2.Value)
	}
}

func TestGetMetadata(t *testing.T) {
	s := newTestStore(t)

	s.Set("test/key", "value", "vector", "my description", []string{"tag1", "tag2"})

	meta, err := s.GetMetadata("test/key")
	if err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}
	if meta.CreatedBy != "vector" {
		t.Fatalf("expected creator 'vector', got %q", meta.CreatedBy)
	}
	if meta.Description != "my description" {
		t.Fatalf("expected description 'my description', got %q", meta.Description)
	}
	if len(meta.Tags) != 2 || meta.Tags[0] != "tag1" {
		t.Fatalf("unexpected tags: %v", meta.Tags)
	}
	if meta.Created.IsZero() {
		t.Fatal("Created timestamp should not be zero")
	}
}

func TestGetMetadataNotFound(t *testing.T) {
	s := newTestStore(t)

	_, err := s.GetMetadata("nonexistent/path")
	if err != ErrSecretNotFound {
		t.Fatalf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestSetPreservesCreatedTimestamp(t *testing.T) {
	s := newTestStore(t)

	s.Set("test/key", "v1", "original-author", "desc1", []string{"tag1"})

	meta1, _ := s.GetMetadata("test/key")
	created := meta1.Created

	// Update the secret
	s.Set("test/key", "v2", "new-author", "", nil)

	meta2, _ := s.GetMetadata("test/key")

	// Created timestamp should be preserved
	if !meta2.Created.Equal(created) {
		t.Fatalf("Created changed: %v -> %v", created, meta2.Created)
	}
	// Description should be preserved when empty
	if meta2.Description != "desc1" {
		t.Fatalf("expected preserved description 'desc1', got %q", meta2.Description)
	}
	// Tags should be preserved when nil
	if len(meta2.Tags) != 1 || meta2.Tags[0] != "tag1" {
		t.Fatalf("expected preserved tags, got %v", meta2.Tags)
	}
	// Updated should change
	if meta2.Updated.Equal(meta1.Updated) || meta2.Updated.Before(meta1.Updated) {
		t.Fatal("Updated timestamp should advance on update")
	}
}

func TestProvider(t *testing.T) {
	s := newTestStore(t)
	if s.Provider() == nil {
		t.Fatal("Provider() should not return nil")
	}
}
