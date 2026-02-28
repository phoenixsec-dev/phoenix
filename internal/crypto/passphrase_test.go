package crypto

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	pf, err := EncryptMasterKey(key, "test-passphrase")
	if err != nil {
		t.Fatalf("encrypting key: %v", err)
	}

	got, err := DecryptMasterKey(pf, "test-passphrase")
	if err != nil {
		t.Fatalf("decrypting key: %v", err)
	}

	if len(got) != KeySize {
		t.Fatalf("expected %d bytes, got %d", KeySize, len(got))
	}
	for i := range key {
		if key[i] != got[i] {
			t.Fatalf("key mismatch at byte %d", i)
		}
	}
}

func TestDecryptWrongPassphrase(t *testing.T) {
	key, _ := GenerateKey()
	pf, _ := EncryptMasterKey(key, "correct")

	_, err := DecryptMasterKey(pf, "wrong")
	if err == nil {
		t.Fatal("expected error with wrong passphrase")
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	key, _ := GenerateKey()
	pf, _ := EncryptMasterKey(key, "test")

	// Tamper with ciphertext
	ct, _ := base64.StdEncoding.DecodeString(pf.Ciphertext)
	ct[0] ^= 0xff
	pf.Ciphertext = base64.StdEncoding.EncodeToString(ct)

	_, err := DecryptMasterKey(pf, "test")
	if err == nil {
		t.Fatal("expected error with tampered ciphertext")
	}
}

func TestIsProtectedKeyFile(t *testing.T) {
	// Raw base64 (unprotected)
	raw := []byte("dGVzdGtleWRhdGE=")
	if IsProtectedKeyFile(raw) {
		t.Fatal("raw base64 should not be detected as protected")
	}

	// JSON (protected)
	jsonData := []byte(`{"phoenix_protected_key":1}`)
	if !IsProtectedKeyFile(jsonData) {
		t.Fatal("JSON should be detected as protected")
	}

	// With whitespace
	if !IsProtectedKeyFile([]byte("  {\"phoenix_protected_key\":1}")) {
		t.Fatal("JSON with whitespace should be detected as protected")
	}

	// Empty
	if IsProtectedKeyFile([]byte("")) {
		t.Fatal("empty should not be detected as protected")
	}
}

func TestLoadMasterKeyReturnsErrPassphraseRequired(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")

	key, _ := GenerateKey()
	if err := SaveProtectedMasterKey(keyPath, key, "testpass"); err != nil {
		t.Fatalf("saving protected key: %v", err)
	}

	_, err := LoadMasterKey(keyPath)
	if err != ErrPassphraseRequired {
		t.Fatalf("expected ErrPassphraseRequired, got: %v", err)
	}
}

func TestLoadMasterKeyWithPassphrase_Protected(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")

	key, _ := GenerateKey()
	if err := SaveProtectedMasterKey(keyPath, key, "testpass"); err != nil {
		t.Fatalf("saving protected key: %v", err)
	}

	got, err := LoadMasterKeyWithPassphrase(keyPath, "testpass")
	if err != nil {
		t.Fatalf("loading protected key: %v", err)
	}

	for i := range key {
		if key[i] != got[i] {
			t.Fatalf("key mismatch at byte %d", i)
		}
	}
}

func TestLoadMasterKeyWithPassphrase_Unprotected(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")

	key, _ := GenerateKey()
	encoded := base64.StdEncoding.EncodeToString(key)
	os.WriteFile(keyPath, []byte(encoded), 0600)

	// Passphrase should be ignored for unprotected files
	got, err := LoadMasterKeyWithPassphrase(keyPath, "anything")
	if err != nil {
		t.Fatalf("loading unprotected key with passphrase: %v", err)
	}

	for i := range key {
		if key[i] != got[i] {
			t.Fatalf("key mismatch at byte %d", i)
		}
	}
}

func TestDeterministicKDF(t *testing.T) {
	salt := make([]byte, saltSize)
	for i := range salt {
		salt[i] = byte(i)
	}

	k1 := DeriveKeyFromPassphrase("password", salt, defaultKDFTime, defaultKDFMemory, defaultKDFThreads)
	k2 := DeriveKeyFromPassphrase("password", salt, defaultKDFTime, defaultKDFMemory, defaultKDFThreads)

	if len(k1) != KeySize {
		t.Fatalf("expected %d bytes, got %d", KeySize, len(k1))
	}

	for i := range k1 {
		if k1[i] != k2[i] {
			t.Fatal("same passphrase + salt should produce same key")
		}
	}
}

func TestDecryptRejectsZeroThreads(t *testing.T) {
	key, _ := GenerateKey()
	pf, _ := EncryptMasterKey(key, "test")
	pf.KDFThreads = 0

	_, err := DecryptMasterKey(pf, "test")
	if err == nil {
		t.Fatal("expected error with kdf_threads=0")
	}
}

func TestDecryptRejectsZeroTime(t *testing.T) {
	key, _ := GenerateKey()
	pf, _ := EncryptMasterKey(key, "test")
	pf.KDFTime = 0

	_, err := DecryptMasterKey(pf, "test")
	if err == nil {
		t.Fatal("expected error with kdf_time=0")
	}
}

func TestDecryptRejectsZeroMemory(t *testing.T) {
	key, _ := GenerateKey()
	pf, _ := EncryptMasterKey(key, "test")
	pf.KDFMemory = 0

	_, err := DecryptMasterKey(pf, "test")
	if err == nil {
		t.Fatal("expected error with kdf_memory=0")
	}
}

func TestDecryptRejectsHugeMemory(t *testing.T) {
	key, _ := GenerateKey()
	pf, _ := EncryptMasterKey(key, "test")
	pf.KDFMemory = maxKDFMemory + 1

	_, err := DecryptMasterKey(pf, "test")
	if err == nil {
		t.Fatal("expected error with excessive kdf_memory")
	}
}

func TestDecryptRejectsUnsupportedKDF(t *testing.T) {
	key, _ := GenerateKey()
	pf, _ := EncryptMasterKey(key, "test")
	pf.KDF = "bcrypt"

	_, err := DecryptMasterKey(pf, "test")
	if err == nil {
		t.Fatal("expected error with unsupported KDF")
	}
}

func TestSaveProtectedMasterKeyAtomic(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")

	key, _ := GenerateKey()
	if err := SaveProtectedMasterKey(keyPath, key, "pass"); err != nil {
		t.Fatalf("saving: %v", err)
	}

	// Verify it's JSON
	data, _ := os.ReadFile(keyPath)
	if !IsProtectedKeyFile(data) {
		t.Fatal("saved file should be detected as protected")
	}

	// Verify no temp file left
	if _, err := os.Stat(keyPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file should not exist after successful save")
	}
}

func TestProtectedKeyFileFormat(t *testing.T) {
	key, _ := GenerateKey()
	pf, err := EncryptMasterKey(key, "test")
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	if pf.Version != 1 {
		t.Fatalf("expected version 1, got %d", pf.Version)
	}
	if pf.KDF != "argon2id" {
		t.Fatalf("expected argon2id, got %s", pf.KDF)
	}
	if pf.KDFTime != defaultKDFTime {
		t.Fatalf("expected time %d, got %d", defaultKDFTime, pf.KDFTime)
	}
	if pf.KDFMemory != defaultKDFMemory {
		t.Fatalf("expected memory %d, got %d", defaultKDFMemory, pf.KDFMemory)
	}
	if pf.KDFThreads != defaultKDFThreads {
		t.Fatalf("expected threads %d, got %d", defaultKDFThreads, pf.KDFThreads)
	}

	// Verify salt is 16 bytes
	salt, _ := base64.StdEncoding.DecodeString(pf.Salt)
	if len(salt) != saltSize {
		t.Fatalf("expected salt %d bytes, got %d", saltSize, len(salt))
	}

	// Verify nonce is 12 bytes
	nonce, _ := base64.StdEncoding.DecodeString(pf.Nonce)
	if len(nonce) != NonceSize {
		t.Fatalf("expected nonce %d bytes, got %d", NonceSize, len(nonce))
	}
}
