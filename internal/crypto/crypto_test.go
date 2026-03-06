package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(key) != KeySize {
		t.Fatalf("expected key length %d, got %d", KeySize, len(key))
	}

	// Two generated keys should be different
	key2, _ := GenerateKey()
	if string(key) == string(key2) {
		t.Fatal("two generated keys should not be identical")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key, _ := GenerateKey()
	plaintext := []byte("super-secret-api-key-12345")

	blob, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if blob.Nonce == "" || blob.Ciphertext == "" {
		t.Fatal("blob should have non-empty nonce and ciphertext")
	}

	decrypted, err := Decrypt(key, blob)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("expected %q, got %q", plaintext, decrypted)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()
	plaintext := []byte("secret")

	blob, _ := Encrypt(key1, plaintext)

	_, err := Decrypt(key2, blob)
	if err != ErrDecryptionFailed {
		t.Fatalf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestEncryptInvalidKey(t *testing.T) {
	_, err := Encrypt([]byte("short"), []byte("data"))
	if err != ErrInvalidKey {
		t.Fatalf("expected ErrInvalidKey, got %v", err)
	}
}

func TestEncryptEmptyPlaintext(t *testing.T) {
	key, _ := GenerateKey()

	blob, err := Encrypt(key, []byte{})
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}

	decrypted, err := Decrypt(key, blob)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}

	if len(decrypted) != 0 {
		t.Fatalf("expected empty, got %d bytes", len(decrypted))
	}
}

func TestWrapUnwrapDEK(t *testing.T) {
	masterKey, _ := GenerateKey()
	dek, _ := GenerateKey()

	wrapped, err := WrapDEK(masterKey, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	unwrapped, err := UnwrapDEK(masterKey, wrapped)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}

	if string(unwrapped) != string(dek) {
		t.Fatal("unwrapped DEK doesn't match original")
	}
}

func TestUnwrapDEKWrongMasterKey(t *testing.T) {
	mk1, _ := GenerateKey()
	mk2, _ := GenerateKey()
	dek, _ := GenerateKey()

	wrapped, _ := WrapDEK(mk1, dek)
	_, err := UnwrapDEK(mk2, wrapped)
	if err == nil {
		t.Fatal("expected error unwrapping with wrong master key")
	}
}

func TestMasterKeyFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "master.key")

	key, err := GenerateAndSaveMasterKey(path)
	if err != nil {
		t.Fatalf("GenerateAndSaveMasterKey: %v", err)
	}

	// Check file permissions
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions, got %o", info.Mode().Perm())
	}

	loaded, err := LoadMasterKey(path)
	if err != nil {
		t.Fatalf("LoadMasterKey: %v", err)
	}

	if string(loaded) != string(key) {
		t.Fatal("loaded key doesn't match generated key")
	}
}

func TestLoadMasterKeyNotFound(t *testing.T) {
	_, err := LoadMasterKey("/nonexistent/path/master.key")
	if err != ErrKeyFileNotFound {
		t.Fatalf("expected ErrKeyFileNotFound, got %v", err)
	}
}

func TestHashToken(t *testing.T) {
	hash := HashToken("my-bearer-token")
	if hash == "" {
		t.Fatal("hash should not be empty")
	}
	if hash[:7] != "sha256:" {
		t.Fatalf("hash should start with 'sha256:', got %s", hash[:7])
	}

	// Same input should produce same hash
	hash2 := HashToken("my-bearer-token")
	if hash != hash2 {
		t.Fatal("same token should produce same hash")
	}

	// Different input should produce different hash
	hash3 := HashToken("different-token")
	if hash == hash3 {
		t.Fatal("different tokens should produce different hashes")
	}
}

func TestMarshalUnmarshalBlob(t *testing.T) {
	key, _ := GenerateKey()
	blob, _ := Encrypt(key, []byte("test-data"))

	data, err := MarshalBlob(blob)
	if err != nil {
		t.Fatalf("MarshalBlob: %v", err)
	}

	restored, err := UnmarshalBlob(data)
	if err != nil {
		t.Fatalf("UnmarshalBlob: %v", err)
	}

	plaintext, err := Decrypt(key, restored)
	if err != nil {
		t.Fatalf("Decrypt after unmarshal: %v", err)
	}
	if string(plaintext) != "test-data" {
		t.Fatalf("expected 'test-data', got %q", plaintext)
	}
}

func TestUnmarshalBlobCorrupted(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"garbage", []byte("not json at all")},
		{"truncated json", []byte(`{"nonce": "abc"`)},
		{"wrong type", []byte(`{"nonce": 123, "ciphertext": 456}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalBlob(tt.data)
			if err == nil {
				t.Fatalf("expected error for corrupted data %q", tt.data)
			}
		})
	}
}

func TestDecryptCorruptedBlob(t *testing.T) {
	key, _ := GenerateKey()

	// Valid nonce but corrupted ciphertext
	_, err := Decrypt(key, &EncryptedBlob{
		Nonce:      "AAAAAAAAAAAAAAAA",                         // 12 bytes base64
		Ciphertext: "dGhpcyBpcyBub3QgYSB2YWxpZCBjaXBoZXJ0ZXh0", // garbage
	})
	if err != ErrDecryptionFailed {
		t.Fatalf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestSaveMasterKeyAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "atomic.key")

	key, _ := GenerateKey()
	if err := SaveMasterKeyAtomic(path, key); err != nil {
		t.Fatalf("SaveMasterKeyAtomic: %v", err)
	}

	loaded, err := LoadMasterKey(path)
	if err != nil {
		t.Fatalf("LoadMasterKey after atomic save: %v", err)
	}
	if string(loaded) != string(key) {
		t.Fatal("loaded key doesn't match saved key")
	}

	// Temp file should be cleaned up
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file should not exist after successful save")
	}
}

func TestEncryptWrongKeyLength(t *testing.T) {
	// 16-byte key (AES-128 sized, but we require AES-256)
	shortKey := make([]byte, 16)
	_, err := Encrypt(shortKey, []byte("data"))
	if err != ErrInvalidKey {
		t.Fatalf("expected ErrInvalidKey for 16-byte key, got %v", err)
	}

	// 64-byte key (too long)
	longKey := make([]byte, 64)
	_, err = Encrypt(longKey, []byte("data"))
	if err != ErrInvalidKey {
		t.Fatalf("expected ErrInvalidKey for 64-byte key, got %v", err)
	}
}

func TestUniqueNonces(t *testing.T) {
	key, _ := GenerateKey()
	plaintext := []byte("same data")

	blob1, _ := Encrypt(key, plaintext)
	blob2, _ := Encrypt(key, plaintext)

	if blob1.Nonce == blob2.Nonce {
		t.Fatal("two encryptions should produce different nonces")
	}
	if blob1.Ciphertext == blob2.Ciphertext {
		t.Fatal("two encryptions should produce different ciphertexts")
	}
}
