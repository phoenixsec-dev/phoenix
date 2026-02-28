// Package crypto provides AES-256-GCM envelope encryption for Phoenix.
//
// Envelope encryption uses a two-tier key hierarchy:
//   - Master key (KEK): wraps/unwraps data encryption keys
//   - Data encryption keys (DEK): encrypt/decrypt actual secret values
//
// This limits blast radius — compromising a DEK only exposes secrets
// encrypted with that key. Rotating the KEK only requires re-wrapping
// DEKs, not re-encrypting all secrets.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	KeySize   = 32 // AES-256
	NonceSize = 12 // GCM standard nonce
)

var (
	ErrInvalidKey          = errors.New("invalid key size: must be 32 bytes")
	ErrDecryptionFailed    = errors.New("decryption failed: ciphertext tampered or wrong key")
	ErrKeyFileNotFound     = errors.New("master key file not found")
	ErrPassphraseRequired  = errors.New("master key is passphrase-protected")
)

// EncryptedBlob holds an encrypted value with its nonce.
type EncryptedBlob struct {
	Nonce      string `json:"nonce"`      // base64-encoded nonce
	Ciphertext string `json:"ciphertext"` // base64-encoded ciphertext+tag
}

// WrappedDEK is a data encryption key encrypted by the master key.
type WrappedDEK struct {
	EncryptedBlob
}

// GenerateKey creates a cryptographically random 256-bit key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generating random key: %w", err)
	}
	return key, nil
}

// Encrypt encrypts plaintext with the given key using AES-256-GCM.
func Encrypt(key, plaintext []byte) (*EncryptedBlob, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return &EncryptedBlob{
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

// Decrypt decrypts an EncryptedBlob with the given key.
func Decrypt(key []byte, blob *EncryptedBlob) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}

	nonce, err := base64.StdEncoding.DecodeString(blob.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decoding nonce: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(blob.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decoding ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// WrapDEK encrypts a data encryption key with the master key.
func WrapDEK(masterKey, dek []byte) (*WrappedDEK, error) {
	blob, err := Encrypt(masterKey, dek)
	if err != nil {
		return nil, fmt.Errorf("wrapping DEK: %w", err)
	}
	return &WrappedDEK{EncryptedBlob: *blob}, nil
}

// UnwrapDEK decrypts a wrapped data encryption key using the master key.
func UnwrapDEK(masterKey []byte, wrapped *WrappedDEK) ([]byte, error) {
	dek, err := Decrypt(masterKey, &wrapped.EncryptedBlob)
	if err != nil {
		return nil, fmt.Errorf("unwrapping DEK: %w", err)
	}
	if len(dek) != KeySize {
		return nil, ErrInvalidKey
	}
	return dek, nil
}

// LoadMasterKey reads the master key from a file.
// Returns ErrPassphraseRequired if the file is passphrase-protected.
func LoadMasterKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrKeyFileNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("reading master key: %w", err)
	}

	if IsProtectedKeyFile(data) {
		return nil, ErrPassphraseRequired
	}

	key, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("decoding master key: %w", err)
	}

	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}

	return key, nil
}

// LoadMasterKeyWithPassphrase reads the master key from a file, decrypting
// it with the given passphrase if the file is protected.
// For unprotected files, the passphrase is ignored.
func LoadMasterKeyWithPassphrase(path, passphrase string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrKeyFileNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("reading master key: %w", err)
	}

	if IsProtectedKeyFile(data) {
		var pf ProtectedKeyFile
		if err := json.Unmarshal(data, &pf); err != nil {
			return nil, fmt.Errorf("parsing protected key file: %w", err)
		}
		return DecryptMasterKey(&pf, passphrase)
	}

	// Unprotected: plain base64
	key, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("decoding master key: %w", err)
	}
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}
	return key, nil
}

// GenerateAndSaveMasterKey creates a new master key and writes it to a file
// with 0600 permissions.
func GenerateAndSaveMasterKey(path string) ([]byte, error) {
	key, err := GenerateKey()
	if err != nil {
		return nil, err
	}

	encoded := base64.StdEncoding.EncodeToString(key)
	if err := os.WriteFile(path, []byte(encoded), 0600); err != nil {
		return nil, fmt.Errorf("writing master key: %w", err)
	}

	return key, nil
}

// SaveMasterKeyAtomic writes a master key to disk using write-tmp + rename
// for crash safety. This matches the atomic write pattern used by store.save().
func SaveMasterKeyAtomic(path string, key []byte) error {
	encoded := base64.StdEncoding.EncodeToString(key)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(encoded), 0600); err != nil {
		return fmt.Errorf("writing temp key file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("renaming temp key file: %w", err)
	}
	return nil
}

// HashToken produces a SHA-256 hash of a bearer token for storage in ACL files.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return fmt.Sprintf("sha256:%s", base64.StdEncoding.EncodeToString(h[:]))
}

// MarshalBlob serializes an EncryptedBlob to JSON bytes.
func MarshalBlob(blob *EncryptedBlob) ([]byte, error) {
	return json.Marshal(blob)
}

// UnmarshalBlob deserializes JSON bytes to an EncryptedBlob.
func UnmarshalBlob(data []byte) (*EncryptedBlob, error) {
	var blob EncryptedBlob
	if err := json.Unmarshal(data, &blob); err != nil {
		return nil, fmt.Errorf("unmarshaling blob: %w", err)
	}
	return &blob, nil
}
