package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

const (
	SealKeySize   = 32
	SealNonceSize = 24
	SealAlgorithm = "x25519-xsalsa20-poly1305"
	SealVersion   = 1
)

var (
	ErrSealKeySize         = errors.New("seal key must be exactly 32 bytes")
	ErrSealDecryptFailed   = errors.New("sealed envelope decryption failed")
	ErrSealPathMismatch    = errors.New("inner/outer path mismatch: envelope may be tampered")
	ErrSealRefMismatch     = errors.New("inner/outer ref mismatch: envelope may be tampered")
	ErrSealKeyFileNotFound = errors.New("seal key file not found")
	ErrSealKeyInsecurePerm = errors.New("seal key file has insecure permissions: must not be readable by group or others")
	ErrSealVersionUnsup    = errors.New("unsupported sealed envelope version")
	ErrSealAlgorithmUnsup  = errors.New("unsupported sealed envelope algorithm")
)

// SealKeyPair holds an X25519 key pair for sealed responses.
type SealKeyPair struct {
	PublicKey  [32]byte
	PrivateKey [32]byte
}

// SealedEnvelope is the outer wire format for a sealed secret value.
type SealedEnvelope struct {
	Version      int    `json:"version"`
	Algorithm    string `json:"algorithm"`
	Path         string `json:"path"`
	Ref          string `json:"ref,omitempty"`
	EphemeralKey string `json:"ephemeral_key"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
}

// SealedPayload is the inner encrypted payload bound inside the ciphertext.
type SealedPayload struct {
	Path     string `json:"path"`
	Ref      string `json:"ref,omitempty"`
	Value    string `json:"value"`
	IssuedAt string `json:"issued_at"`
}

// GenerateSealKeyPair creates a new X25519 key pair for sealed responses.
func GenerateSealKeyPair() (*SealKeyPair, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating seal key pair: %w", err)
	}
	return &SealKeyPair{
		PublicKey:  *pub,
		PrivateKey: *priv,
	}, nil
}

// SealValue encrypts a secret value for a specific recipient using NaCl box.
// It creates an ephemeral X25519 key pair, encrypts the payload, and discards
// the ephemeral private key.
func SealValue(path, ref, value string, recipientPubKey *[32]byte) (*SealedEnvelope, error) {
	payload := SealedPayload{
		Path:     path,
		Ref:      ref,
		Value:    value,
		IssuedAt: time.Now().UTC().Format(time.RFC3339),
	}

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling sealed payload: %w", err)
	}

	ephPub, ephPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral key: %w", err)
	}
	defer func() {
		ZeroBytes(ephPriv[:])
	}()

	var nonce [SealNonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := box.Seal(nil, plaintext, &nonce, recipientPubKey, ephPriv)

	return &SealedEnvelope{
		Version:      SealVersion,
		Algorithm:    SealAlgorithm,
		Path:         path,
		Ref:          ref,
		EphemeralKey: base64.StdEncoding.EncodeToString(ephPub[:]),
		Nonce:        base64.StdEncoding.EncodeToString(nonce[:]),
		Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

// OpenSealedEnvelope decrypts a sealed envelope using the recipient's private key.
// After decryption, it verifies that the inner path/ref match the outer envelope
// to prevent relabeling attacks.
func OpenSealedEnvelope(env *SealedEnvelope, recipientPrivKey *[32]byte) (*SealedPayload, error) {
	if env.Version != SealVersion {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrSealVersionUnsup, env.Version, SealVersion)
	}
	if env.Algorithm != SealAlgorithm {
		return nil, fmt.Errorf("%w: got %q", ErrSealAlgorithmUnsup, env.Algorithm)
	}

	ephKeyBytes, err := base64.StdEncoding.DecodeString(env.EphemeralKey)
	if err != nil {
		return nil, fmt.Errorf("decoding ephemeral key: %w", err)
	}
	if len(ephKeyBytes) != SealKeySize {
		return nil, fmt.Errorf("ephemeral key wrong size: got %d, want %d", len(ephKeyBytes), SealKeySize)
	}

	nonceBytes, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decoding nonce: %w", err)
	}
	if len(nonceBytes) != SealNonceSize {
		return nil, fmt.Errorf("nonce wrong size: got %d, want %d", len(nonceBytes), SealNonceSize)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decoding ciphertext: %w", err)
	}

	var ephPub [32]byte
	copy(ephPub[:], ephKeyBytes)

	var nonce [24]byte
	copy(nonce[:], nonceBytes)

	plaintext, ok := box.Open(nil, ciphertext, &nonce, &ephPub, recipientPrivKey)
	if !ok {
		return nil, ErrSealDecryptFailed
	}

	var payload SealedPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("unmarshaling sealed payload: %w", err)
	}

	if payload.Path != env.Path {
		return nil, ErrSealPathMismatch
	}
	if payload.Ref != env.Ref {
		return nil, ErrSealRefMismatch
	}

	return &payload, nil
}

// LoadSealPrivateKey reads a base64-encoded 32-byte X25519 private key from a file.
func LoadSealPrivateKey(path string) (*[32]byte, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrSealKeyFileNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("stat seal key file: %w", err)
	}

	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s has mode %04o", ErrSealKeyInsecurePerm, path, info.Mode().Perm())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading seal key file: %w", err)
	}

	key, err := DecodeSealKey(string(data))
	if err != nil {
		return nil, fmt.Errorf("decoding seal key from %s: %w", path, err)
	}
	return key, nil
}

// DeriveSealPublicKey derives the X25519 public key from a private key.
func DeriveSealPublicKey(privKey *[32]byte) *[32]byte {
	pub, _ := curve25519.X25519(privKey[:], curve25519.Basepoint)
	var out [32]byte
	copy(out[:], pub)
	return &out
}

// EncodeSealKey encodes a 32-byte key as base64.
func EncodeSealKey(key *[32]byte) string {
	return base64.StdEncoding.EncodeToString(key[:])
}

// DecodeSealKey decodes a base64-encoded 32-byte key.
func DecodeSealKey(encoded string) (*[32]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	if len(raw) != SealKeySize {
		return nil, ErrSealKeySize
	}
	var key [32]byte
	copy(key[:], raw)
	return &key, nil
}
