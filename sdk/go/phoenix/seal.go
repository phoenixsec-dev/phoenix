package phoenix

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// openSealedEnvelope decrypts a sealed envelope using the recipient's private key.
func openSealedEnvelope(env *SealedEnvelope, privKey *[32]byte) (string, error) {
	if env.Version != 1 {
		return "", fmt.Errorf("unsupported seal version: %d", env.Version)
	}
	if env.Algorithm != "x25519-xsalsa20-poly1305" {
		return "", fmt.Errorf("unsupported seal algorithm: %s", env.Algorithm)
	}

	ephPub, err := base64.StdEncoding.DecodeString(env.EphemeralKey)
	if err != nil || len(ephPub) != 32 {
		return "", fmt.Errorf("invalid ephemeral key")
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil || len(nonce) != 24 {
		return "", fmt.Errorf("invalid nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("invalid ciphertext")
	}

	var ephPubKey [32]byte
	var nonceArr [24]byte
	copy(ephPubKey[:], ephPub)
	copy(nonceArr[:], nonce)

	plaintext, ok := box.Open(nil, ciphertext, &nonceArr, &ephPubKey, privKey)
	if !ok {
		return "", fmt.Errorf("decryption failed")
	}

	var payload struct {
		Path     string `json:"path"`
		Ref      string `json:"ref"`
		Value    string `json:"value"`
		IssuedAt string `json:"issued_at"`
	}
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return "", fmt.Errorf("parsing decrypted payload: %v", err)
	}

	// Verify inner/outer binding
	if payload.Path != env.Path {
		return "", fmt.Errorf("path mismatch: inner=%q outer=%q", payload.Path, env.Path)
	}
	if payload.Ref != env.Ref {
		return "", fmt.Errorf("ref mismatch: inner=%q outer=%q", payload.Ref, env.Ref)
	}

	return payload.Value, nil
}

// decodeSealKey decodes a base64-encoded 32-byte key.
func decodeSealKey(encoded string) (*[32]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decoding seal key: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("seal key must be 32 bytes, got %d", len(raw))
	}
	var key [32]byte
	copy(key[:], raw)
	return &key, nil
}

// encodeSealKey encodes a 32-byte key to base64.
func encodeSealKey(key *[32]byte) string {
	return base64.StdEncoding.EncodeToString(key[:])
}

// deriveSealPublicKey derives the X25519 public key from a private key.
func deriveSealPublicKey(privKey *[32]byte) *[32]byte {
	var pubKey [32]byte
	pub, _ := curve25519.X25519(privKey[:], curve25519.Basepoint)
	copy(pubKey[:], pub)
	return &pubKey
}
