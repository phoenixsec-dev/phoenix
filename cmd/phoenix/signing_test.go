package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func writeTestKey(t *testing.T, dir string) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	path := filepath.Join(dir, "test.key")
	if err := os.WriteFile(path, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path, key
}

func TestSignPayloadAndVerify(t *testing.T) {
	dir := t.TempDir()
	keyPath, key := writeTestKey(t, dir)

	data := []byte("test payload to sign")
	sig, err := signPayload(keyPath, data)
	if err != nil {
		t.Fatalf("signPayload: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature should not be empty")
	}

	// Verify the signature
	hash := sha256Digest(data)
	if !ecdsa.VerifyASN1(&key.PublicKey, hash, sig) {
		t.Fatal("signature verification failed")
	}
}

func TestSignPayloadFileNotFound(t *testing.T) {
	_, err := signPayload("/nonexistent/key.pem", []byte("data"))
	if err == nil {
		t.Fatal("expected error for missing key file")
	}
}

func TestSignPayloadInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.key")
	os.WriteFile(path, []byte("not a pem file"), 0600)

	_, err := signPayload(path, []byte("data"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestParseECDSAPrivateKeyEC(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	parsed, err := parseECDSAPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parseECDSAPrivateKey EC format: %v", err)
	}
	if !parsed.PublicKey.Equal(&key.PublicKey) {
		t.Fatal("parsed key doesn't match original")
	}
}

func TestParseECDSAPrivateKeyPKCS8(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	parsed, err := parseECDSAPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parseECDSAPrivateKey PKCS8 format: %v", err)
	}
	if !parsed.PublicKey.Equal(&key.PublicKey) {
		t.Fatal("parsed key doesn't match original")
	}
}

func TestParseECDSAPrivateKeyInvalidPEM(t *testing.T) {
	_, err := parseECDSAPrivateKey([]byte("not pem"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestSha256Digest(t *testing.T) {
	digest := sha256Digest([]byte("hello"))
	if len(digest) != 32 {
		t.Fatalf("expected 32-byte digest, got %d", len(digest))
	}
	// Same input = same digest
	digest2 := sha256Digest([]byte("hello"))
	if string(digest) != string(digest2) {
		t.Fatal("same input should produce same digest")
	}
	// Different input = different digest
	digest3 := sha256Digest([]byte("world"))
	if string(digest) == string(digest3) {
		t.Fatal("different input should produce different digest")
	}
}
