package crypto

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateSealKeyPair(t *testing.T) {
	kp1, err := GenerateSealKeyPair()
	if err != nil {
		t.Fatalf("GenerateSealKeyPair: %v", err)
	}

	kp2, err := GenerateSealKeyPair()
	if err != nil {
		t.Fatalf("GenerateSealKeyPair second: %v", err)
	}

	if kp1.PublicKey == kp2.PublicKey {
		t.Error("two generated key pairs have identical public keys")
	}
	if kp1.PrivateKey == kp2.PrivateKey {
		t.Error("two generated key pairs have identical private keys")
	}
}

func TestSealRoundTrip(t *testing.T) {
	kp, err := GenerateSealKeyPair()
	if err != nil {
		t.Fatalf("GenerateSealKeyPair: %v", err)
	}

	path := "myapp/api-key"
	ref := "phoenix://myapp/api-key"
	value := "super-secret-value-12345"

	env, err := SealValue(path, ref, value, &kp.PublicKey)
	if err != nil {
		t.Fatalf("SealValue: %v", err)
	}

	if env.Version != SealVersion {
		t.Errorf("version = %d, want %d", env.Version, SealVersion)
	}
	if env.Algorithm != SealAlgorithm {
		t.Errorf("algorithm = %q, want %q", env.Algorithm, SealAlgorithm)
	}
	if env.Path != path {
		t.Errorf("path = %q, want %q", env.Path, path)
	}
	if env.Ref != ref {
		t.Errorf("ref = %q, want %q", env.Ref, ref)
	}

	payload, err := OpenSealedEnvelope(env, &kp.PrivateKey)
	if err != nil {
		t.Fatalf("OpenSealedEnvelope: %v", err)
	}

	if payload.Value != value {
		t.Errorf("value = %q, want %q", payload.Value, value)
	}
	if payload.Path != path {
		t.Errorf("path = %q, want %q", payload.Path, path)
	}
	if payload.Ref != ref {
		t.Errorf("ref = %q, want %q", payload.Ref, ref)
	}
	if payload.IssuedAt == "" {
		t.Error("issued_at is empty")
	}
}

func TestSealRoundTripNoRef(t *testing.T) {
	kp, err := GenerateSealKeyPair()
	if err != nil {
		t.Fatalf("GenerateSealKeyPair: %v", err)
	}

	env, err := SealValue("db/password", "", "secret", &kp.PublicKey)
	if err != nil {
		t.Fatalf("SealValue: %v", err)
	}

	payload, err := OpenSealedEnvelope(env, &kp.PrivateKey)
	if err != nil {
		t.Fatalf("OpenSealedEnvelope: %v", err)
	}

	if payload.Value != "secret" {
		t.Errorf("value = %q, want %q", payload.Value, "secret")
	}
}

func TestSealWrongKeyRejected(t *testing.T) {
	kp1, _ := GenerateSealKeyPair()
	kp2, _ := GenerateSealKeyPair()

	env, err := SealValue("test/secret", "", "value", &kp1.PublicKey)
	if err != nil {
		t.Fatalf("SealValue: %v", err)
	}

	_, err = OpenSealedEnvelope(env, &kp2.PrivateKey)
	if err != ErrSealDecryptFailed {
		t.Errorf("expected ErrSealDecryptFailed, got %v", err)
	}
}

func TestSealTamperedCiphertextRejected(t *testing.T) {
	kp, _ := GenerateSealKeyPair()

	env, _ := SealValue("test/secret", "", "value", &kp.PublicKey)

	raw, _ := base64.StdEncoding.DecodeString(env.Ciphertext)
	raw[0] ^= 0xff
	env.Ciphertext = base64.StdEncoding.EncodeToString(raw)

	_, err := OpenSealedEnvelope(env, &kp.PrivateKey)
	if err != ErrSealDecryptFailed {
		t.Errorf("expected ErrSealDecryptFailed, got %v", err)
	}
}

func TestSealMalformedBase64Rejected(t *testing.T) {
	kp, _ := GenerateSealKeyPair()

	tests := []struct {
		name   string
		mutate func(env *SealedEnvelope)
	}{
		{"bad ephemeral_key", func(env *SealedEnvelope) { env.EphemeralKey = "not-base64!!!" }},
		{"bad nonce", func(env *SealedEnvelope) { env.Nonce = "not-base64!!!" }},
		{"bad ciphertext", func(env *SealedEnvelope) { env.Ciphertext = "not-base64!!!" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, _ := SealValue("test/secret", "", "value", &kp.PublicKey)
			tt.mutate(env)
			_, err := OpenSealedEnvelope(env, &kp.PrivateKey)
			if err == nil {
				t.Error("expected error for malformed base64")
			}
		})
	}
}

func TestSealPathMismatchRejected(t *testing.T) {
	kp, _ := GenerateSealKeyPair()

	env, _ := SealValue("real/path", "", "value", &kp.PublicKey)
	env.Path = "fake/path"

	_, err := OpenSealedEnvelope(env, &kp.PrivateKey)
	if err != ErrSealPathMismatch {
		t.Errorf("expected ErrSealPathMismatch, got %v", err)
	}
}

func TestSealRefMismatchRejected(t *testing.T) {
	kp, _ := GenerateSealKeyPair()

	env, _ := SealValue("test/path", "phoenix://test/path", "value", &kp.PublicKey)
	env.Ref = "phoenix://other/path"

	_, err := OpenSealedEnvelope(env, &kp.PrivateKey)
	if err != ErrSealRefMismatch {
		t.Errorf("expected ErrSealRefMismatch, got %v", err)
	}
}

func TestSealRefStrippedFromOuterRejected(t *testing.T) {
	kp, _ := GenerateSealKeyPair()

	// Seal with a ref set
	env, _ := SealValue("test/path", "phoenix://test/path", "value", &kp.PublicKey)

	// Attacker strips outer ref to bypass mismatch check
	env.Ref = ""

	_, err := OpenSealedEnvelope(env, &kp.PrivateKey)
	if err != ErrSealRefMismatch {
		t.Errorf("expected ErrSealRefMismatch when outer ref stripped, got %v", err)
	}
}

func TestSealKeyEncodeDecode(t *testing.T) {
	kp, _ := GenerateSealKeyPair()

	encoded := EncodeSealKey(&kp.PublicKey)
	decoded, err := DecodeSealKey(encoded)
	if err != nil {
		t.Fatalf("DecodeSealKey: %v", err)
	}
	if *decoded != kp.PublicKey {
		t.Error("round-trip encode/decode changed key value")
	}
}

func TestDecodeSealKeyBadBase64(t *testing.T) {
	_, err := DecodeSealKey("not-valid-base64!!!")
	if err == nil {
		t.Error("expected error for bad base64")
	}
}

func TestDecodeSealKeyWrongSize(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte("tooshort"))
	_, err := DecodeSealKey(short)
	if err != ErrSealKeySize {
		t.Errorf("expected ErrSealKeySize, got %v", err)
	}
}

func TestDeriveSealPublicKey(t *testing.T) {
	kp, _ := GenerateSealKeyPair()

	derived := DeriveSealPublicKey(&kp.PrivateKey)
	if *derived != kp.PublicKey {
		t.Error("derived public key does not match generated public key")
	}
}

func TestLoadSealPrivateKey(t *testing.T) {
	kp, _ := GenerateSealKeyPair()

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "test.seal.key")

	encoded := EncodeSealKey(&kp.PrivateKey)
	if err := os.WriteFile(keyFile, []byte(encoded), 0600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}

	loaded, err := LoadSealPrivateKey(keyFile)
	if err != nil {
		t.Fatalf("LoadSealPrivateKey: %v", err)
	}
	if *loaded != kp.PrivateKey {
		t.Error("loaded key does not match original")
	}
}

func TestLoadSealPrivateKeyNotFound(t *testing.T) {
	_, err := LoadSealPrivateKey("/nonexistent/path/key.seal")
	if err != ErrSealKeyFileNotFound {
		t.Errorf("expected ErrSealKeyFileNotFound, got %v", err)
	}
}

func TestLoadSealPrivateKeyBadContent(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "bad.seal.key")

	if err := os.WriteFile(keyFile, []byte("not-a-valid-key"), 0600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}

	_, err := LoadSealPrivateKey(keyFile)
	if err == nil {
		t.Error("expected error for bad key content")
	}
}

func TestOpenSealedEnvelopeRejectsWrongVersion(t *testing.T) {
	kp, _ := GenerateSealKeyPair()
	env, _ := SealValue("test/path", "", "value", &kp.PublicKey)

	env.Version = 99

	_, err := OpenSealedEnvelope(env, &kp.PrivateKey)
	if !errors.Is(err, ErrSealVersionUnsup) {
		t.Errorf("expected ErrSealVersionUnsup, got %v", err)
	}
}

func TestOpenSealedEnvelopeRejectsWrongAlgorithm(t *testing.T) {
	kp, _ := GenerateSealKeyPair()
	env, _ := SealValue("test/path", "", "value", &kp.PublicKey)

	env.Algorithm = "aes-256-gcm"

	_, err := OpenSealedEnvelope(env, &kp.PrivateKey)
	if !errors.Is(err, ErrSealAlgorithmUnsup) {
		t.Errorf("expected ErrSealAlgorithmUnsup, got %v", err)
	}
}

func TestLoadSealPrivateKeyInsecurePerms(t *testing.T) {
	kp, _ := GenerateSealKeyPair()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "insecure.seal.key")

	encoded := EncodeSealKey(&kp.PrivateKey)

	// Group-readable (0640)
	if err := os.WriteFile(keyFile, []byte(encoded), 0640); err != nil {
		t.Fatalf("writing key file: %v", err)
	}
	_, err := LoadSealPrivateKey(keyFile)
	if !errors.Is(err, ErrSealKeyInsecurePerm) {
		t.Errorf("expected ErrSealKeyInsecurePerm for 0640, got %v", err)
	}

	// World-readable (0644)
	os.Chmod(keyFile, 0644)
	_, err = LoadSealPrivateKey(keyFile)
	if !errors.Is(err, ErrSealKeyInsecurePerm) {
		t.Errorf("expected ErrSealKeyInsecurePerm for 0644, got %v", err)
	}

	// Owner-only (0600) should succeed
	os.Chmod(keyFile, 0600)
	_, err = LoadSealPrivateKey(keyFile)
	if err != nil {
		t.Errorf("expected success for 0600, got %v", err)
	}
}

func TestSealEphemeralKeyWrongSize(t *testing.T) {
	kp, _ := GenerateSealKeyPair()
	env, _ := SealValue("test/path", "", "value", &kp.PublicKey)

	env.EphemeralKey = base64.StdEncoding.EncodeToString([]byte("short"))

	_, err := OpenSealedEnvelope(env, &kp.PrivateKey)
	if err == nil {
		t.Error("expected error for wrong-size ephemeral key")
	}
}

func TestSealNonceWrongSize(t *testing.T) {
	kp, _ := GenerateSealKeyPair()
	env, _ := SealValue("test/path", "", "value", &kp.PublicKey)

	env.Nonce = base64.StdEncoding.EncodeToString([]byte("short"))

	_, err := OpenSealedEnvelope(env, &kp.PrivateKey)
	if err == nil {
		t.Error("expected error for wrong-size nonce")
	}
}
