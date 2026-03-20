package session

import (
	"crypto/rand"
	"testing"
	"time"
)

func TestMintValidateRoundtrip(t *testing.T) {
	key := make([]byte, SigningKeyBytes)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	claims := &Claims{
		SessionID: "ses_test123",
		Role:      "dev",
		Agent:     "test-agent",
		ExpiresAt: time.Now().Add(time.Hour),
		IssuedAt:  time.Now(),
	}

	token, err := mintToken(claims, key)
	if err != nil {
		t.Fatalf("mintToken: %v", err)
	}

	if token[:len(TokenPrefix)] != TokenPrefix {
		t.Fatalf("token missing prefix: %s", token[:10])
	}

	got, err := validateToken(token, key)
	if err != nil {
		t.Fatalf("validateToken: %v", err)
	}

	if got.SessionID != claims.SessionID {
		t.Errorf("SessionID = %q, want %q", got.SessionID, claims.SessionID)
	}
	if got.Role != claims.Role {
		t.Errorf("Role = %q, want %q", got.Role, claims.Role)
	}
	if got.Agent != claims.Agent {
		t.Errorf("Agent = %q, want %q", got.Agent, claims.Agent)
	}
}

func TestValidateExpiredToken(t *testing.T) {
	key := make([]byte, SigningKeyBytes)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	claims := &Claims{
		SessionID: "ses_expired",
		Role:      "dev",
		Agent:     "test-agent",
		ExpiresAt: time.Now().Add(-time.Minute),
		IssuedAt:  time.Now().Add(-time.Hour),
	}

	token, err := mintToken(claims, key)
	if err != nil {
		t.Fatalf("mintToken: %v", err)
	}

	_, err = validateToken(token, key)
	if err != ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestValidateTamperedToken(t *testing.T) {
	key := make([]byte, SigningKeyBytes)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	claims := &Claims{
		SessionID: "ses_tamper",
		Role:      "dev",
		Agent:     "test-agent",
		ExpiresAt: time.Now().Add(time.Hour),
		IssuedAt:  time.Now(),
	}

	token, err := mintToken(claims, key)
	if err != nil {
		t.Fatalf("mintToken: %v", err)
	}

	// Flip a character in the payload portion
	tampered := []byte(token)
	tampered[len(TokenPrefix)+5] ^= 0xFF
	_, err = validateToken(string(tampered), key)
	if err == nil {
		t.Fatal("expected error for tampered token")
	}
}

func TestValidateWrongKey(t *testing.T) {
	key1 := make([]byte, SigningKeyBytes)
	key2 := make([]byte, SigningKeyBytes)
	if _, err := rand.Read(key1); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(key2); err != nil {
		t.Fatal(err)
	}

	claims := &Claims{
		SessionID: "ses_wrongkey",
		Role:      "dev",
		Agent:     "test-agent",
		ExpiresAt: time.Now().Add(time.Hour),
		IssuedAt:  time.Now(),
	}

	token, err := mintToken(claims, key1)
	if err != nil {
		t.Fatalf("mintToken: %v", err)
	}

	_, err = validateToken(token, key2)
	if err != ErrSignatureInvalid {
		t.Fatalf("expected ErrSignatureInvalid, got %v", err)
	}
}

func TestValidateMalformedTokens(t *testing.T) {
	key := make([]byte, SigningKeyBytes)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	cases := []string{
		"",
		"not-a-token",
		"phxs_",
		"phxs_nodot",
		"phxs_bad.bad",
		"wrong_prefix.stuff",
	}

	for _, tc := range cases {
		_, err := validateToken(tc, key)
		if err == nil {
			t.Errorf("validateToken(%q): expected error, got nil", tc)
		}
	}
}

func TestSealKeyFingerprint(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	fp := SealKeyFingerprint(key)
	if fp[:7] != "sha256:" {
		t.Fatalf("fingerprint missing sha256: prefix: %s", fp)
	}
	if len(fp) != 7+64 { // "sha256:" + 64 hex chars
		t.Fatalf("fingerprint wrong length: %d", len(fp))
	}

	// Same input -> same output
	fp2 := SealKeyFingerprint(key)
	if fp != fp2 {
		t.Errorf("fingerprint not deterministic: %s != %s", fp, fp2)
	}

	// Different input -> different output
	key[0] = 0xFF
	fp3 := SealKeyFingerprint(key)
	if fp == fp3 {
		t.Error("different keys produced same fingerprint")
	}
}

func TestSealKeyFingerprintWithBinding(t *testing.T) {
	key := make([]byte, SigningKeyBytes)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	sealKey := make([]byte, 32)
	if _, err := rand.Read(sealKey); err != nil {
		t.Fatal(err)
	}

	fp := SealKeyFingerprint(sealKey)

	claims := &Claims{
		SessionID:          "ses_sealbound",
		Role:               "secure",
		Agent:              "test-agent",
		SealKeyFingerprint: fp,
		ExpiresAt:          time.Now().Add(time.Hour),
		IssuedAt:           time.Now(),
	}

	token, err := mintToken(claims, key)
	if err != nil {
		t.Fatalf("mintToken: %v", err)
	}

	got, err := validateToken(token, key)
	if err != nil {
		t.Fatalf("validateToken: %v", err)
	}

	if got.SealKeyFingerprint != fp {
		t.Errorf("SealKeyFingerprint = %q, want %q", got.SealKeyFingerprint, fp)
	}
}
