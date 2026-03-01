package token

import (
	"testing"
	"time"
)

func TestMintAndValidate(t *testing.T) {
	iss, err := NewIssuer(5 * time.Minute)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}

	tok, claims, err := iss.Mint("test-agent", nil, "")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok == "" {
		t.Fatal("expected non-empty token")
	}
	if claims.Agent != "test-agent" {
		t.Fatalf("agent = %q, want test-agent", claims.Agent)
	}
	if claims.IssuedAt.IsZero() {
		t.Fatal("expected non-zero IssuedAt")
	}
	if claims.ExpiresAt.IsZero() {
		t.Fatal("expected non-zero ExpiresAt")
	}

	// Validate
	validated, err := iss.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if validated.Agent != "test-agent" {
		t.Fatalf("validated agent = %q, want test-agent", validated.Agent)
	}
}

func TestMintWithProcessClaims(t *testing.T) {
	iss, _ := NewIssuer(5 * time.Minute)

	uid := 1001
	tok, claims, err := iss.Mint("worker", &uid, "sha256:abc123")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	if claims.ProcessUID == nil || *claims.ProcessUID != 1001 {
		t.Fatalf("ProcessUID = %v, want 1001", claims.ProcessUID)
	}
	if claims.BinaryHash != "sha256:abc123" {
		t.Fatalf("BinaryHash = %q, want sha256:abc123", claims.BinaryHash)
	}

	validated, err := iss.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if validated.ProcessUID == nil || *validated.ProcessUID != 1001 {
		t.Fatalf("validated ProcessUID = %v, want 1001", validated.ProcessUID)
	}
}

func TestExpiredToken(t *testing.T) {
	iss, _ := NewIssuer(1 * time.Millisecond)

	tok, _, _ := iss.Mint("test", nil, "")
	time.Sleep(10 * time.Millisecond)

	_, err := iss.Validate(tok)
	if err != ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired, got: %v", err)
	}
}

func TestTamperedToken(t *testing.T) {
	iss, _ := NewIssuer(5 * time.Minute)

	tok, _, _ := iss.Mint("test", nil, "")

	// Tamper with token
	tampered := tok[:len(tok)-2] + "XX"
	_, err := iss.Validate(tampered)
	if err != ErrSignatureInvalid {
		t.Fatalf("expected ErrSignatureInvalid, got: %v", err)
	}
}

func TestMalformedToken(t *testing.T) {
	iss, _ := NewIssuer(5 * time.Minute)

	tests := []string{
		"",
		"not-a-token",
		"....",
		"abc",
	}

	for _, tok := range tests {
		_, err := iss.Validate(tok)
		if err == nil {
			t.Fatalf("expected error for malformed token %q", tok)
		}
	}
}

func TestDifferentKeyRejectsToken(t *testing.T) {
	iss1, _ := NewIssuer(5 * time.Minute)
	iss2, _ := NewIssuer(5 * time.Minute)

	tok, _, _ := iss1.Mint("test", nil, "")

	_, err := iss2.Validate(tok)
	if err != ErrSignatureInvalid {
		t.Fatalf("expected ErrSignatureInvalid for different key, got: %v", err)
	}
}

func TestDefaultTTL(t *testing.T) {
	iss, _ := NewIssuer(0)
	if iss.TTL() != DefaultTTL {
		t.Fatalf("expected default TTL %v, got %v", DefaultTTL, iss.TTL())
	}
}

func TestNewIssuerWithKeyTooShort(t *testing.T) {
	_, err := NewIssuerWithKey([]byte("short"), 5*time.Minute)
	if err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestTokenCrossIssuerAgent(t *testing.T) {
	// Tokens are HMAC-signed, so validation is scoped to the issuer's key.
	// Verify that a token minted for agent "A" can be validated (returns claims)
	// and the caller is responsible for checking the agent name.
	iss, _ := NewIssuer(5 * time.Minute)

	tok, _, _ := iss.Mint("agent-a", nil, "")

	claims, err := iss.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// The issuer doesn't enforce agent identity — caller must check.
	if claims.Agent != "agent-a" {
		t.Fatalf("expected agent 'agent-a', got %q", claims.Agent)
	}
}

func TestTokenTTL(t *testing.T) {
	ttl := 30 * time.Second
	iss, _ := NewIssuer(ttl)
	if iss.TTL() != ttl {
		t.Fatalf("expected TTL %v, got %v", ttl, iss.TTL())
	}
}

func TestNewIssuerWithKey(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	iss, err := NewIssuerWithKey(key, 5*time.Minute)
	if err != nil {
		t.Fatalf("NewIssuerWithKey: %v", err)
	}

	tok, _, _ := iss.Mint("agent", nil, "")

	// Same key validates
	iss2, _ := NewIssuerWithKey(key, 5*time.Minute)
	_, err = iss2.Validate(tok)
	if err != nil {
		t.Fatalf("same key should validate: %v", err)
	}
}
