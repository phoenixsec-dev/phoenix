// Package token implements short-lived credential minting and validation
// for Phoenix attestation flows.
//
// Instead of long-lived certificates (90-day default), the local attestation
// agent can mint ephemeral tokens with short TTLs (default 15 minutes).
// If a token leaks, it expires almost immediately.
//
// Tokens are HMAC-SHA256 signed JSON payloads containing the agent identity,
// issued-at timestamp, expiry, and attestation claims from the process
// attestation step.
package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	// DefaultTTL is the default token lifetime.
	DefaultTTL = 15 * time.Minute
	// SigningKeyBytes is the size of the HMAC signing key.
	SigningKeyBytes = 32
)

var (
	ErrTokenExpired    = errors.New("token expired")
	ErrTokenMalformed  = errors.New("malformed token")
	ErrSignatureInvalid = errors.New("invalid token signature")
)

// Claims contains the attestation claims embedded in a token.
type Claims struct {
	Agent      string    `json:"agent"`
	IssuedAt   time.Time `json:"iat"`
	ExpiresAt  time.Time `json:"exp"`
	ProcessUID *int      `json:"proc_uid,omitempty"`
	BinaryHash string    `json:"binary_hash,omitempty"`
}

// Issuer mints and validates short-lived tokens.
type Issuer struct {
	signingKey []byte
	ttl        time.Duration
}

// NewIssuer creates a token issuer with a random signing key and the given TTL.
// If ttl is zero, DefaultTTL is used.
func NewIssuer(ttl time.Duration) (*Issuer, error) {
	key := make([]byte, SigningKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating signing key: %w", err)
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Issuer{signingKey: key, ttl: ttl}, nil
}

// NewIssuerWithKey creates a token issuer with the given signing key and TTL.
func NewIssuerWithKey(key []byte, ttl time.Duration) (*Issuer, error) {
	if len(key) < SigningKeyBytes {
		return nil, fmt.Errorf("signing key must be at least %d bytes", SigningKeyBytes)
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Issuer{signingKey: key, ttl: ttl}, nil
}

// Mint creates a new token for the given agent with optional process claims.
func (iss *Issuer) Mint(agent string, procUID *int, binaryHash string) (string, *Claims, error) {
	now := time.Now().UTC()
	claims := &Claims{
		Agent:      agent,
		IssuedAt:   now,
		ExpiresAt:  now.Add(iss.ttl),
		ProcessUID: procUID,
		BinaryHash: binaryHash,
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", nil, fmt.Errorf("marshaling claims: %w", err)
	}

	sig := iss.sign(payload)

	// Token format: base64(payload).base64(signature)
	token := base64.RawURLEncoding.EncodeToString(payload) +
		"." +
		base64.RawURLEncoding.EncodeToString(sig)

	return token, claims, nil
}

// Validate verifies a token's signature and expiry, returning the claims.
func (iss *Issuer) Validate(token string) (*Claims, error) {
	// Split token into payload and signature
	dot := -1
	for i := len(token) - 1; i >= 0; i-- {
		if token[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		return nil, ErrTokenMalformed
	}

	payloadB64 := token[:dot]
	sigB64 := token[dot+1:]

	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, ErrTokenMalformed
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, ErrTokenMalformed
	}

	// Verify signature
	expected := iss.sign(payload)
	if !hmac.Equal(sig, expected) {
		return nil, ErrSignatureInvalid
	}

	// Parse claims
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrTokenMalformed
	}

	// Check expiry
	if time.Now().After(claims.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	return &claims, nil
}

// TTL returns the configured token lifetime.
func (iss *Issuer) TTL() time.Duration {
	return iss.ttl
}

// sign computes HMAC-SHA256 of the payload.
func (iss *Issuer) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, iss.signingKey)
	mac.Write(payload)
	return mac.Sum(nil)
}
