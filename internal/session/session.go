// Package session implements v1 session identity for Phoenix.
//
// Agents mint session tokens by authenticating via an existing channel
// (mTLS, bearer, or local) and requesting a role. The session token is
// scoped to the role's namespaces and optionally bound to a seal key
// fingerprint. Tokens are HMAC-SHA256 signed and carry a "phxs_" prefix
// to distinguish them from short-lived attestation tokens.
package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// TokenPrefix distinguishes session tokens from other token types.
	TokenPrefix = "phxs_"
	// SessionIDBytes is the number of random bytes in a session ID.
	SessionIDBytes = 16
	// SigningKeyBytes is the size of the HMAC signing key.
	SigningKeyBytes = 32
	// DefaultTTL is the default session lifetime.
	DefaultTTL = 1 * time.Hour
)

var (
	ErrTokenExpired     = errors.New("session token expired")
	ErrTokenMalformed   = errors.New("malformed session token")
	ErrSignatureInvalid = errors.New("invalid session token signature")
	ErrSessionRevoked   = errors.New("session has been revoked")
	ErrSessionNotFound  = errors.New("session not found")
)

// Default actions granted when a role's Actions list is empty.
var DefaultActions = []string{"list", "read_value"}

// Session represents an active agent session.
type Session struct {
	ID                 string    `json:"session_id"`
	Role               string    `json:"role"`
	Agent              string    `json:"agent"`
	SealKeyFingerprint string    `json:"seal_key_fingerprint,omitempty"`
	CertFingerprint    string    `json:"-"`
	ElevatesACL        bool      `json:"elevates_acl,omitempty"`
	Namespaces         []string  `json:"namespaces"`
	Actions            []string  `json:"actions"`
	BootstrapMethod    string    `json:"bootstrap_method"`
	SourceIP           string    `json:"source_ip"`
	CreatedAt          time.Time `json:"created_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	Revoked            bool      `json:"revoked"`
}

// ActionAllowed returns true if the given action is permitted by this session.
func (s *Session) ActionAllowed(action string) bool {
	for _, a := range s.Actions {
		if a == action {
			return true
		}
		// "admin" implies everything
		if a == "admin" {
			return true
		}
	}
	return false
}

// Claims are the HMAC-signed payload in the session token wire format.
type Claims struct {
	SessionID          string    `json:"sid"`
	Role               string    `json:"role"`
	Agent              string    `json:"agent"`
	SealKeyFingerprint string    `json:"skfp,omitempty"`
	ElevatesACL        bool      `json:"eacl,omitempty"`
	ExpiresAt          time.Time `json:"exp"`
	IssuedAt           time.Time `json:"iat"`
}

// generateSessionID creates a random hex-encoded session ID.
func generateSessionID() (string, error) {
	b := make([]byte, SessionIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating session ID: %w", err)
	}
	return "ses_" + hex.EncodeToString(b), nil
}

// mintToken creates a signed session token from claims using the given key.
func mintToken(claims *Claims, signingKey []byte) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshaling session claims: %w", err)
	}

	sig := sign(payload, signingKey)

	token := TokenPrefix +
		base64.RawURLEncoding.EncodeToString(payload) +
		"." +
		base64.RawURLEncoding.EncodeToString(sig)

	return token, nil
}

// validateToken verifies a session token's signature and expiry.
func validateToken(tokenStr string, signingKey []byte) (*Claims, error) {
	if !strings.HasPrefix(tokenStr, TokenPrefix) {
		return nil, ErrTokenMalformed
	}
	tokenStr = strings.TrimPrefix(tokenStr, TokenPrefix)

	dot := strings.LastIndexByte(tokenStr, '.')
	if dot < 0 {
		return nil, ErrTokenMalformed
	}

	payloadB64 := tokenStr[:dot]
	sigB64 := tokenStr[dot+1:]

	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, ErrTokenMalformed
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, ErrTokenMalformed
	}

	expected := sign(payload, signingKey)
	if !hmac.Equal(sig, expected) {
		return nil, ErrSignatureInvalid
	}

	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrTokenMalformed
	}

	if time.Now().After(claims.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	return &claims, nil
}

// validateTokenNoExpiry verifies signature and parses claims but skips the
// expiry check. Used for audit logging of expired/revoked session tokens
// where we need the agent identity even though the token is no longer valid.
func validateTokenNoExpiry(tokenStr string, signingKey []byte) (*Claims, error) {
	if !strings.HasPrefix(tokenStr, TokenPrefix) {
		return nil, ErrTokenMalformed
	}
	tokenStr = strings.TrimPrefix(tokenStr, TokenPrefix)

	dot := strings.LastIndexByte(tokenStr, '.')
	if dot < 0 {
		return nil, ErrTokenMalformed
	}

	payload, err := base64.RawURLEncoding.DecodeString(tokenStr[:dot])
	if err != nil {
		return nil, ErrTokenMalformed
	}

	sig, err := base64.RawURLEncoding.DecodeString(tokenStr[dot+1:])
	if err != nil {
		return nil, ErrTokenMalformed
	}

	if !hmac.Equal(sig, sign(payload, signingKey)) {
		return nil, ErrSignatureInvalid
	}

	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrTokenMalformed
	}

	return &claims, nil
}

// sign computes HMAC-SHA256 of the payload.
func sign(payload, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return mac.Sum(nil)
}

// SealKeyFingerprint computes a fingerprint of a seal public key.
// Format matches certFingerprint in api.go: "sha256:<UPPERCASE_HEX>".
func SealKeyFingerprint(pubKey []byte) string {
	h := sha256.Sum256(pubKey)
	return fmt.Sprintf("sha256:%X", h[:])
}

// PathInScope checks if a secret path falls within any of the given
// namespace patterns. Supports the same glob syntax as ACL rules:
// "*" matches everything, "ns/*" matches one level, "ns/**" matches recursively.
func PathInScope(path string, namespaces []string) bool {
	for _, ns := range namespaces {
		if matchNamespace(ns, path) {
			return true
		}
	}
	return false
}

func matchNamespace(pattern, path string) bool {
	if pattern == "*" || pattern == "**" {
		return true
	}
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return strings.HasPrefix(path, prefix+"/") || path == prefix
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		if !strings.HasPrefix(path, prefix+"/") {
			return false
		}
		rest := strings.TrimPrefix(path, prefix+"/")
		return !strings.Contains(rest, "/")
	}
	return pattern == path
}

// IsLoopback returns true if the IP address is a loopback address.
func IsLoopback(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1"
}
