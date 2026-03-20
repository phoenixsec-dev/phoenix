package session

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

const (
	// CleanupInterval is how often expired/revoked sessions are purged.
	CleanupInterval = 60 * time.Second
)

// Store manages session lifecycle: creation, validation, revocation, and cleanup.
type Store struct {
	mu         sync.RWMutex
	sessions   map[string]*Session // keyed by session ID
	signingKey []byte
	defaultTTL time.Duration
	stopCh     chan struct{}
	stopped    bool
}

// NewStore creates a new session store with the given default TTL.
// If defaultTTL is zero, DefaultTTL (1h) is used.
// Call Stop() when the store is no longer needed.
func NewStore(defaultTTL time.Duration) (*Store, error) {
	if defaultTTL <= 0 {
		defaultTTL = DefaultTTL
	}

	key := make([]byte, SigningKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating session signing key: %w", err)
	}

	s := &Store{
		sessions:   make(map[string]*Session),
		signingKey: key,
		defaultTTL: defaultTTL,
		stopCh:     make(chan struct{}),
	}

	go s.cleanupLoop()
	return s, nil
}

// Create mints a new session and returns the signed token.
func (s *Store) Create(role, agent string, sealPubKey []byte, namespaces, actions []string, bootstrapMethod, certFingerprint, sourceIP string, ttl time.Duration) (string, *Session, error) {
	if ttl <= 0 {
		ttl = s.defaultTTL
	}

	id, err := generateSessionID()
	if err != nil {
		return "", nil, err
	}

	now := time.Now().UTC()
	var fingerprint string
	if len(sealPubKey) > 0 {
		fingerprint = SealKeyFingerprint(sealPubKey)
	}

	if len(actions) == 0 {
		actions = DefaultActions
	}

	sess := &Session{
		ID:                 id,
		Role:               role,
		Agent:              agent,
		SealKeyFingerprint: fingerprint,
		CertFingerprint:    certFingerprint,
		Namespaces:         namespaces,
		Actions:            actions,
		BootstrapMethod:    bootstrapMethod,
		SourceIP:           sourceIP,
		CreatedAt:          now,
		ExpiresAt:          now.Add(ttl),
	}

	claims := &Claims{
		SessionID:          id,
		Role:               role,
		Agent:              agent,
		SealKeyFingerprint: fingerprint,
		ExpiresAt:          sess.ExpiresAt,
		IssuedAt:           now,
	}

	token, err := mintToken(claims, s.signingKey)
	if err != nil {
		return "", nil, err
	}

	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()

	return token, sess, nil
}

// Renew extends an existing session's expiry and mints a new signed token.
// The session ID is preserved so the audit trail remains continuous.
// Returns ErrSessionNotFound, ErrSessionRevoked, or ErrTokenExpired as appropriate.
func (s *Store) Renew(sessionID string, ttl time.Duration) (string, *Session, error) {
	if ttl <= 0 {
		ttl = s.defaultTTL
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[sessionID]
	if !ok {
		return "", nil, ErrSessionNotFound
	}
	if sess.Revoked {
		return "", nil, ErrSessionRevoked
	}
	if time.Now().After(sess.ExpiresAt) {
		return "", nil, ErrTokenExpired
	}

	now := time.Now().UTC()
	sess.ExpiresAt = now.Add(ttl)

	claims := &Claims{
		SessionID:          sess.ID,
		Role:               sess.Role,
		Agent:              sess.Agent,
		SealKeyFingerprint: sess.SealKeyFingerprint,
		ExpiresAt:          sess.ExpiresAt,
		IssuedAt:           now,
	}

	token, err := mintToken(claims, s.signingKey)
	if err != nil {
		return "", nil, err
	}

	return token, sess, nil
}

// Validate verifies a session token and returns the associated session.
// Returns ErrSessionRevoked if the session was explicitly revoked,
// ErrTokenExpired if the TTL elapsed, or ErrSessionNotFound if the
// session ID in the token doesn't match any active session.
func (s *Store) Validate(tokenStr string) (*Session, error) {
	claims, err := validateToken(tokenStr, s.signingKey)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	sess, ok := s.sessions[claims.SessionID]
	s.mu.RUnlock()

	if !ok {
		return nil, ErrSessionNotFound
	}

	if sess.Revoked {
		return nil, ErrSessionRevoked
	}

	if time.Now().After(sess.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	return sess, nil
}

// Revoke marks a session as revoked. Revocation is idempotent.
func (s *Store) Revoke(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}
	sess.Revoked = true
	return nil
}

// Get returns a session by ID, or nil if not found.
func (s *Store) Get(sessionID string) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[sessionID]
}

// List returns all active (non-expired, non-revoked) sessions.
func (s *Store) List() []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	var result []*Session
	for _, sess := range s.sessions {
		if !sess.Revoked && now.Before(sess.ExpiresAt) {
			result = append(result, sess)
		}
	}
	return result
}

// ParseClaimsInsecure extracts the agent and session ID from a session token
// without checking expiry. The HMAC signature is still verified to prevent
// logging spoofed identities. Returns ok=false if the token is malformed
// or has an invalid signature.
func (s *Store) ParseClaimsInsecure(tokenStr string) (agent, sessionID string, ok bool) {
	claims, err := validateTokenNoExpiry(tokenStr, s.signingKey)
	if err != nil {
		return "", "", false
	}
	return claims.Agent, claims.SessionID, true
}

// ActiveCount returns the number of active sessions.
func (s *Store) ActiveCount() int {
	return len(s.List())
}

// Stop halts the background cleanup goroutine.
func (s *Store) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.stopped {
		close(s.stopCh)
		s.stopped = true
	}
}

func (s *Store) cleanupLoop() {
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.cleanup()
		}
	}
}

func (s *Store) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, sess := range s.sessions {
		if sess.Revoked || now.After(sess.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
}
