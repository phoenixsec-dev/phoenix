package session

import (
	"crypto/rand"
	"fmt"
	"log"
	"sync"
	"time"
)

const (
	// CleanupInterval is how often expired/revoked sessions are purged.
	CleanupInterval = 60 * time.Second
)

// Store manages session lifecycle: creation, validation, revocation, and cleanup.
//
// With a sessions file (Options.Path) every change is saved, so sessions and
// revocations survive a restart. Revoked records are kept until they expire
// so a revoked token keeps getting SESSION_REVOKED, before and after a restart.
type Store struct {
	mu         sync.RWMutex
	sessions   map[string]*Session // keyed by session ID
	signingKey []byte
	path       string // sessions file; "" = memory only
	// roleFingerprints is saved with the sessions; see Options.
	roleFingerprints map[string]string
	defaultTTL       time.Duration
	stopCh           chan struct{}
	stopped          bool
}

// NewStore creates a memory-only session store with a random signing key and
// the given default TTL (zero = DefaultTTL). Sessions do not survive a
// restart; the server uses OpenStore. Call Stop() when done.
func NewStore(defaultTTL time.Duration) (*Store, error) {
	return OpenStore(Options{TTL: defaultTTL})
}

// OpenStore creates a session store, loading saved sessions from opts.Path
// if set. Call Stop() when the store is no longer needed.
func OpenStore(opts Options) (*Store, error) {
	defaultTTL := opts.TTL
	if defaultTTL <= 0 {
		defaultTTL = DefaultTTL
	}

	key := append([]byte(nil), opts.SigningKey...)
	if len(key) == 0 {
		key = make([]byte, SigningKeyBytes)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generating session signing key: %w", err)
		}
	}

	sessions := make(map[string]*Session)
	if opts.Path != "" {
		loaded, err := loadSessions(opts.Path, opts.RoleFingerprints)
		if err != nil {
			return nil, err
		}
		sessions = loaded
	}

	s := &Store{
		sessions:         sessions,
		signingKey:       key,
		path:             opts.Path,
		roleFingerprints: opts.RoleFingerprints,
		defaultTTL:       defaultTTL,
		stopCh:           make(chan struct{}),
	}

	// Rewrite the file now so sessions dropped at load (expired, or of a
	// changed role) cannot come back if the role is later changed back.
	if err := s.saveLocked(); err != nil {
		return nil, err
	}

	go s.cleanupLoop()
	return s, nil
}

// Create mints a new session and returns the signed token.
func (s *Store) Create(role, agent string, sealPubKey []byte, namespaces, actions []string, bootstrapMethod, sourceIP string, ttl time.Duration) (string, *Session, error) {
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
	defer s.mu.Unlock()
	s.sessions[id] = sess
	if err := s.saveLocked(); err != nil {
		// Not saved means it would vanish at restart; refuse the mint
		// rather than hand out a token that silently dies later.
		delete(s.sessions, id)
		return "", nil, err
	}

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
	oldExpiry := sess.ExpiresAt
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
		sess.ExpiresAt = oldExpiry
		return "", nil, err
	}
	if err := s.saveLocked(); err != nil {
		sess.ExpiresAt = oldExpiry
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

// Revoke marks a session as revoked. Revocation is idempotent. The session
// is denied at once even if saving fails; the error then means the revoke
// would be lost at the next restart.
func (s *Store) Revoke(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}
	sess.Revoked = true
	if err := s.saveLocked(); err != nil {
		return fmt.Errorf("session revoked now but not saved, so a restart would undo it: %w", err)
	}
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

// cleanup drops expired sessions. Revoked ones stay until they expire, so
// their tokens keep getting SESSION_REVOKED rather than SESSION_INVALID.
func (s *Store) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	removed := false
	for id, sess := range s.sessions {
		if now.After(sess.ExpiresAt) {
			delete(s.sessions, id)
			removed = true
		}
	}
	if removed {
		if err := s.saveLocked(); err != nil {
			log.Printf("WARNING: session cleanup: %v", err)
		}
	}
}
