package session

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"slices"
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
//
// A session is tied to the bearer token that minted it. The check that the
// token is still the agent's (BindCredentials) runs under mu, and so does every
// token change (ChangeCredential), so a mint, renewal or use either comes before
// the change and is ended by it, or comes after it and is refused.
type Store struct {
	mu         sync.RWMutex
	sessions   map[string]*Session // keyed by session ID
	signingKey []byte
	path       string // sessions file; "" = memory only
	// roleFingerprints is saved with the sessions; see Options.
	roleFingerprints map[string]string
	// credentialCurrent is set by BindCredentials; nil refuses every session.
	credentialCurrent func(agent, credentialFP string) bool
	unsaved           bool // the last save failed; cleanup retries it
	// writeFile saves the sessions file.
	writeFile  func(path string, data []byte, perm os.FileMode) error
	defaultTTL time.Duration
	stopCh     chan struct{}
	stopped    bool
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

	sessions, dropped := make(map[string]*Session), false
	if opts.Path != "" {
		var err error
		if sessions, dropped, err = loadSessions(opts.Path, opts.RoleFingerprints); err != nil {
			return nil, err
		}
	}

	s := &Store{
		sessions:         sessions,
		signingKey:       key,
		path:             opts.Path,
		roleFingerprints: opts.RoleFingerprints,
		writeFile:        writeSessionsFile,
		defaultTTL:       defaultTTL,
		stopCh:           make(chan struct{}),
	}

	// Rewrite the file now if sessions were dropped at load (expired, or of a
	// changed role), so they cannot come back if the role is later changed
	// back. A full disk must not keep the server from starting: they are gone
	// from memory, and cleanup retries the save.
	if dropped {
		if err := s.saveLocked(); err != nil {
			log.Printf("WARNING: sessions that ended at start are not saved as ended yet, will retry: %v", err)
		}
	}

	go s.cleanupLoop()
	return s, nil
}

// BindCredentials sets the check that decides whether a session's credential
// (agent plus CredentialFP) is still the agent's, and ends every session that
// fails it: its agent is gone, its token was replaced (for example by editing
// the ACL file while the server was down), or it has no fingerprint because
// v0.23.0 saved it. It returns the ended sessions; the error means they are
// ended but that is not saved yet (cleanup retries). Until it is called every
// mint, use and renewal is refused. check runs under the store lock and must
// not call back into the Store.
func (s *Store) BindCredentials(check func(agent, credentialFP string) bool) ([]*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credentialCurrent = check
	ended := s.endLocked(func(sess *Session) bool { return !s.credentialOKLocked(sess) })
	if len(ended) > 0 {
		if err := s.saveLocked(); err != nil {
			return ended, err
		}
	}
	return ended, nil
}

// ChangeCredential runs change, which deletes agent or replaces its token, with
// no session minted, used or renewed meanwhile, then ends the agent's sessions
// that no longer pass the credential check and returns them. They are ended
// even if change fails part way. If the sessions file cannot be saved they are
// still dead, also after a restart, because the ACL no longer has their
// credential; that is logged and cleanup retries the save.
func (s *Store) ChangeCredential(agent string, change func() error) ([]*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := change()
	ended := s.endLocked(func(sess *Session) bool {
		return sess.Agent == agent && !s.credentialOKLocked(sess)
	})
	if len(ended) > 0 {
		if saveErr := s.saveLocked(); saveErr != nil {
			log.Printf("WARNING: %d sessions of agent %q ended but not saved, will retry: %v", len(ended), agent, saveErr)
		}
	}
	return ended, err
}

// Check returns nil if the session is still usable: not ended, revoked or
// expired, and made with its agent's current token. Else the error is the one
// logging in with it would give.
func (s *Store) Check(id string) error {
	_, stale, err := s.lookup(id)
	if stale {
		return ErrCredentialChanged
	}
	return err
}

// credentialOKLocked reports whether the token sess was minted with is still
// its agent's token. A session without a fingerprint never passes. The caller
// must hold s.mu (read or write).
func (s *Store) credentialOKLocked(sess *Session) bool {
	return sess.CredentialFP != "" && s.credentialCurrent != nil && s.credentialCurrent(sess.Agent, sess.CredentialFP)
}

// endLocked removes the live sessions that match and returns them, so their
// tokens get SESSION_INVALID and clients mint again. Revoked ones stay: they
// must keep answering SESSION_REVOKED. The caller must hold s.mu and save.
func (s *Store) endLocked(match func(*Session) bool) []*Session {
	var ended []*Session
	for id, sess := range s.sessions {
		if !sess.Revoked && match(sess) {
			delete(s.sessions, id)
			ended = append(ended, sess)
		}
	}
	return ended
}

// endStaleLocked ends one session whose credential check failed and returns
// ErrCredentialChanged. Every route that changes a token already ends the
// agent's sessions; this is the second guard. The caller must hold s.mu.
func (s *Store) endStaleLocked(sess *Session) error {
	delete(s.sessions, sess.ID)
	if err := s.saveLocked(); err != nil {
		log.Printf("WARNING: session %s ended but not saved: %v", sess.ID, err)
	}
	return ErrCredentialChanged
}

// Create mints a new session bound to credentialFP, the fingerprint of the
// bearer token the caller logged in with, and returns the signed token. If
// that is not the agent's token by the time the session is stored, nothing is
// minted and the error is ErrCredentialChanged.
func (s *Store) Create(role, agent, credentialFP string, sealPubKey []byte, namespaces, actions []string, bootstrapMethod, sourceIP string, ttl time.Duration) (string, *Session, error) {
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
		CredentialFP:       credentialFP,
		SealKeyFingerprint: fingerprint,
		Namespaces:         slices.Clone(namespaces),
		Actions:            slices.Clone(actions),
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
	if !s.credentialOKLocked(sess) {
		return "", nil, ErrCredentialChanged
	}
	s.sessions[id] = sess
	s.saveLoginLocked(id)

	return token, sess.snapshot(), nil
}

// snapshot is a copy to hand to callers: the stored record changes when the
// session is renewed or revoked, and nothing a caller does may change it.
func (sess *Session) snapshot() *Session {
	c := *sess
	c.Namespaces, c.Actions = slices.Clone(sess.Namespaces), slices.Clone(sess.Actions)
	return &c
}

// Renew extends an existing session's expiry and mints a new signed token.
// The session ID is preserved so the audit trail remains continuous.
// Returns ErrSessionNotFound, ErrSessionRevoked, ErrTokenExpired or
// ErrCredentialChanged as appropriate.
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
	if !s.credentialOKLocked(sess) {
		return "", nil, s.endStaleLocked(sess)
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
	s.saveLoginLocked(sess.ID)

	return token, sess.snapshot(), nil
}

// saveLoginLocked saves a minted or renewed session. A full disk must not keep
// agents out, and the session allows nothing its agent's token does not: if the
// save fails it works from memory and cleanup retries. A restart before that
// forgets it, and the client mints another. The caller must hold s.mu.
func (s *Store) saveLoginLocked(id string) {
	if err := s.saveLocked(); err != nil {
		log.Printf("WARNING: session %s works but is not saved yet, will retry: %v", id, err)
	}
}

// Validate verifies a session token and returns the associated session.
// Returns ErrSessionRevoked if the session was explicitly revoked,
// ErrTokenExpired if the TTL elapsed, ErrSessionNotFound if the session ID
// in the token doesn't match any active session, or ErrCredentialChanged if
// the token it was minted with is no longer its agent's (the session is ended;
// only the call that ended it gets this, later ones get ErrSessionNotFound).
func (s *Store) Validate(tokenStr string) (*Session, error) {
	claims, err := validateToken(tokenStr, s.signingKey)
	if err != nil {
		return nil, err
	}

	sess, stale, err := s.lookup(claims.SessionID)
	if !stale {
		return sess, err
	}

	return nil, s.endStale(sess.ID)
}

// endStale ends the session a lookup found stale, unless something else got
// there since. It returns the error for the caller.
func (s *Store) endStale(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[id]
	switch {
	case sess == nil:
		return ErrSessionNotFound
	case sess.Revoked: // keep the record, it must say so
		return ErrSessionRevoked
	}
	return s.endStaleLocked(sess)
}

// lookup finds a usable session by ID and returns a snapshot. stale means it is live but its
// credential check failed, so the caller must end it.
func (s *Store) lookup(id string) (sess *Session, stale bool, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sess, ok := s.sessions[id]
	switch {
	case !ok:
		return nil, false, ErrSessionNotFound
	case sess.Revoked:
		return nil, false, ErrSessionRevoked
	case time.Now().After(sess.ExpiresAt):
		return nil, false, ErrTokenExpired
	case !s.credentialOKLocked(sess):
		return sess.snapshot(), true, nil
	}
	return sess.snapshot(), false, nil
}

// Revoke marks a session as revoked. Revocation is idempotent. The session
// is denied at once even if saving fails; the error then means the revoke
// may be lost at a restart or power cut.
func (s *Store) Revoke(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}
	sess.Revoked = true
	if err := s.saveLocked(); err != nil {
		return fmt.Errorf("session revoked now, but saving that failed, so a restart may undo it: %w", err)
	}
	return nil
}

// Get returns a snapshot of a session by ID, or nil if not found.
func (s *Store) Get(sessionID string) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil
	}
	return sess.snapshot()
}

// List returns snapshots of all active (non-expired, non-revoked) sessions.
func (s *Store) List() []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	var result []*Session
	for _, sess := range s.sessions {
		if !sess.Revoked && now.Before(sess.ExpiresAt) {
			result = append(result, sess.snapshot())
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
	removed := s.unsaved // a failed save is retried here
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
