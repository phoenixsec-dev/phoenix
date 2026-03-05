// Package nonce implements a challenge-response nonce store for anti-replay
// protection in Phoenix attestation flows.
//
// Before resolving a secret that requires nonce attestation, the client
// requests a one-time nonce via POST /v1/challenge. The nonce is signed
// and included in the resolve request. The broker validates that the nonce
// is fresh, has not been used before, and was issued within the max age.
//
// The store automatically cleans up expired nonces to prevent unbounded
// memory growth.
package nonce

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

const (
	// DefaultMaxAge is the default maximum age of a nonce before it expires.
	DefaultMaxAge = 30 * time.Second
	// NonceBytes is the number of random bytes in a nonce.
	NonceBytes = 16
	// CleanupInterval is how often expired nonces are purged.
	CleanupInterval = 60 * time.Second
)

// Entry tracks a single issued nonce.
type Entry struct {
	Nonce   string    `json:"nonce"`
	Expires time.Time `json:"expires"`
	Used    bool
}

// Store manages nonce issuance and validation.
type Store struct {
	mu      sync.Mutex
	nonces  map[string]*Entry
	maxAge  time.Duration
	stopCh  chan struct{}
	stopped bool
}

// NewStore creates a new nonce store with the given max age.
// If maxAge is zero, DefaultMaxAge is used.
// Call Stop() when the store is no longer needed to stop cleanup.
func NewStore(maxAge time.Duration) *Store {
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	s := &Store{
		nonces: make(map[string]*Entry),
		maxAge: maxAge,
		stopCh: make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

// Generate creates a new nonce with the configured TTL.
func (s *Store) Generate() (*Entry, error) {
	b := make([]byte, NonceBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	nonce := hex.EncodeToString(b)
	expires := time.Now().Add(s.maxAge)

	entry := &Entry{
		Nonce:   nonce,
		Expires: expires,
	}

	s.mu.Lock()
	s.nonces[nonce] = entry
	s.mu.Unlock()

	return entry, nil
}

// Validate checks a nonce: it must exist, not be expired, and not have been
// used before. On successful validation, the nonce is marked as used and
// cannot be validated again (single-use).
func (s *Store) Validate(nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.nonces[nonce]
	if !ok {
		return fmt.Errorf("unknown nonce")
	}

	if time.Now().After(entry.Expires) {
		delete(s.nonces, nonce)
		return fmt.Errorf("nonce expired")
	}

	if entry.Used {
		return fmt.Errorf("nonce already used (replay detected)")
	}

	entry.Used = true
	// Remove from map immediately — it can never be used again
	delete(s.nonces, nonce)
	return nil
}

// Pending returns the number of outstanding (issued but not yet used/expired) nonces.
func (s *Store) Pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.nonces)
}

// Stop shuts down the background cleanup goroutine.
func (s *Store) Stop() {
	s.mu.Lock()
	if !s.stopped {
		s.stopped = true
		close(s.stopCh)
	}
	s.mu.Unlock()
}

// cleanupLoop periodically removes expired nonces.
func (s *Store) cleanupLoop() {
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.cleanup()
		case <-s.stopCh:
			return
		}
	}
}

// cleanup removes all expired nonces.
func (s *Store) cleanup() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	for k, entry := range s.nonces {
		if now.After(entry.Expires) {
			delete(s.nonces, k)
		}
	}
}
