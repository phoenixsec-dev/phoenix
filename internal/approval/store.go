package approval

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrNotFound   = errors.New("approval not found")
	ErrNotPending = errors.New("approval is not pending")
)

// CleanupInterval is how often the background goroutine runs.
const CleanupInterval = 30 * time.Second

// Store manages approval lifecycle: creation, approval, denial, expiry, and cleanup.
type Store struct {
	mu             sync.RWMutex
	approvals      map[string]*Approval
	defaultTimeout time.Duration
	stopCh         chan struct{}
	stopped        bool
}

// NewStore creates a new approval store with the given default timeout.
// If defaultTimeout is zero, DefaultTimeout (5m) is used.
func NewStore(defaultTimeout time.Duration) *Store {
	if defaultTimeout <= 0 {
		defaultTimeout = DefaultTimeout
	}
	s := &Store{
		approvals:      make(map[string]*Approval),
		defaultTimeout: defaultTimeout,
		stopCh:         make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

// Create adds a new pending approval and returns it.
func (s *Store) Create(role, agent string, sealPubKey []byte, namespaces, actions []string,
	bootstrapMethod, certFingerprint, sourceIP, requesterTTY string, sessionTTL, approvalTimeout time.Duration) (*Approval, error) {

	id, err := generateApprovalID()
	if err != nil {
		return nil, err
	}

	if approvalTimeout <= 0 {
		approvalTimeout = s.defaultTimeout
	}

	now := time.Now().UTC()
	apr := &Approval{
		ID:              id,
		Role:            role,
		Agent:           agent,
		SealPubKey:      sealPubKey,
		Namespaces:      namespaces,
		Actions:         actions,
		BootstrapMethod: bootstrapMethod,
		CertFingerprint: certFingerprint,
		SourceIP:        sourceIP,
		RequesterTTY:    requesterTTY,
		SessionTTL:      sessionTTL,
		Status:          StatusPending,
		CreatedAt:       now,
		ExpiresAt:       now.Add(approvalTimeout),
	}

	s.mu.Lock()
	s.approvals[id] = apr
	s.mu.Unlock()

	return apr, nil
}

// Get returns an approval by ID, or nil if not found.
// Pending approvals past their expiry are marked expired before return.
func (s *Store) Get(id string) *Approval {
	s.mu.Lock()
	defer s.mu.Unlock()

	apr, ok := s.approvals[id]
	if !ok {
		return nil
	}
	// Lazily expire
	if apr.Status == StatusPending && time.Now().After(apr.ExpiresAt) {
		apr.Status = StatusExpired
	}
	return apr
}

// Approve marks a pending approval as approved and stores the session details.
// Approving an already-approved approval is idempotent (returns nil).
// Approving a denied or expired approval returns ErrNotPending.
func (s *Store) Approve(id, approvedBy, approverIP, approverTTY, sessionToken, sessionID string, sessionExpiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	apr, ok := s.approvals[id]
	if !ok {
		return ErrNotFound
	}

	// Lazily expire
	if apr.Status == StatusPending && time.Now().After(apr.ExpiresAt) {
		apr.Status = StatusExpired
	}

	switch apr.Status {
	case StatusApproved:
		return nil // idempotent
	case StatusPending:
		apr.Status = StatusApproved
		apr.ApprovedBy = approvedBy
		apr.ApproverIP = approverIP
		apr.ApproverTTY = approverTTY
		apr.SessionToken = sessionToken
		apr.SessionID = sessionID
		apr.SessionExpiry = sessionExpiry
		return nil
	default:
		return ErrNotPending
	}
}

// Deny marks a pending approval as denied.
// Denying an already-denied approval is idempotent.
// Denying an approved or expired approval returns ErrNotPending.
func (s *Store) Deny(id, deniedBy, denierIP string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	apr, ok := s.approvals[id]
	if !ok {
		return ErrNotFound
	}

	// Lazily expire
	if apr.Status == StatusPending && time.Now().After(apr.ExpiresAt) {
		apr.Status = StatusExpired
	}

	switch apr.Status {
	case StatusDenied:
		return nil // idempotent
	case StatusPending:
		apr.Status = StatusDenied
		apr.ApprovedBy = deniedBy // reuse field for denier
		apr.ApproverIP = denierIP
		return nil
	default:
		return ErrNotPending
	}
}

// ListPending returns all pending (non-expired) approvals.
func (s *Store) ListPending() []*Approval {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	var result []*Approval
	for _, apr := range s.approvals {
		if apr.Status == StatusPending {
			if now.After(apr.ExpiresAt) {
				apr.Status = StatusExpired
				continue
			}
			result = append(result, apr)
		}
	}
	return result
}

// ListAll returns all approvals (pending, approved, denied, expired).
func (s *Store) ListAll() []*Approval {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	result := make([]*Approval, 0, len(s.approvals))
	for _, apr := range s.approvals {
		if apr.Status == StatusPending && now.After(apr.ExpiresAt) {
			apr.Status = StatusExpired
		}
		result = append(result, apr)
	}
	return result
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
	for id, apr := range s.approvals {
		// Expire pending approvals past their deadline
		if apr.Status == StatusPending && now.After(apr.ExpiresAt) {
			apr.Status = StatusExpired
		}
		// Purge completed approvals older than 10 minutes
		if apr.Status != StatusPending && now.Sub(apr.ExpiresAt) > 10*time.Minute {
			delete(s.approvals, id)
		}
	}
}
