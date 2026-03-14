// Package approval implements step-up approval for Phoenix session identity.
//
// When a role has StepUp enabled, session minting returns a pending approval
// instead of a token. A human approves from the CLI, and the agent polls
// for approval status to receive the session token once approved.
package approval

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

const (
	// ApprovalIDBytes is the number of random bytes in an approval ID.
	ApprovalIDBytes = 16
	// DefaultTimeout is the default approval window.
	DefaultTimeout = 5 * time.Minute
)

// Status represents the lifecycle state of an approval request.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
	StatusExpired  Status = "expired"
)

// Approval represents a pending or resolved step-up approval request.
type Approval struct {
	ID              string        `json:"id"`
	Role            string        `json:"role"`
	Agent           string        `json:"agent"`
	SealPubKey      []byte        `json:"-"`
	Namespaces      []string      `json:"namespaces"`
	Actions         []string      `json:"actions"`
	BootstrapMethod string        `json:"bootstrap_method"`
	CertFingerprint string        `json:"cert_fingerprint,omitempty"`
	SourceIP        string        `json:"source_ip"`
	RequesterTTY    string        `json:"requester_tty,omitempty"`
	SessionTTL      time.Duration `json:"-"`
	Status          Status        `json:"status"`
	CreatedAt       time.Time     `json:"created_at"`
	ExpiresAt       time.Time     `json:"expires_at"`
	ApprovedBy      string        `json:"approved_by,omitempty"`
	ApproverIP      string        `json:"approver_ip,omitempty"`
	ApproverTTY     string        `json:"approver_tty,omitempty"`
	SessionToken    string        `json:"session_token,omitempty"`
	SessionID       string        `json:"session_id,omitempty"`
	SessionExpiry   time.Time     `json:"session_expiry,omitempty"`
}

// generateApprovalID creates a random hex-encoded approval ID with "apr_" prefix.
func generateApprovalID() (string, error) {
	b := make([]byte, ApprovalIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating approval ID: %w", err)
	}
	return "apr_" + hex.EncodeToString(b), nil
}
