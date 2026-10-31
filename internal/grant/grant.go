// Package grant stores request-use grants: an agent asks for temporary use of
// exact secret paths, a human approves or denies, and an approved request
// becomes a short-lived grant that Phoenix checks when the normal ACL says no.
//
// A grant holds no secret and no token. It is a record saying "agent X, using
// credential C from IP I, may do action Y on paths Z until T". The store keeps
// those records in grants.json with a durable write protocol (see store.go).
//
// This package knows nothing about HTTP or config files. The API layer
// (internal/api) passes config values and the caller's identity in explicitly,
// decides who counts as an approver, and maps the Error codes below to HTTP.
package grant

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/phoenixsec/phoenix/internal/store"
)

// ActionReadValue is the only grantable action in v1.
const ActionReadValue = "read_value"

// Auth methods, matching internal/api's bootstrapMethod strings. Sessions
// ("phxs_" tokens) can never create or use a grant.
const (
	AuthBearer = "bearer"
	AuthMTLS   = "mtls"
	AuthToken  = "token" // short-lived token
)

// Fixed limits from the plan (section 5 and the abuse limits table).
const (
	MaxPaths           = 10
	MaxPathLen         = 512
	MaxReasonLen       = 300 // characters (runes), after cleaning
	MinGrantTTL        = time.Minute
	MaxPendingPerAgent = 3
	MaxPendingTotal    = 50
	MaxCreatesPerHour  = 10
	DenyCooldown       = 10 * time.Minute
	MaxActiveGrants    = 10
	Retention          = 30 * 24 * time.Hour // resolved requests and dead grants
	EndedLookback      = 24 * time.Hour      // how long Match reports grant_expired / grant_revoked
)

// Status is a request's lifecycle state: pending -> approved | denied | expired.
// Terminal states never change.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
	StatusExpired  Status = "expired"
)

// GrantState is derived from a grant's clock and revoke fields.
type GrantState string

const (
	GrantActive  GrantState = "active"
	GrantExpired GrantState = "expired"
	GrantRevoked GrantState = "revoked"
)

// Reasons Match gives for a denial when a matching grant recently ended.
// They mirror the accessDecision reasons in the plan (section 8).
const (
	ReasonGrantExpired = "grant_expired"
	ReasonGrantRevoked = "grant_revoked"
)

// Request is an agent's ask for temporary use of exact paths. Values returned
// by the Store are copies; changing them does not change the store.
type Request struct {
	ID           string        `json:"id"`
	Agent        string        `json:"agent"`
	Paths        []string      `json:"paths"`
	Action       string        `json:"action"`
	Reason       string        `json:"reason"`
	RequestedTTL time.Duration `json:"requested_ttl"`
	SourceIP     string        `json:"source_ip"`
	AuthMethod   string        `json:"auth_method"`
	CredentialFP string        `json:"credential_fp,omitempty"`
	Status       Status        `json:"status"`
	CreatedAt    time.Time     `json:"created_at"`
	ExpiresAt    time.Time     `json:"expires_at"`
	DecidedBy    string        `json:"decided_by,omitempty"`
	DeciderIP    string        `json:"decider_ip,omitempty"`
	DecidedAt    time.Time     `json:"decided_at,omitzero"`
	Note         string        `json:"note,omitempty"`
	GrantID      string        `json:"grant_id,omitempty"`
}

// Grant is an approved, time-limited permission. Usable only by the same
// agent, with the same kind of credential (and the same IP when bound).
type Grant struct {
	ID                 string    `json:"id"`
	RequestID          string    `json:"request_id"`
	Agent              string    `json:"agent"`
	Paths              []string  `json:"paths"`
	Action             string    `json:"action"`
	SealedOnly         bool      `json:"sealed_only"`
	BoundSourceIP      string    `json:"bound_source_ip,omitempty"`
	AuthMethod         string    `json:"auth_method"`
	CredentialFP       string    `json:"credential_fp,omitempty"`
	NotBeforeTombstone time.Time `json:"not_before_tombstone,omitzero"`
	CreatedAt          time.Time `json:"created_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	ApprovedBy         string    `json:"approved_by"`
	RevokedAt          time.Time `json:"revoked_at,omitzero"`
	RevokedBy          string    `json:"revoked_by,omitempty"`
	ExpiryRecorded     bool      `json:"expiry_recorded,omitempty"` // grant.expired audit event queued
	LastUsedAt         time.Time `json:"last_used_at,omitzero"`
	UseCount           int64     `json:"use_count,omitempty"`
}

// State returns whether the grant is active, expired or revoked at now.
// Expiry is exclusive: at exactly ExpiresAt the grant is already expired.
// Once expiry is recorded it is final, even if the clock later steps back.
func (g Grant) State(now time.Time) GrantState {
	if !g.RevokedAt.IsZero() {
		return GrantRevoked
	}
	if g.ExpiryRecorded || !now.Before(g.ExpiresAt) {
		return GrantExpired
	}
	return GrantActive
}

// endedAt is when an inactive grant stopped working.
func (g *Grant) endedAt() time.Time {
	if !g.RevokedAt.IsZero() && g.RevokedAt.Before(g.ExpiresAt) {
		return g.RevokedAt
	}
	return g.ExpiresAt
}

// covers reports whether the grant names this exact path and action.
func (g *Grant) covers(path, action string) bool {
	return g.Action == action && slices.Contains(g.Paths, path)
}

// Code is a stable error code. internal/api maps each to an HTTP status and
// the denial JSON shape; the strings match the plan's code table.
type Code string

const (
	CodeInvalidRequest     Code = "INVALID_REQUEST"         // 400
	CodeActionNotGrantable Code = "ACTION_NOT_GRANTABLE"    // 400
	CodeNotFound           Code = "NOT_FOUND"               // 404
	CodeUnknownAgent       Code = "UNKNOWN_AGENT"           // 403: agent no longer in the ACL
	CodeNotPending         Code = "NOT_PENDING"             // 409
	CodeSelfApproval       Code = "SELF_APPROVAL"           // 403
	CodeWideningNotAllowed Code = "WIDENING_NOT_ALLOWED"    // 400
	CodeEmptyGrant         Code = "EMPTY_GRANT"             // 400
	CodeGrantLimit         Code = "GRANT_LIMIT"             // 409
	CodeTooManyPending     Code = "TOO_MANY_PENDING"        // 429 + Retry-After
	CodeRateLimited        Code = "RATE_LIMITED"            // 429 + Retry-After
	CodeRequestCooldown    Code = "REQUEST_COOLDOWN"        // 429 + Retry-After
	CodeAuditWriteFailed   Code = "AUDIT_WRITE_FAILED"      // 500: attempt line could not be written, nothing changed
	CodeStoreWriteFailed   Code = "STORE_WRITE_FAILED"      // 500: nothing published
	CodeRevokeNotDurable   Code = "REVOKE_NOT_DURABLE"      // 500: revoked in memory only
	CodeRequestsDegraded   Code = "REQUESTS_DEGRADED"       // 503
	CodeDeleteACLFailed    Code = "AGENT_DELETE_ACL_FAILED" // 500: grants revoked durably, ACL entry still there
)

// Error is the error type every Store method returns. Use errors.Is with the
// Err* sentinels (matching is by Code) or errors.As to read RetryAfter.
type Error struct {
	Code       Code
	Msg        string
	RetryAfter time.Duration // set for the 429 codes
	Err        error         // underlying cause, if any (never shown to agents)
}

func (e *Error) Error() string {
	msg := string(e.Code)
	if e.Msg != "" {
		msg += ": " + e.Msg
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *Error) Unwrap() error { return e.Err }

// Is makes errors.Is(err, grant.ErrNotPending) match any *Error with that Code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// Sentinels for errors.Is. Compare by code only.
var (
	ErrInvalidRequest     = &Error{Code: CodeInvalidRequest}
	ErrActionNotGrantable = &Error{Code: CodeActionNotGrantable}
	ErrNotFound           = &Error{Code: CodeNotFound}
	ErrUnknownAgent       = &Error{Code: CodeUnknownAgent}
	ErrNotPending         = &Error{Code: CodeNotPending}
	ErrSelfApproval       = &Error{Code: CodeSelfApproval}
	ErrWideningNotAllowed = &Error{Code: CodeWideningNotAllowed}
	ErrEmptyGrant         = &Error{Code: CodeEmptyGrant}
	ErrGrantLimit         = &Error{Code: CodeGrantLimit}
	ErrTooManyPending     = &Error{Code: CodeTooManyPending}
	ErrRateLimited        = &Error{Code: CodeRateLimited}
	ErrRequestCooldown    = &Error{Code: CodeRequestCooldown}
	ErrAuditWriteFailed   = &Error{Code: CodeAuditWriteFailed}
	ErrStoreWriteFailed   = &Error{Code: CodeStoreWriteFailed}
	ErrRevokeNotDurable   = &Error{Code: CodeRevokeNotDurable}
	ErrRequestsDegraded   = &Error{Code: CodeRequestsDegraded}
	ErrDeleteACLFailed    = &Error{Code: CodeDeleteACLFailed}
)

// CodeOf returns the Code of a grant error, or "" for nil / foreign errors.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func newErr(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// BearerFingerprint turns the ACL's stored bearer-token hash into the
// credential fingerprint a grant is bound to. It hashes the hash so the
// stored hash itself never lands in grants.json.
func BearerFingerprint(storedTokenHash string) string {
	sum := sha256.Sum256([]byte(storedTokenHash))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// newID returns prefix + 32 hex chars (16 random bytes). crypto/rand.Read
// never returns an error on Go 1.24+ (it aborts the process instead).
func newID(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// isHiddenRune reports Unicode bidi controls and zero-width characters, which
// can make text display differently from what it is.
func isHiddenRune(r rune) bool {
	switch {
	case r == 0x061C, r == 0x200E, r == 0x200F: // ALM, LRM, RLM
		return true
	case r >= 0x202A && r <= 0x202E: // LRE..RLO
		return true
	case r >= 0x2066 && r <= 0x2069: // LRI..PDI
		return true
	case r >= 0x200B && r <= 0x200D, r == 0x2060, r == 0xFEFF, r == 0x180E: // zero-width
		return true
	}
	return false
}

// NormalizePaths validates a requested path list and returns it de-duplicated
// and sorted. Paths must be exact secret paths (store rules) with no glob
// characters, control characters, bidi or zero-width characters.
func NormalizePaths(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, newErr(CodeInvalidRequest, "at least one path is required")
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if err := validatePath(p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > MaxPaths {
		return nil, newErr(CodeInvalidRequest, "at most %d paths per request", MaxPaths)
	}
	return out, nil
}

func validatePath(p string) error {
	if len(p) > MaxPathLen || !utf8.ValidString(p) {
		return newErr(CodeInvalidRequest, "invalid path")
	}
	if err := store.ValidatePath(p); err != nil {
		return newErr(CodeInvalidRequest, "invalid path %q", p)
	}
	for _, r := range p {
		if strings.ContainsRune("*?[]{}", r) || unicode.IsControl(r) || isHiddenRune(r) {
			return newErr(CodeInvalidRequest, "path must be exact: no wildcard, control, bidi or zero-width characters")
		}
	}
	return nil
}

// CleanText strips control, bidi and zero-width characters (tabs and
// newlines become spaces), trims, and enforces maxLen characters. Used for
// the request reason and the deny note.
func CleanText(s string, maxLen int) (string, error) {
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			b.WriteRune(' ')
		case unicode.IsControl(r) || isHiddenRune(r):
		default:
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	if utf8.RuneCountInString(out) > maxLen {
		return "", newErr(CodeInvalidRequest, "text longer than %d characters", maxLen)
	}
	return out, nil
}
