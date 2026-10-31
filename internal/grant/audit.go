package grant

import (
	"maps"
	"slices"
	"strings"
	"time"
)

// Phase says which line of the two-step audit protocol an Event is.
type Phase string

const (
	PhaseAttempt   Phase = "attempt"   // written BEFORE a change; failure aborts the change
	PhaseCommitted Phase = "committed" // written AFTER the change is durable; retried until it lands
	PhaseFailed    Phase = "failed"    // best-effort note that a change was not saved
)

// Audit event names. Attempt and failed lines use "<op>.attempt" and
// "<op>.failed"; committed lines use the past-tense name.
const (
	opCreate      = "access_request.create"
	opApprove     = "access_request.approve"
	opDeny        = "access_request.deny"
	opRevoke      = "grant.revoke"
	opDeleteAgent = "grant.agent_delete"

	EventRequestCreated  = "access_request.created"
	EventRequestApproved = "access_request.approved"
	EventRequestDenied   = "access_request.denied"
	EventRequestExpired  = "access_request.expired"
	EventGrantRevoked    = "grant.revoked"
	EventGrantExpired    = "grant.expired"
	EventAgentDeleted    = "grant.agent_deleted"
)

// Event is one audit line the store wants written. Committed events are also
// kept in grants.json (audit_pending) until the sink accepts them, so
// delivery is at-least-once: a crash can repeat a line (same ID), never lose one.
// The attempt, committed and failed lines of one transition share an ID.
type Event struct {
	ID        string            `json:"id"`   // evt_..., stable across retries
	Name      string            `json:"name"` // e.g. "access_request.approved"
	Phase     Phase             `json:"phase"`
	Time      time.Time         `json:"time"`
	Agent     string            `json:"agent"`           // the requesting / owning agent
	Actor     string            `json:"actor,omitempty"` // who acted: approver, agent, or "system"
	ActorIP   string            `json:"actor_ip,omitempty"`
	RequestID string            `json:"request_id,omitempty"`
	GrantID   string            `json:"grant_id,omitempty"`
	Paths     []string          `json:"paths,omitempty"`
	Action    string            `json:"action,omitempty"`
	Detail    map[string]string `json:"detail,omitempty"` // ttl, note, error text, ...
}

// AuditSink receives audit lines. internal/api adapts its *audit.Logger to
// this (e.g. Actor as the audit agent, Name as the action, Metadata() as
// metadata). Append must return an error when the line was not written.
// It is called with the store's transition lock held, so it must not call
// back into the Store.
type AuditSink interface {
	Append(e Event) error
}

// Metadata flattens an Event into the string map internal/audit stores.
func (e Event) Metadata() map[string]string {
	m := map[string]string{
		"event_id":   e.ID,
		"phase":      string(e.Phase),
		"agent":      e.Agent,
		"request_id": e.RequestID,
		"grant_id":   e.GrantID,
	}
	if len(e.Paths) > 0 {
		m["paths"] = strings.Join(e.Paths, ",")
	}
	for k, v := range e.Detail {
		m[k] = v
	}
	return m
}

// clone deep-copies the slices and maps so a sink can never alias the
// store's records.
func (e Event) clone() Event {
	e.Paths = slices.Clone(e.Paths)
	e.Detail = maps.Clone(e.Detail)
	return e
}

type discardSink struct{}

func (discardSink) Append(Event) error { return nil }
