package grant

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/phoenixsec/phoenix/internal/fsutil"
)

// Write protocol (plan section 5), used by every transition:
//
//  1. Copy the published state and apply the change to the copy.
//  2. Append the audit "attempt" line. If that fails, change nothing.
//  3. Save the copy to grants.json (temp write, fsync, rename, dir fsync).
//     The copy carries the committed audit event in audit_pending.
//  4. Only now publish the copy (swap it in) and return success.
//  5. Append the committed audit line; on success drop it from audit_pending
//     on the next save. On failure Tick retries it (at-least-once).
//
// Published state is never modified in place: every change builds new maps
// and new record copies. That lets Match read a snapshot without holding the
// transition lock while it scans.

const fileVersion = 1

// approveMaybeOnDiskMsg is the STORE_WRITE_FAILED message for the one case
// where a failed approve may still be on disk (see commit).
const approveMaybeOnDiskMsg = "could not confirm the approval was saved, and undoing it on disk also failed: " +
	"the approval may still be on disk and could take effect after a restart. " +
	"Check the grants list and revoke it if it is not wanted"

// Defaults used when Options leaves a duration at zero.
const (
	DefaultRequestTTL         = 15 * time.Minute
	DefaultGrantTTL           = time.Hour
	DefaultMaxGrantTTL        = 8 * time.Hour
	DefaultTombstoneRetention = 25 * time.Hour // max(token TTL, max grant TTL) + margin; API should pass its own
)

const (
	quarantineNone   = ""
	quarantineOK     = "quarantined"       // corrupt file renamed aside, started empty
	quarantineFailed = "quarantine_failed" // could not rename it: writes refused
)

// Options configures a Store. Only Path is required.
type Options struct {
	Path  string    // grants.json location
	FS    FS        // nil = OSFS{}
	Audit AuditSink // nil = discard
	Now   func() time.Time
	// AgentExists reports whether the name is still in the ACL. Called under
	// the store lock at create/approve and outside it at Match. nil = always.
	// It must not call back into the Store.
	AgentExists func(name string) bool
	Logf        func(format string, args ...any) // nil = log.Printf

	RequestTTL         time.Duration // how long a request stays pending
	DefaultGrantTTL    time.Duration // TTL when the agent does not ask for one
	MaxGrantTTL        time.Duration // ceiling for requested TTLs at create time
	TombstoneRetention time.Duration // how long an agent-delete tombstone is kept
}

// state is the whole contents of grants.json.
type state struct {
	Version      int                  `json:"version"`
	Requests     map[string]*Request  `json:"requests"`
	Grants       map[string]*Grant    `json:"grants"`
	Tombstones   map[string]time.Time `json:"tombstones"` // agent name -> deleted_at
	AuditPending []Event              `json:"audit_pending"`
}

func emptyState() *state {
	return &state{
		Version:    fileVersion,
		Requests:   map[string]*Request{},
		Grants:     map[string]*Grant{},
		Tombstones: map[string]time.Time{},
	}
}

// clone copies the maps and the pending slice, sharing the (immutable) records.
func (st *state) clone() *state {
	n := &state{
		Version:      fileVersion,
		Requests:     make(map[string]*Request, len(st.Requests)),
		Grants:       make(map[string]*Grant, len(st.Grants)),
		Tombstones:   make(map[string]time.Time, len(st.Tombstones)),
		AuditPending: slices.Clone(st.AuditPending),
	}
	for k, v := range st.Requests {
		n.Requests[k] = v
	}
	for k, v := range st.Grants {
		n.Grants[k] = v
	}
	for k, v := range st.Tombstones {
		n.Tombstones[k] = v
	}
	return n
}

type usageDelta struct {
	last  time.Time
	count int64
}

// Store holds requests and grants. Create one with Open; all methods are
// safe for concurrent use.
type Store struct {
	opts  Options
	fs    FS
	sink  AuditSink
	now   func() time.Time
	logf  func(string, ...any)
	exist func(string) bool

	mu         sync.Mutex // serializes every transition and Tick
	auditDirty bool       // audit_pending shrank in memory; next save clears it on disk

	pubMu         sync.RWMutex // guards the fields below (short holds only)
	cur           *state
	writeFailed   error  // last failed save that left memory ahead of disk; nil after a good save
	quarantine    string // quarantineNone / quarantineOK / quarantineFailed
	quarantinedTo string

	usageMu sync.Mutex
	usage   map[string]usageDelta
}

// Open loads grants.json (or starts empty when it does not exist), expires
// anything stale, saves, and re-emits audit events left in audit_pending.
// A corrupt or unreadable file never stops the server: it is renamed to
// grants.json.corrupt-<unix> and the store starts empty and degraded. If
// that rename fails, the original is left untouched and all writes are
// refused. The only error is a missing Path.
func Open(opts Options) (*Store, error) {
	if opts.Path == "" {
		return nil, errors.New("grant store path is required")
	}
	if opts.FS == nil {
		opts.FS = OSFS{}
	}
	if opts.Audit == nil {
		opts.Audit = discardSink{}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logf == nil {
		opts.Logf = log.Printf
	}
	if opts.AgentExists == nil {
		opts.AgentExists = func(string) bool { return true }
	}
	if opts.RequestTTL <= 0 {
		opts.RequestTTL = DefaultRequestTTL
	}
	if opts.DefaultGrantTTL <= 0 {
		opts.DefaultGrantTTL = DefaultGrantTTL
	}
	if opts.MaxGrantTTL <= 0 {
		opts.MaxGrantTTL = DefaultMaxGrantTTL
	}
	if opts.TombstoneRetention <= 0 {
		opts.TombstoneRetention = DefaultTombstoneRetention
	}
	s := &Store{
		opts:  opts,
		fs:    opts.FS,
		sink:  opts.Audit,
		now:   func() time.Time { return opts.Now().UTC() },
		logf:  opts.Logf,
		exist: opts.AgentExists,
		usage: map[string]usageDelta{},
	}
	s.cur = s.load()
	s.Tick()
	return s, nil
}

// load reads and validates grants.json, quarantining it when it is bad.
func (s *Store) load() *state {
	data, err := s.fs.ReadFile(s.opts.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return emptyState()
	}
	if err == nil {
		var st *state
		if st, err = decodeState(data); err == nil {
			return st
		}
	}
	dest := fmt.Sprintf("%s.corrupt-%d", s.opts.Path, s.now().Unix())
	if rerr := s.fs.Rename(s.opts.Path, dest); rerr != nil {
		s.quarantine = quarantineFailed
		s.logf("ERROR: grant store %s is unreadable or corrupt (%v) and could not be moved aside (%v); "+
			"access requests are disabled and the file is left untouched until an operator fixes it",
			s.opts.Path, err, rerr)
		return emptyState()
	}
	s.quarantine = quarantineOK
	s.quarantinedTo = dest
	s.logf("ERROR: grant store %s is unreadable or corrupt (%v); moved to %s and started with zero grants",
		s.opts.Path, err, dest)
	return emptyState()
}

// decodeState parses grants.json and checks its basic shape.
func decodeState(data []byte) (*state, error) {
	var st state
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	if st.Version != fileVersion {
		return nil, fmt.Errorf("unsupported grants file version %d", st.Version)
	}
	if st.Requests == nil {
		st.Requests = map[string]*Request{}
	}
	if st.Grants == nil {
		st.Grants = map[string]*Grant{}
	}
	if st.Tombstones == nil {
		st.Tombstones = map[string]time.Time{}
	}
	for id, r := range st.Requests {
		if r == nil || r.ID != id || r.Agent == "" || len(r.Paths) == 0 {
			return nil, fmt.Errorf("malformed request record %q", id)
		}
	}
	for id, g := range st.Grants {
		if g == nil || g.ID != id || g.Agent == "" || len(g.Paths) == 0 || g.ExpiresAt.IsZero() {
			return nil, fmt.Errorf("malformed grant record %q", id)
		}
	}
	return &st, nil
}

// --- published state and health ---------------------------------------------

func (s *Store) snapshot() *state {
	s.pubMu.RLock()
	defer s.pubMu.RUnlock()
	return s.cur
}

func (s *Store) publish(next *state) {
	s.pubMu.Lock()
	s.cur = next
	s.pubMu.Unlock()
}

func (s *Store) setWriteFailed(err error) {
	s.pubMu.Lock()
	s.writeFailed = err
	s.pubMu.Unlock()
}

// degraded reports whether new requests, approvals and grant use are off.
func (s *Store) degraded() bool {
	s.pubMu.RLock()
	defer s.pubMu.RUnlock()
	return s.writeFailed != nil || s.quarantine != quarantineNone
}

func (s *Store) writesRefused() bool {
	s.pubMu.RLock()
	defer s.pubMu.RUnlock()
	return s.quarantine == quarantineFailed
}

// Health is what /v1/status shows for the grant store.
type Health struct {
	Degraded      bool   // no new requests/approvals and no grant-backed access
	Reason        string // short operator-facing explanation when Degraded
	WritesRefused bool   // corrupt file could not be moved aside; nothing is written
	QuarantinedTo string // where a corrupt grants.json was moved, if it was
	AuditPending  int    // committed events not yet in the audit log (>0 = audit degraded)
}

// Health reports the store's degraded state for status pages.
func (s *Store) Health() Health {
	s.pubMu.RLock()
	defer s.pubMu.RUnlock()
	h := Health{QuarantinedTo: s.quarantinedTo, AuditPending: len(s.cur.AuditPending)}
	switch {
	case s.quarantine == quarantineFailed:
		h.Degraded, h.WritesRefused = true, true
		h.Reason = "grants file is corrupt and could not be moved aside; fix it and restart"
	case s.quarantine == quarantineOK:
		h.Degraded = true
		h.Reason = "grants file was corrupt and moved to " + s.quarantinedTo + "; restart after review"
	case s.writeFailed != nil:
		h.Degraded = true
		h.Reason = "last save of the grants file failed: " + s.writeFailed.Error()
	}
	return h
}

// --- write protocol ---------------------------------------------------------

func (s *Store) newEvent(name string, phase Phase, agent, actor, ip string) Event {
	return Event{ID: newID("evt_"), Name: name, Phase: phase, Time: s.now(), Agent: agent, Actor: actor, ActorIP: ip}
}

// derive makes the attempt / failed twin of a committed event.
func derive(e Event, op string, phase Phase) Event {
	e.Name = op + "." + string(phase)
	e.Phase = phase
	return e
}

func (s *Store) save(st *state) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return s.fs.WriteFileAtomic(s.opts.Path, data, 0600)
}

// commit runs steps 2-5 for create / approve / deny. On a failed save nothing
// is published. If the rename already happened (dir fsync failed), disk may
// hold the unpublished change, so commit immediately writes the published
// state back over it; if that also fails the store is degraded until Tick
// manages to. (A crash in that short window can still bring the change back.)
func (s *Store) commit(next *state, op string, committed Event) error {
	if err := s.appendAudit(derive(committed, op, PhaseAttempt)); err != nil {
		return &Error{Code: CodeAuditWriteFailed, Msg: "audit log unavailable; nothing changed", Err: err}
	}
	next.AuditPending = append(next.AuditPending, committed)
	if err := s.save(next); err != nil {
		msg := "could not save the grants file; nothing changed"
		maybeSaved := false
		if errors.Is(err, fsutil.ErrDirSyncFailed) {
			if rerr := s.save(s.snapshot()); rerr != nil {
				s.setWriteFailed(err)
				// Residual risk (review R1 G1, accepted): the unacknowledged
				// change is on disk and the rollback failed, so a restart
				// before Tick heals the file loads it. For approve that is a
				// grant the human did approve; tell them so they can revoke.
				if op == opApprove {
					msg = approveMaybeOnDiskMsg
					maybeSaved = true
				}
			}
		}
		s.appendFailed(committed, op, err)
		return &Error{Code: CodeStoreWriteFailed, Msg: msg, Err: err, MaybeSaved: maybeSaved}
	}
	s.publish(next)
	s.setWriteFailed(nil)
	s.flushAudit()
	return nil
}

// commitRevoke runs the protocol for revoke and agent delete. A revoke always
// takes effect in memory, even when the attempt line or the save fails; a
// failed save returns REVOKE_NOT_DURABLE and degrades the store.
func (s *Store) commitRevoke(next *state, op string, attempt Event, committed []Event) error {
	if err := s.appendAudit(derive(attempt, op, PhaseAttempt)); err != nil {
		// Never let a broken audit log keep a grant alive. The committed
		// events below still go through audit_pending.
		s.logf("WARNING: grant store: audit attempt line for %s failed, revoking anyway: %v", op, err)
	}
	next.AuditPending = append(next.AuditPending, committed...)
	err := s.save(next)
	s.publish(next)
	if err != nil {
		s.setWriteFailed(err)
		s.appendFailed(attempt, op, err)
		return &Error{Code: CodeRevokeNotDurable,
			Msg: "revoked until the next restart but not saved; fix the disk, retry, or rotate the secret", Err: err}
	}
	s.setWriteFailed(nil)
	s.flushAudit()
	return nil
}

// appendAudit hands the sink a deep copy of e, never the store's own slices.
func (s *Store) appendAudit(e Event) error { return s.sink.Append(e.clone()) }

func (s *Store) appendFailed(e Event, op string, cause error) {
	f := derive(e, op, PhaseFailed)
	f.Detail = map[string]string{"error": cause.Error()}
	if err := s.appendAudit(f); err != nil {
		s.logf("WARNING: grant store: could not audit failed %s: %v", op, err)
	}
}

// flushAudit appends queued committed events in order, stopping at the first
// failure. Skipped while memory is ahead of disk (those events are not durable).
// Caller holds s.mu.
func (s *Store) flushAudit() {
	if s.degradedByWrite() {
		return
	}
	cur := s.snapshot()
	n := 0
	for _, e := range cur.AuditPending {
		if err := s.appendAudit(e); err != nil {
			s.logf("WARNING: grant store: audit append for %s failed, will retry: %v", e.Name, err)
			break
		}
		n++
	}
	if n == 0 {
		return
	}
	next := cur.clone()
	next.AuditPending = slices.Clone(cur.AuditPending[n:])
	s.publish(next)
	s.auditDirty = true
}

func (s *Store) degradedByWrite() bool {
	s.pubMu.RLock()
	defer s.pubMu.RUnlock()
	return s.writeFailed != nil
}

// --- create -----------------------------------------------------------------

// CreateInput is what the API passes to Create. Agent, SourceIP, AuthMethod
// and CredentialFP come from authentication, never from the request body.
type CreateInput struct {
	Agent        string
	Paths        []string
	Action       string
	Reason       string
	TTL          time.Duration // 0 = DefaultGrantTTL; clamped to [1m, MaxGrantTTL]
	SourceIP     string
	AuthMethod   string // AuthBearer, AuthMTLS or AuthToken
	CredentialFP string // bearer: BearerFingerprint(hash); mtls: cert fingerprint; token: empty
}

// Create files a new pending request. It returns created=true for a new
// request, or the existing request with created=false when the agent already
// has an identical pending one (same sorted paths and action). Limits,
// cooldown and dedup are all checked under the store lock.
func (s *Store) Create(in CreateInput) (Request, bool, error) {
	if in.Agent == "" {
		return Request{}, false, newErr(CodeInvalidRequest, "agent is required")
	}
	switch in.AuthMethod {
	case AuthBearer, AuthMTLS:
		if in.CredentialFP == "" {
			return Request{}, false, newErr(CodeInvalidRequest, "credential fingerprint is required")
		}
	case AuthToken:
		in.CredentialFP = ""
	default:
		return Request{}, false, newErr(CodeInvalidRequest, "requests need the agent's own bearer, mTLS or short-lived token")
	}
	if in.Action != ActionReadValue {
		return Request{}, false, newErr(CodeActionNotGrantable, "only %s can be requested", ActionReadValue)
	}
	paths, err := NormalizePaths(in.Paths)
	if err != nil {
		return Request{}, false, err
	}
	reason, err := CleanText(in.Reason, MaxReasonLen)
	if err != nil {
		return Request{}, false, err
	}
	if reason == "" {
		return Request{}, false, newErr(CodeInvalidRequest, "a reason is required")
	}
	ttl := in.TTL
	switch {
	case ttl < 0:
		return Request{}, false, newErr(CodeInvalidRequest, "ttl must be positive")
	case ttl == 0:
		ttl = s.opts.DefaultGrantTTL
	}
	ttl = min(max(ttl, MinGrantTTL), s.opts.MaxGrantTTL)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.degraded() {
		return Request{}, false, newErr(CodeRequestsDegraded, "access requests are temporarily unavailable")
	}
	if !s.exist(in.Agent) {
		return Request{}, false, newErr(CodeUnknownAgent, "agent no longer exists")
	}
	now := s.now()
	cur := s.snapshot()

	var agentPending, allPending, recent []*Request
	var cooldownUntil time.Time
	for _, r := range cur.Requests {
		pending := r.Status == StatusPending && now.Before(r.ExpiresAt)
		if pending {
			allPending = append(allPending, r)
		}
		if r.Agent != in.Agent {
			continue
		}
		if pending {
			if r.Action == in.Action && slices.Equal(r.Paths, paths) {
				return r.clone(now), false, nil // identical pending request
			}
			agentPending = append(agentPending, r)
		}
		if now.Before(r.CreatedAt.Add(time.Hour)) {
			recent = append(recent, r)
		}
		if r.Status == StatusDenied && r.Action == in.Action && overlaps(r.Paths, paths) {
			if until := r.DecidedAt.Add(DenyCooldown); now.Before(until) && until.After(cooldownUntil) {
				cooldownUntil = until
			}
		}
	}
	if !cooldownUntil.IsZero() {
		return Request{}, false, &Error{Code: CodeRequestCooldown, RetryAfter: cooldownUntil.Sub(now),
			Msg: "a human recently denied one of these paths; ask the user before requesting again"}
	}
	if len(agentPending) >= MaxPendingPerAgent {
		return Request{}, false, &Error{Code: CodeTooManyPending, RetryAfter: firstExpiry(agentPending).Sub(now),
			Msg: fmt.Sprintf("at most %d pending requests per agent", MaxPendingPerAgent)}
	}
	if len(allPending) >= MaxPendingTotal {
		return Request{}, false, &Error{Code: CodeTooManyPending, RetryAfter: firstExpiry(allPending).Sub(now),
			Msg: "too many pending requests"}
	}
	if len(recent) >= MaxCreatesPerHour {
		oldest := recent[0].CreatedAt
		for _, r := range recent {
			if r.CreatedAt.Before(oldest) {
				oldest = r.CreatedAt
			}
		}
		return Request{}, false, &Error{Code: CodeRateLimited, RetryAfter: oldest.Add(time.Hour).Sub(now),
			Msg: fmt.Sprintf("at most %d requests per hour", MaxCreatesPerHour)}
	}

	r := &Request{
		ID: newID("req_"), Agent: in.Agent, Paths: paths, Action: in.Action, Reason: reason,
		RequestedTTL: ttl, SourceIP: in.SourceIP, AuthMethod: in.AuthMethod, CredentialFP: in.CredentialFP,
		Status: StatusPending, CreatedAt: now, ExpiresAt: now.Add(s.opts.RequestTTL),
	}
	next := cur.clone()
	next.Requests[r.ID] = r
	ev := s.newEvent(EventRequestCreated, PhaseCommitted, r.Agent, r.Agent, r.SourceIP)
	ev.RequestID, ev.Paths, ev.Action = r.ID, paths, r.Action
	ev.Detail = map[string]string{"requested_ttl": ttl.String(), "auth_method": r.AuthMethod}
	if err := s.commit(next, opCreate, ev); err != nil {
		return Request{}, false, err
	}
	return r.clone(now), true, nil
}

func overlaps(a, b []string) bool {
	for _, p := range a {
		if slices.Contains(b, p) {
			return true
		}
	}
	return false
}

func firstExpiry(rs []*Request) time.Time {
	t := rs[0].ExpiresAt
	for _, r := range rs[1:] {
		if r.ExpiresAt.Before(t) {
			t = r.ExpiresAt
		}
	}
	return t
}

// --- approve / deny ---------------------------------------------------------

// ApproveInput carries the decision and the CURRENT config values the API
// re-checks at approval time. The API has already checked that Approver is
// allowed to approve and that no path matches deny_paths.
type ApproveInput struct {
	RequestID    string
	Approver     string // "dashboard@<ip>" or the approver agent's name
	ApproverIP   string
	Paths        []string      // nil = all requested paths; non-nil must be a non-empty subset
	TTL          time.Duration // 0 = requested TTL; may shorten, never lengthen
	MaxTTL       time.Duration // current max_grant_ttl (0 = store default); the grant is clamped to it
	SealedOnly   bool          // current require_sealed
	BindSourceIP bool          // current bind_source_ip
}

// Approve turns a pending request into a grant. Repeating the same approval
// (same resolved paths and TTL) returns the original grant; any other call on
// a non-pending request is NOT_PENDING. The 10-active-grant cap is checked
// here; on GRANT_LIMIT the request stays pending.
func (s *Store) Approve(in ApproveInput) (Request, Grant, error) {
	if in.Approver == "" {
		return Request{}, Grant{}, newErr(CodeInvalidRequest, "approver is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.degraded() {
		return Request{}, Grant{}, newErr(CodeRequestsDegraded, "approvals are temporarily unavailable")
	}
	now := s.now()
	cur := s.snapshot()
	r, ok := cur.Requests[in.RequestID]
	if !ok {
		return Request{}, Grant{}, newErr(CodeNotFound, "request not found")
	}
	if in.Approver == r.Agent {
		return Request{}, Grant{}, newErr(CodeSelfApproval, "an agent cannot approve its own request")
	}

	paths := r.Paths
	if in.Paths != nil {
		if len(in.Paths) == 0 {
			return Request{}, Grant{}, newErr(CodeEmptyGrant, "at least one path must stay in the grant")
		}
		np, err := NormalizePaths(in.Paths)
		if err != nil {
			return Request{}, Grant{}, err
		}
		for _, p := range np {
			if !slices.Contains(r.Paths, p) {
				return Request{}, Grant{}, newErr(CodeWideningNotAllowed, "path %q was not requested", p)
			}
		}
		paths = np
	}
	ttl := in.TTL
	switch {
	case ttl == 0:
		ttl = r.RequestedTTL
	case ttl < MinGrantTTL:
		return Request{}, Grant{}, newErr(CodeInvalidRequest, "ttl must be at least %s", MinGrantTTL)
	case ttl > r.RequestedTTL:
		return Request{}, Grant{}, newErr(CodeWideningNotAllowed, "ttl longer than requested")
	}
	maxTTL := in.MaxTTL
	if maxTTL <= 0 {
		maxTTL = s.opts.MaxGrantTTL
	}
	ttl = min(ttl, maxTTL)

	if r.Status == StatusApproved {
		if g := cur.Grants[r.GrantID]; g != nil && slices.Equal(g.Paths, paths) && g.ExpiresAt.Sub(g.CreatedAt) == ttl {
			return r.clone(now), s.grantView(g), nil
		}
		return Request{}, Grant{}, newErr(CodeNotPending, "request is %s", r.Status)
	}
	if st := r.clone(now).Status; st != StatusPending {
		return Request{}, Grant{}, newErr(CodeNotPending, "request is %s", st)
	}
	if !s.exist(r.Agent) {
		return Request{}, Grant{}, newErr(CodeUnknownAgent, "requesting agent no longer exists")
	}
	active := 0
	for _, g := range cur.Grants {
		if g.Agent == r.Agent && g.State(now) == GrantActive {
			active++
		}
	}
	if active >= MaxActiveGrants {
		return Request{}, Grant{}, newErr(CodeGrantLimit, "agent already has %d active grants", MaxActiveGrants)
	}

	g := &Grant{
		ID: newID("gnt_"), RequestID: r.ID, Agent: r.Agent, Paths: paths, Action: r.Action,
		SealedOnly: in.SealedOnly, AuthMethod: r.AuthMethod, CredentialFP: r.CredentialFP,
		NotBeforeTombstone: cur.Tombstones[r.Agent],
		CreatedAt:          now, ExpiresAt: now.Add(ttl), ApprovedBy: in.Approver,
	}
	if in.BindSourceIP {
		g.BoundSourceIP = r.SourceIP
	}
	nr := *r
	nr.Status, nr.DecidedBy, nr.DeciderIP, nr.DecidedAt, nr.GrantID = StatusApproved, in.Approver, in.ApproverIP, now, g.ID
	next := cur.clone()
	next.Requests[r.ID] = &nr
	next.Grants[g.ID] = g
	ev := s.newEvent(EventRequestApproved, PhaseCommitted, r.Agent, in.Approver, in.ApproverIP)
	ev.RequestID, ev.GrantID, ev.Paths, ev.Action = r.ID, g.ID, paths, r.Action
	ev.Detail = map[string]string{"ttl": ttl.String(), "expires_at": g.ExpiresAt.Format(time.RFC3339)}
	if err := s.commit(next, opApprove, ev); err != nil {
		return Request{}, Grant{}, err
	}
	return nr.clone(now), s.grantView(g), nil
}

// DenyInput is a human's "no" on a pending request.
type DenyInput struct {
	RequestID string
	Denier    string
	DenierIP  string
	Note      string // optional, cleaned like the reason
}

// Deny rejects a pending request. Denying again with the same note returns the
// original result; anything else on a non-pending request is NOT_PENDING. The
// denial starts the 10-minute cooldown on its paths for that agent.
func (s *Store) Deny(in DenyInput) (Request, error) {
	if in.Denier == "" {
		return Request{}, newErr(CodeInvalidRequest, "denier is required")
	}
	note, err := CleanText(in.Note, MaxReasonLen)
	if err != nil {
		return Request{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writesRefused() {
		return Request{}, newErr(CodeRequestsDegraded, "grant store is read-only until an operator fixes it")
	}
	now := s.now()
	cur := s.snapshot()
	r, ok := cur.Requests[in.RequestID]
	if !ok {
		return Request{}, newErr(CodeNotFound, "request not found")
	}
	if in.Denier == r.Agent {
		return Request{}, newErr(CodeSelfApproval, "an agent cannot decide its own request")
	}
	if r.Status == StatusDenied && r.Note == note {
		return r.clone(now), nil
	}
	if st := r.clone(now).Status; st != StatusPending {
		return Request{}, newErr(CodeNotPending, "request is %s", st)
	}
	nr := *r
	nr.Status, nr.DecidedBy, nr.DeciderIP, nr.DecidedAt, nr.Note = StatusDenied, in.Denier, in.DenierIP, now, note
	next := cur.clone()
	next.Requests[r.ID] = &nr
	ev := s.newEvent(EventRequestDenied, PhaseCommitted, r.Agent, in.Denier, in.DenierIP)
	ev.RequestID, ev.Paths, ev.Action = r.ID, r.Paths, r.Action
	if note != "" {
		ev.Detail = map[string]string{"note": note}
	}
	if err := s.commit(next, opDeny, ev); err != nil {
		return Request{}, err
	}
	return nr.clone(now), nil
}

// --- revoke / delete agent --------------------------------------------------

// RevokeInput identifies a grant and who is pulling it back.
type RevokeInput struct {
	GrantID string
	By      string // approver identity or the owning agent's name
	IP      string
	// OwnerOnly is set when an agent revokes its own grant: a grant owned by
	// anyone else is reported as NOT_FOUND (no existence oracle). Approvers
	// leave it false; the API decides who counts as an approver.
	OwnerOnly bool
}

// Revoke ends a grant now. It is idempotent: revoking a revoked grant returns
// it unchanged. If the save fails the grant is STILL revoked in memory (every
// later Match denies), the error is REVOKE_NOT_DURABLE, and the store stays
// degraded until a save succeeds; retrying Revoke retries the save.
func (s *Store) Revoke(in RevokeInput) (Grant, error) {
	if in.By == "" {
		return Grant{}, newErr(CodeInvalidRequest, "revoker is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	cur := s.snapshot()
	g, ok := cur.Grants[in.GrantID]
	if !ok || (in.OwnerOnly && g.Agent != in.By) {
		return Grant{}, newErr(CodeNotFound, "grant not found")
	}
	if s.writesRefused() {
		return Grant{}, newErr(CodeRequestsDegraded, "grant store is read-only until an operator fixes it")
	}
	if !g.RevokedAt.IsZero() {
		if s.degradedByWrite() {
			// An earlier revoke was not saved. Retry the save now.
			if err := s.save(cur); err != nil {
				s.setWriteFailed(err)
				return s.grantView(g), &Error{Code: CodeRevokeNotDurable,
					Msg: "revoked until the next restart but not saved; fix the disk, retry, or rotate the secret", Err: err}
			}
			s.setWriteFailed(nil)
			s.flushAudit()
		}
		return s.grantView(g), nil
	}
	ng := *g
	ng.RevokedAt, ng.RevokedBy = now, in.By
	next := cur.clone()
	next.Grants[g.ID] = &ng
	ev := s.newEvent(EventGrantRevoked, PhaseCommitted, g.Agent, in.By, in.IP)
	ev.RequestID, ev.GrantID, ev.Paths, ev.Action = g.RequestID, g.ID, g.Paths, g.Action
	err := s.commitRevoke(next, opRevoke, ev, []Event{ev})
	return s.grantView(&ng), err
}

// DeleteAgentResult lists what DeleteAgent ended.
type DeleteAgentResult struct {
	RevokedGrants   []string
	ExpiredRequests []string
}

// DeleteAgent is step 1 and 2 of agent deletion, under the store lock:
// durably revoke the agent's active grants, expire its pending requests and
// record a tombstone (name -> deleted_at); then call removeACL to drop the
// ACL entry. If the save fails, everything is still revoked in memory, the
// error is REVOKE_NOT_DURABLE and removeACL is NOT called. If removeACL
// fails the grants stay revoked (fail closed). removeACL may be nil and must
// not call back into the Store.
func (s *Store) DeleteAgent(agent, by, ip string, removeACL func() error) (DeleteAgentResult, error) {
	var res DeleteAgentResult
	if agent == "" || by == "" {
		return res, newErr(CodeInvalidRequest, "agent and actor are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writesRefused() {
		return res, newErr(CodeRequestsDegraded, "grant store is read-only; cannot record the agent deletion")
	}
	now := s.now()
	cur := s.snapshot()
	next := cur.clone()
	var events []Event
	for id, g := range cur.Grants {
		if g.Agent != agent || g.State(now) != GrantActive {
			continue
		}
		ng := *g
		ng.RevokedAt, ng.RevokedBy = now, by
		next.Grants[id] = &ng
		res.RevokedGrants = append(res.RevokedGrants, id)
		ev := s.newEvent(EventGrantRevoked, PhaseCommitted, agent, by, ip)
		ev.RequestID, ev.GrantID, ev.Paths, ev.Action = g.RequestID, g.ID, g.Paths, g.Action
		ev.Detail = map[string]string{"cause": "agent_deleted"}
		events = append(events, ev)
	}
	for id, r := range cur.Requests {
		if r.Agent != agent || r.clone(now).Status != StatusPending {
			continue
		}
		nr := *r
		nr.Status, nr.DecidedBy, nr.DeciderIP, nr.DecidedAt, nr.Note = StatusExpired, by, ip, now, "agent deleted"
		next.Requests[id] = &nr
		res.ExpiredRequests = append(res.ExpiredRequests, id)
		ev := s.newEvent(EventRequestExpired, PhaseCommitted, agent, by, ip)
		ev.RequestID, ev.Paths, ev.Action = r.ID, r.Paths, r.Action
		ev.Detail = map[string]string{"cause": "agent_deleted"}
		events = append(events, ev)
	}
	sort.Strings(res.RevokedGrants)
	sort.Strings(res.ExpiredRequests)
	next.Tombstones[agent] = now
	summary := s.newEvent(EventAgentDeleted, PhaseCommitted, agent, by, ip)
	summary.Detail = map[string]string{
		"revoked_grants":   fmt.Sprint(len(res.RevokedGrants)),
		"expired_requests": fmt.Sprint(len(res.ExpiredRequests)),
	}
	events = append(events, summary)
	if err := s.commitRevoke(next, opDeleteAgent, summary, events); err != nil {
		return res, err
	}
	if removeACL != nil {
		if err := removeACL(); err != nil {
			return res, &Error{Code: CodeDeleteACLFailed,
				Msg: "grants were revoked but the ACL entry could not be removed", Err: err}
		}
	}
	return res, nil
}

// --- match / use ------------------------------------------------------------

// Caller is the authenticated identity on a data request. The API fills it
// from authInfo; session callers must never reach Match.
type Caller struct {
	Agent         string
	SourceIP      string
	AuthMethod    string    // AuthBearer, AuthMTLS or AuthToken
	CredentialFP  string    // same format as CreateInput.CredentialFP
	TokenIssuedAt time.Time // for AuthToken
}

// MatchResult is Match's answer. Grant is a copy of the active grant that
// allows the access, or nil. When Grant is nil, Reason is ReasonGrantExpired
// or ReasonGrantRevoked if a grant for this agent+path+action ended within the
// last 24h, else "" (plain ACL denial).
type MatchResult struct {
	Grant  *Grant
	Reason string
}

// Match finds an active grant that lets c do action on path right now. It
// checks expiry and revoke against the clock on every call (no cache), the
// credential binding, the bound IP, and that the agent still exists. It
// returns nothing while the store is degraded.
//
// The ACL lookup runs first, outside any store lock. The grant decision then
// runs entirely under the publish read-lock, which only blocks the instant a
// transition swaps in new state (never during file or audit I/O). Any revoke
// acknowledged before that point is therefore seen (review R1 G2).
func (s *Store) Match(c Caller, path, action string) MatchResult {
	if c.Agent == "" || !s.exist(c.Agent) {
		return MatchResult{}
	}
	s.pubMu.RLock()
	defer s.pubMu.RUnlock()
	if s.writeFailed != nil || s.quarantine != quarantineNone {
		return MatchResult{}
	}
	cur := s.cur
	now := s.now()
	tomb := cur.Tombstones[c.Agent]
	var endedAt time.Time
	var reason string
	// When several active grants cover the path, prefer one that allows
	// plain delivery; otherwise the map's random order would make plain
	// reads succeed or fail at random (review P5 S2).
	var sealedMatch *Grant
	for _, g := range cur.Grants {
		if g.Agent != c.Agent || !g.covers(path, action) {
			continue
		}
		switch g.State(now) {
		case GrantActive:
			if credentialMatches(g, c, tomb) {
				if !g.SealedOnly {
					v := s.grantView(g)
					return MatchResult{Grant: &v}
				}
				if sealedMatch == nil {
					sealedMatch = g
				}
			}
		case GrantRevoked, GrantExpired:
			if end := g.endedAt(); now.Sub(end) < EndedLookback && end.After(endedAt) {
				endedAt = end
				reason = ReasonGrantExpired
				if g.State(now) == GrantRevoked {
					reason = ReasonGrantRevoked
				}
			}
		}
	}
	if sealedMatch != nil {
		v := s.grantView(sealedMatch)
		return MatchResult{Grant: &v}
	}
	return MatchResult{Reason: reason}
}

// credentialMatches applies the plan's credential binding table.
func credentialMatches(g *Grant, c Caller, tomb time.Time) bool {
	if c.AuthMethod != g.AuthMethod {
		return false
	}
	if g.BoundSourceIP != "" && c.SourceIP != g.BoundSourceIP {
		return false
	}
	switch g.AuthMethod {
	case AuthBearer, AuthMTLS:
		return g.CredentialFP != "" &&
			subtle.ConstantTimeCompare([]byte(c.CredentialFP), []byte(g.CredentialFP)) == 1
	case AuthToken:
		notBefore := g.NotBeforeTombstone
		if tomb.After(notBefore) {
			notBefore = tomb
		}
		return !c.TokenIssuedAt.IsZero() && c.TokenIssuedAt.After(notBefore)
	}
	return false
}

// RecordUse notes that a grant just authorized an access. Counts are kept in
// memory and saved by the next Tick, so a crash can lose a few seconds of
// them; the audit log is the authoritative record.
func (s *Store) RecordUse(grantID string) {
	now := s.now()
	s.usageMu.Lock()
	d := s.usage[grantID]
	d.last, d.count = now, d.count+1
	s.usage[grantID] = d
	s.usageMu.Unlock()
}

// --- reads ------------------------------------------------------------------

// clone returns a caller-owned copy, showing a pending request past its
// window as expired (lazy expiry; Tick makes it durable).
func (r *Request) clone(now time.Time) Request {
	c := *r
	c.Paths = slices.Clone(r.Paths)
	if c.Status == StatusPending && !now.Before(c.ExpiresAt) {
		c.Status = StatusExpired
	}
	return c
}

// grantView returns a caller-owned copy including not-yet-saved usage.
func (s *Store) grantView(g *Grant) Grant {
	c := *g
	c.Paths = slices.Clone(g.Paths)
	s.usageMu.Lock()
	if d, ok := s.usage[g.ID]; ok {
		c.UseCount += d.count
		if d.last.After(c.LastUsedAt) {
			c.LastUsedAt = d.last
		}
	}
	s.usageMu.Unlock()
	return c
}

// GetRequest returns one request by ID. The API decides whether the caller
// may see it (agents only their own; 404 otherwise).
func (s *Store) GetRequest(id string) (Request, bool) {
	r, ok := s.snapshot().Requests[id]
	if !ok {
		return Request{}, false
	}
	return r.clone(s.now()), true
}

// ListRequests returns requests, oldest first. agent "" means all agents;
// status "" means any status (expiry applied lazily).
func (s *Store) ListRequests(agent string, status Status) []Request {
	now := s.now()
	var out []Request
	for _, r := range s.snapshot().Requests {
		if agent != "" && r.Agent != agent {
			continue
		}
		c := r.clone(now)
		if status != "" && c.Status != status {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return byAge(out[i].CreatedAt, out[j].CreatedAt, out[i].ID, out[j].ID) })
	return out
}

// GetGrant returns one grant by ID (copy). Use Grant.State for its status.
func (s *Store) GetGrant(id string) (Grant, bool) {
	g, ok := s.snapshot().Grants[id]
	if !ok {
		return Grant{}, false
	}
	return s.grantView(g), true
}

// ListGrants returns grants, oldest first. agent "" means all agents; only
// active grants unless includeInactive.
func (s *Store) ListGrants(agent string, includeInactive bool) []Grant {
	now := s.now()
	var out []Grant
	for _, g := range s.snapshot().Grants {
		if agent != "" && g.Agent != agent {
			continue
		}
		if !includeInactive && g.State(now) != GrantActive {
			continue
		}
		out = append(out, s.grantView(g))
	}
	sort.Slice(out, func(i, j int) bool { return byAge(out[i].CreatedAt, out[j].CreatedAt, out[i].ID, out[j].ID) })
	return out
}

// byAge orders oldest first, ties broken by ID so lists are deterministic.
func byAge(ti, tj time.Time, idi, idj string) bool {
	if !ti.Equal(tj) {
		return ti.Before(tj)
	}
	return idi < idj
}

// --- cleanup ----------------------------------------------------------------

// Tick is the 30s cleanup step: persist expiry of pending requests and grants
// (queuing their audit events), prune records past retention, save use
// counts, retry a failed save (which ends write-degraded mode), and retry
// audit events still in audit_pending. Enforcement never waits for Tick;
// Match checks the clock itself.
func (s *Store) Tick() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writesRefused() {
		return
	}
	now := s.now()
	cur := s.snapshot()
	next := cur.clone()
	changed := false

	for id, r := range cur.Requests {
		if r.Status == StatusPending && !now.Before(r.ExpiresAt) {
			nr := *r
			nr.Status = StatusExpired
			next.Requests[id] = &nr
			ev := s.newEvent(EventRequestExpired, PhaseCommitted, r.Agent, "system", "")
			ev.RequestID, ev.Paths, ev.Action = r.ID, r.Paths, r.Action
			next.AuditPending = append(next.AuditPending, ev)
			changed = true
		}
	}
	for id, g := range cur.Grants {
		if g.State(now) == GrantExpired && !g.ExpiryRecorded {
			ng := *g
			ng.ExpiryRecorded = true
			next.Grants[id] = &ng
			ev := s.newEvent(EventGrantExpired, PhaseCommitted, g.Agent, "system", "")
			ev.RequestID, ev.GrantID, ev.Paths, ev.Action = g.RequestID, g.ID, g.Paths, g.Action
			next.AuditPending = append(next.AuditPending, ev)
			changed = true
		}
	}
	if s.prune(next, now) {
		changed = true
	}

	s.usageMu.Lock()
	taken := s.usage
	s.usage = map[string]usageDelta{}
	s.usageMu.Unlock()
	for id, d := range taken {
		if g, ok := next.Grants[id]; ok {
			ng := *g
			ng.UseCount += d.count
			if d.last.After(ng.LastUsedAt) {
				ng.LastUsedAt = d.last
			}
			next.Grants[id] = &ng
			changed = true
		}
	}

	if changed || s.auditDirty || s.degradedByWrite() {
		if err := s.save(next); err != nil {
			s.logf("ERROR: grant store: saving %s failed: %v", s.opts.Path, err)
			s.usageMu.Lock()
			for id, d := range taken {
				m := s.usage[id]
				m.count += d.count
				if d.last.After(m.last) {
					m.last = d.last
				}
				s.usage[id] = m
			}
			s.usageMu.Unlock()
			if errors.Is(err, fsutil.ErrDirSyncFailed) || s.degradedByWrite() {
				s.setWriteFailed(err)
			}
		} else {
			s.publish(next)
			s.setWriteFailed(nil)
			s.auditDirty = false
		}
	}
	// Emits what is durable on disk; skipped while memory is ahead of disk.
	s.flushAudit()
}

// prune drops records past retention from next. Returns whether it removed any.
func (s *Store) prune(next *state, now time.Time) bool {
	removed := false
	for id, g := range next.Grants {
		if g.State(now) != GrantActive && !now.Before(g.endedAt().Add(Retention)) {
			delete(next.Grants, id)
			removed = true
		}
	}
	for id, r := range next.Requests {
		if r.Status == StatusPending {
			continue
		}
		end := r.DecidedAt
		if r.Status == StatusExpired && end.IsZero() {
			end = r.ExpiresAt
		}
		if g, ok := next.Grants[r.GrantID]; ok {
			end = g.endedAt()
			if g.State(now) == GrantActive {
				continue
			}
		}
		if !now.Before(end.Add(Retention)) {
			delete(next.Requests, id)
			removed = true
		}
	}
	for name, at := range next.Tombstones {
		if !now.Before(at.Add(s.opts.TombstoneRetention)) {
			delete(next.Tombstones, name)
			removed = true
		}
	}
	return removed
}

// Run calls Tick every interval until ctx is done. The API starts it once.
func (s *Store) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Tick()
		}
	}
}
