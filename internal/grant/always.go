package grant

import (
	"errors"
	"slices"
	"time"
)

// "Always": a human's yes that puts read access to the exact paths asked for
// on the agent's own access list. Two files change, the access list and
// grants.json, so the order matters:
//
//  1. the audit attempt line; failure changes nothing
//  2. the access list (each rule says which request it came from)
//  3. grants.json: request approved
//
// If 3 fails, 2 is undone. If the server dies between 2 and 3 the access list
// holds rules from a request nobody answered; Open takes them away again, and
// so does any other answer to that request. So access stands only when the
// request says it was approved.

// AlwaysRules is the agents' access list, as far as "always" needs it.
// internal/api adapts *acl.ACL. Called under the store's lock; it must not
// call back into the Store.
type AlwaysRules interface {
	// Add lets agent read exactly paths, replacing any rule already there
	// from the same request. It fails with CREDENTIAL_CHANGED unless the
	// agent's token is still the one credentialFP names, checked together
	// with the change. On any error the agent can read nothing more than
	// before.
	Add(agent, credentialFP, requestID, by string, at time.Time, paths []string) error
	// Clear removes every rule that came from a request. No rules = nil. On
	// error the rules are gone from memory but may come back after a restart.
	Clear(requestID string) error
	// RequestIDs lists the requests that rules came from.
	RequestIDs() []string
}

// AlwaysInput is a human's "always" on a pending request.
type AlwaysInput struct {
	RequestID  string
	Approver   string
	ApproverIP string
	Paths      []string // nil = all requested paths; non-nil must be a non-empty subset
}

// ApproveAlways answers a pending request with standing read access to its
// exact paths. Repeating the same answer returns the original result and adds
// nothing, even when the access was removed since. Logins have no "always".
func (s *Store) ApproveAlways(in AlwaysInput) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, paths, err := s.approvable(in.RequestID, in.Approver, in.Paths)
	if err != nil {
		return Request{}, err
	}
	if s.opts.Always == nil || r.Action != ActionReadValue {
		return Request{}, newErr(CodeAlwaysNotAllowed, "this request cannot be allowed always")
	}
	now := s.now()
	if r.Status == StatusApproved && r.Always && slices.Equal(r.GrantedPaths, paths) {
		return r.clone(now), nil
	}
	if st := r.clone(now).Status; st != StatusPending {
		return Request{}, newErr(CodeNotPending, "request is %s", st)
	}
	if !s.exist(r.Agent) {
		return Request{}, newErr(CodeUnknownAgent, "requesting agent no longer exists")
	}

	nr := *r
	nr.Status, nr.DecidedBy, nr.DeciderIP, nr.DecidedAt = StatusApproved, in.Approver, in.ApproverIP, now
	nr.Always, nr.GrantedPaths = true, paths
	ev := s.newEvent(EventRequestApproved, PhaseCommitted, r.Agent, in.Approver, in.ApproverIP)
	ev.RequestID, ev.Paths, ev.Action = r.ID, paths, r.Action
	ev.Detail = map[string]string{"always": "true"}
	if err := s.auditAttempt(opApprove, ev); err != nil {
		return Request{}, err
	}
	if err := s.opts.Always.Add(r.Agent, r.CredentialFP, r.ID, in.Approver, now, paths); err != nil {
		s.appendFailed(ev, opApprove, err)
		var ge *Error
		if errors.As(err, &ge) {
			return Request{}, ge
		}
		return Request{}, &Error{Code: CodeACLWriteFailed, Msg: "could not save the agent's access list; nothing changed", Err: err}
	}
	next := s.snapshot().clone()
	next.Requests[r.ID] = &nr
	if err := s.commitAudited(next, opApprove, ev); err != nil {
		if cerr := s.clearAlways(r.ID); cerr != nil {
			s.logf("ERROR: grant store: %v", cerr)
		}
		return Request{}, err
	}
	return nr.clone(now), nil
}

// clearAlways removes standing access left by an "always" that failed half
// way. Caller holds s.mu.
func (s *Store) clearAlways(requestID string) error {
	if s.opts.Always == nil {
		return nil
	}
	if err := s.opts.Always.Clear(requestID); err != nil {
		return &Error{Code: CodeACLWriteFailed, Msg: "could not save the agent's access list", Err: err}
	}
	return nil
}

// reconcileAlways runs once at Open: standing access whose request was never
// approved came from an answer the server died in the middle of, so it goes.
// A request the store does not know (pruned after 30 days, or a lost
// grants.json) proves nothing, and its access stays.
func (s *Store) reconcileAlways() {
	if s.opts.Always == nil {
		return
	}
	for _, id := range s.opts.Always.RequestIDs() {
		r, ok := s.cur.Requests[id]
		if !ok || r.Status == StatusApproved {
			continue
		}
		s.logf("WARNING: grant store: request %s was never approved but its access was on %q's list; removing it", id, r.Agent)
		if err := s.clearAlways(id); err != nil {
			s.logf("ERROR: grant store: %v", err)
		}
	}
}
