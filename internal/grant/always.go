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
//  2. staged rules on the access list, which nobody can read through
//  3. grants.json: request approved
//  4. the staged rules become real
//
// So nobody can read before the answer is saved, and a live rule always has a
// saved answer behind it. If the server dies after 3, or 4 cannot be saved, the
// next start does 4. If 3 never happened, the next start throws the staged
// rules away. Nothing ever makes a live rule out of anything but a staged one,
// so access a human removed cannot come back.

// AlwaysRules is the agents' access list, as far as "always" needs it.
// internal/api adapts *acl.ACL. Called under the store's lock; it must not
// call back into the Store.
type AlwaysRules interface {
	// Stage writes inactive rules for r.Agent on exactly paths. It fails with
	// CREDENTIAL_CHANGED unless the agent's token is still the one that asked.
	Stage(r Request, by string, at time.Time, paths []string) error
	// Finish turns the request's staged rules into real ones, with the same
	// token check; none staged = nil. An error that is not a *Error means it
	// took effect but could not be saved.
	Finish(r Request) error
	// Drop throws the request's staged rules away.
	Drop(requestID string) error
	// Staged lists the requests staged rules belong to.
	Staged() []string
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
	if err := s.opts.Always.Stage(r.clone(now), in.Approver, now, paths); err != nil {
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
		s.dropStaged(r.ID)
		return Request{}, err
	}
	if err := s.opts.Always.Finish(nr.clone(now)); err != nil {
		s.logf("ERROR: grant store: request %s was approved, but saving its access failed (the next start saves it): %v", r.ID, err)
	}
	return nr.clone(now), nil
}

// dropStaged throws staged rules away. A failure is only logged: they allow
// nothing, and the next start drops them.
func (s *Store) dropStaged(requestID string) {
	if err := s.opts.Always.Drop(requestID); err != nil {
		s.logf("WARNING: grant store: dropping staged access of %s: %v", requestID, err)
	}
}

// reconcileAlways runs once at Open and settles rules the last run left staged:
// finished when their request was approved with "always", thrown away
// otherwise (never answered, answered differently, or not known).
func (s *Store) reconcileAlways() {
	if s.opts.Always == nil {
		return
	}
	for _, id := range s.opts.Always.Staged() {
		r, ok := s.cur.Requests[id]
		if !ok || r.Status != StatusApproved || !r.Always {
			s.dropStaged(id)
			continue
		}
		var ge *Error
		if err := s.opts.Always.Finish(*r); errors.As(err, &ge) {
			s.logf("WARNING: grant store: not finishing the access of %s: %v", id, err)
			s.dropStaged(id)
		} else if err != nil {
			s.logf("ERROR: grant store: saving the access of %s: %v", id, err)
		}
	}
}
