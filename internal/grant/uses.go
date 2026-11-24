package grant

import (
	"errors"
	"maps"
	"slices"

	"github.com/phoenixsec/phoenix/internal/fsutil"
)

// SpendItem is one path about to be delivered under one grant.
type SpendItem struct {
	GrantID string
	Path    string
}

// Spend takes one use of each item's grant, for values the caller is about to
// be handed. It re-checks everything Match checked, under the lock that
// serializes every change, and saves the new counts before it returns, so a
// use can never be spent twice by two calls at once or come back after a
// restart. The result has one entry per item: nil means go ahead and deliver.
//
// Call it last, when nothing but writing the response is left: a use whose
// value was not delivered is gone. The same path under the same grant twice in
// one call costs one use. A grant with no use limit costs nothing here.
//
// With allOrNone, one refused item means nothing is spent.
func (s *Store) Spend(c Caller, action string, items []SpendItem, allOrNone bool) []error {
	errs := make([]error, len(items))
	if len(items) == 0 {
		return errs
	}
	refuse := func(err error) []error {
		for i := range errs {
			errs[i] = err
		}
		return errs
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.exist(c.Agent) {
		return refuse(newErr(CodeUnknownAgent, "agent no longer exists"))
	}
	if s.degraded() {
		return refuse(newErr(CodeRequestsDegraded, "grants are temporarily unavailable"))
	}
	now := s.now()
	next := s.snapshot().clone()
	spent := map[SpendItem]error{}
	changed, refused := false, false
	for i, it := range items {
		err, seen := spent[it]
		if !seen {
			var ng *Grant
			if ng, err = s.spendOne(next.Grants[it.GrantID], c, it.Path, action); err == nil && ng != nil {
				ng.LastUsedAt = now
				if ng.Action != ActionSSHLogin && ng.usedUp() {
					ng.UsedUpAt = now
					ev := s.newEvent(EventGrantUsedUp, PhaseCommitted, ng.Agent, "system", "")
					ev.RequestID, ev.GrantID, ev.Paths, ev.Action = ng.RequestID, ng.ID, ng.Paths, ng.Action
					next.AuditPending = append(next.AuditPending, ev)
				}
				next.Grants[ng.ID] = ng
				changed = true
			}
			spent[it] = err
		}
		errs[i] = err
		refused = refused || err != nil
	}
	if !changed || (allOrNone && refused) {
		return errs
	}
	if _, err := s.saveOrUndo(next); err != nil {
		s.logf("ERROR: grant store: saving a use failed, value not delivered: %v", err)
		if errors.Is(err, fsutil.ErrDirSyncFailed) {
			s.logf("ERROR: grant store: that use may count as spent after a restart")
		}
		return refuse(&Error{Code: CodeStoreWriteFailed, Msg: "the use could not be saved; nothing was delivered", Err: err})
	}
	s.publish(next)
	s.setWriteFailed(nil)
	s.flushAudit()
	return errs
}

// spendOne checks that g lets c use path right now and returns a copy with one
// more use counted, or nil when g has no use limit. Caller holds s.mu.
func (s *Store) spendOne(g *Grant, c Caller, path, action string) (*Grant, error) {
	if g == nil || g.Agent != c.Agent || !g.covers(path, action) || !credentialMatches(g, c) {
		return nil, newErr(CodeGrantEnded, "no such grant")
	}
	switch g.State(s.now()) {
	case GrantRevoked:
		return nil, &Error{Code: CodeGrantEnded, Msg: ReasonGrantRevoked}
	case GrantExpired:
		return nil, &Error{Code: CodeGrantEnded, Msg: ReasonGrantExpired}
	case GrantUsed:
		return nil, newErr(CodeGrantUsedUp, "every allowed use was spent")
	}
	if g.MaxUses == 0 {
		return nil, nil
	}
	if g.UsesLeft(path) == 0 {
		return nil, newErr(CodeGrantUsedUp, "every allowed use was spent")
	}
	ng := *g
	ng.Paths = slices.Clone(g.Paths)
	ng.PathUses = maps.Clone(g.PathUses)
	if ng.PathUses == nil {
		ng.PathUses = map[string]int64{}
	}
	ng.PathUses[path]++
	ng.UseCount++
	return &ng, nil
}

// SpendReason turns a Spend refusal into the denial reason Match would have
// given, or "" when it is not about the grant itself (the save failed).
func SpendReason(err error) string {
	var e *Error
	if !errors.As(err, &e) {
		return ""
	}
	switch e.Code {
	case CodeGrantUsedUp:
		return ReasonGrantUsedUp
	case CodeGrantEnded:
		if e.Msg == ReasonGrantRevoked {
			return ReasonGrantRevoked
		}
		return ReasonGrantExpired
	}
	return ""
}
