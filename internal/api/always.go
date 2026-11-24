package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/grant"
)

// "Always" answers put read access on the agent's own access list. The grant
// store decides when (internal/grant/always.go); this is its way to the list.

// alwaysRules adapts the ACL to grant.AlwaysRules.
type alwaysRules struct{ acl *acl.ACL }

// NewAlwaysRules gives the grant store (grant.Options.Always) the access list
// "always" answers change.
func NewAlwaysRules(a *acl.ACL) grant.AlwaysRules { return alwaysRules{a} }

// tokenAsked reports whether the agent's token is still the one, and the same
// issue of it, that made the request. Requests from before issues were recorded
// compare the token alone.
func tokenAsked(rq grant.Request, a *acl.Agent) bool {
	return grant.BearerFingerprint(a.TokenHash) == rq.CredentialFP && (rq.IssueFP == "" || rq.IssueFP == sessionCredentialFP(a))
}

// checkTokenAsked is tokenAsked as a check under the access list's lock.
func checkTokenAsked(rq grant.Request) func(acl.Agent) error {
	return func(a acl.Agent) error {
		if !tokenAsked(rq, &a) {
			return &grant.Error{Code: grant.CodeCredentialChanged, Msg: "this agent's token was replaced after it asked; it has to ask again"}
		}
		return nil
	}
}

// agentGone turns the ACL's "no such agent" into the store's.
func agentGone(err error) error {
	if errors.Is(err, acl.ErrAgentNotFound) {
		return &grant.Error{Code: grant.CodeUnknownAgent, Msg: "requesting agent no longer exists"}
	}
	return err
}

func (r alwaysRules) Stage(rq grant.Request, by string, at time.Time, paths []string) error {
	origin := acl.AlwaysOrigin{RequestID: rq.ID, By: by, At: at}
	return agentGone(r.acl.StageAlways(rq.Agent, origin, paths, checkTokenAsked(rq)))
}

func (r alwaysRules) Finish(rq grant.Request) error {
	return agentGone(r.acl.FinishAlways(rq.Agent, rq.ID, checkTokenAsked(rq)))
}

func (r alwaysRules) Drop(requestID string) error { return r.acl.DropStaged(requestID) }

func (r alwaysRules) Staged() []string { return r.acl.StagedRequests() }

// RequestTokenCurrent reports whether the agent still has the token that made
// rq, so that answering yes could reach it.
func (s *Server) RequestTokenCurrent(rq grant.Request) bool {
	a, err := s.acl.GetAgent(rq.Agent)
	return err == nil && tokenAsked(rq, a)
}

// RemoveAlwaysAs takes back the read access one request put on agent's list for
// path, for someone the dashboard has authenticated. The next read through it
// is denied even if the change cannot be saved; that comes back as
// REVOKE_NOT_DURABLE.
func (s *Server) RemoveAlwaysAs(agent, path, requestID, by, ip string) error {
	md := map[string]string{"agent": agent, "request_id": requestID}
	found, err := s.acl.RemoveAlways(agent, path, requestID)
	switch {
	case errors.Is(err, acl.ErrAgentNotFound), err == nil && !found:
		return &ApprovalError{CodeNotFound, "that access was already removed", http.StatusNotFound}
	case err != nil:
		s.logAudit(s.audit.LogDeniedWithMetadata(by, "always.remove", path, ip, "store_write_failed", md))
		return &grant.Error{Code: grant.CodeRevokeNotDurable,
			Msg: "removed until the next restart but not saved; fix the disk and remove it again", Err: err}
	}
	s.logAudit(s.audit.LogAllowedWithMetadata(by, "always.removed", path, ip, md))
	return nil
}
