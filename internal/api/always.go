package api

import (
	"errors"
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

func (r alwaysRules) Add(agent, credentialFP, requestID, by string, at time.Time, paths []string) error {
	err := r.acl.AddAlways(agent, acl.AlwaysOrigin{RequestID: requestID, By: by, At: at}, paths, func(a acl.Agent) error {
		if grant.BearerFingerprint(a.TokenHash) != credentialFP {
			return &grant.Error{Code: grant.CodeCredentialChanged, Msg: "this agent's token was replaced after it asked; it has to ask again"}
		}
		return nil
	})
	if errors.Is(err, acl.ErrAgentNotFound) {
		return &grant.Error{Code: grant.CodeUnknownAgent, Msg: "requesting agent no longer exists"}
	}
	return err
}

func (r alwaysRules) Clear(requestID string) error { return r.acl.ClearAlways(requestID) }

func (r alwaysRules) RequestIDs() []string {
	var ids []string
	for _, rule := range r.acl.ListAlways() {
		ids = append(ids, rule.RequestID)
	}
	return ids
}

// RemoveAlwaysAs takes back an agent's "always" on one path, for someone the
// dashboard has authenticated. The next read is denied even if the change
// cannot be saved; that comes back as REVOKE_NOT_DURABLE. stillAllowed says
// another rule on the agent's list goes on allowing the path.
func (s *Server) RemoveAlwaysAs(agent, path, by, ip string) (stillAllowed bool, err error) {
	ids := map[string]string{"agent": agent}
	for _, rule := range s.acl.ListAlways() {
		if rule.Agent == agent && rule.Path == path {
			ids["request_id"] = rule.RequestID
		}
	}
	n, err := s.acl.RemoveAlways(agent, path)
	switch {
	case errors.Is(err, acl.ErrAgentNotFound):
		return false, &ApprovalError{CodeNotFound, "no such agent", 404}
	case err != nil:
		s.logAudit(s.audit.LogDeniedWithMetadata(by, "always.remove", path, ip, "store_write_failed", ids))
		return false, &grant.Error{Code: grant.CodeRevokeNotDurable,
			Msg: "removed until the next restart but not saved; fix the disk and remove it again", Err: err}
	case n == 0 && ids["request_id"] == "":
		return false, &ApprovalError{CodeNotFound, "that access was already removed", 404}
	}
	s.logAudit(s.audit.LogAllowedWithMetadata(by, "always.removed", path, ip, ids))
	return s.acl.Authorize(agent, path, acl.ActionReadValue) == nil, nil
}
