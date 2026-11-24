package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/audit"
)

// Who, authority and kind on identities, and who/host/authority/attested on
// audit lines. These describe a caller; nothing here decides what it may do.

// callerKey is the request context key for *requestCaller.
type callerKey struct{}

// requestCaller is the caller of one request. authenticateInfo fills it in,
// so every audit line of the request carries the labels the identity had when
// it was authenticated, not what a same-named identity has later.
type requestCaller struct {
	agent  string
	caller audit.Caller
}

// withRequestCaller gives the request an empty requestCaller.
func withRequestCaller(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), callerKey{}, &requestCaller{}))
}

// identifyCaller records the authenticated caller on the request. Host stays
// empty and Attested false: a token says nothing about where it is used from.
func identifyCaller(r *http.Request, info *authInfo, labels acl.Labels) {
	info.Labels = labels
	info.Caller = audit.Caller{Who: labels.Who, Authority: labels.Authority}
	if rc, ok := r.Context().Value(callerKey{}).(*requestCaller); ok {
		rc.agent, rc.caller = info.Agent, info.Caller
	}
}

// callerFor returns the caller fields for an audit line about agent. They are
// empty unless agent is who this request authenticated as, so a line about
// "system", or a refused credential, never borrows someone's labels.
func callerFor(r *http.Request, agent string) audit.Caller {
	if r == nil {
		return audit.Caller{}
	}
	rc, ok := r.Context().Value(callerKey{}).(*requestCaller)
	if !ok || rc.agent == "" || rc.agent != agent {
		return audit.Caller{}
	}
	return rc.caller
}

// writeAudit writes one audit line for a request, adding the caller fields
// and, when e has no metadata of its own, the caller metadata hints.
func (s *Server) writeAudit(r *http.Request, e audit.Entry) error {
	e.Caller = callerFor(r, e.Agent)
	if e.Metadata == nil {
		e.Metadata = callerAuditMetadata(r)
	}
	return s.audit.Log(e)
}

// labelAuditMetadata is the caller metadata plus which labels were set to
// what, so the log shows how an identity came to be called something.
func labelAuditMetadata(r *http.Request, c acl.LabelChange) map[string]string {
	md := callerAuditMetadata(r)
	if md == nil {
		md = map[string]string{}
	}
	var changed []string
	set := func(field, v string) {
		changed = append(changed, field)
		md["identity."+field] = v // an empty value is left out of the line
	}
	if c.Who != nil {
		set("who", *c.Who)
	}
	if c.Authority != nil {
		set("authority", *c.Authority)
	}
	if c.Kind != nil {
		set("kind", *c.Kind)
	}
	if c.Formerly != nil {
		set("formerly", strings.Join(*c.Formerly, ","))
	}
	if changed != nil {
		md["identity.changed"] = strings.Join(changed, ",")
	}
	return md
}

// identityRoutes registers the route that sets an identity's labels. They are
// shown by GET /v1/agents and GET /v1/whoami.
func (s *Server) identityRoutes() {
	s.mux.HandleFunc("PATCH /v1/agents/{name}/identity", s.handleSetIdentity)
}

// handleSetIdentity: PATCH /v1/agents/{name}/identity, admin only. Sets the
// labels in the body and leaves out-of-body ones alone. The token, the
// permissions and any sessions are not touched.
func (s *Server) handleSetIdentity(w http.ResponseWriter, r *http.Request) {
	agentName, err := s.authenticate(r)
	if err != nil {
		handleAuthError(w, err)
		return
	}
	if err := s.acl.Authorize(agentName, "agents", acl.ActionAdmin); err != nil {
		jsonError(w, "access denied: admin required", http.StatusForbidden)
		return
	}

	target := r.PathValue("name")
	var change acl.LabelChange
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	// Refused, not ignored: "host" or "token" here would look as if it worked.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&change); err != nil {
		jsonError(w, "invalid request body: send any of who, authority, kind (text) and formerly (a list of names)", http.StatusBadRequest)
		return
	}
	if change, err = change.Normalized(target); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if change.Empty() {
		jsonError(w, "nothing to set: send any of who, authority, kind, formerly", http.StatusBadRequest)
		return
	}

	labels, err := s.acl.SetLabels(target, change)
	if errors.Is(err, acl.ErrAgentNotFound) {
		jsonError(w, "agent not found", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("error setting identity fields on %q: %v", target, err)
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.logAudit(s.writeAudit(r, audit.Entry{
		Agent: agentName, Action: "set-identity", Path: target, Status: "allowed",
		IP: clientIP(r), Metadata: labelAuditMetadata(r, change),
	}))
	jsonOK(w, map[string]any{"status": "ok", "identity": acl.Identity{Name: target, Labels: labels}})
}

// auditAgentChange writes the create-agent or update-agent line.
func (s *Server) auditAgentChange(r *http.Request, actor, action, target string, labels acl.LabelChange) {
	s.logAudit(s.writeAudit(r, audit.Entry{
		Agent: actor, Action: action, Path: target, Status: "allowed",
		IP: clientIP(r), Metadata: labelAuditMetadata(r, labels),
	}))
}

// identityOf returns an identity's name and labels for a response.
func (s *Server) identityOf(name string) acl.Identity {
	id := acl.Identity{Name: name}
	if a, err := s.acl.GetAgent(name); err == nil {
		id.Labels = a.Labels
	}
	return id
}
