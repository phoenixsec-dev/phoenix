package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/audit"
	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/grant"
	"github.com/phoenixsec/phoenix/internal/session"
)

// Request-use grants: the API on top of internal/grant (plan sections 7, 8).
//
// An agent that gets ACL_DENIED with next_step request_use asks a human for
// temporary use of exact paths (POST /v1/access-requests). An approver says
// yes or no. A yes becomes a grant that dataAccess consults when the normal
// ACL says no. Sessions (phxs_ tokens) can never request or use a grant.

// neverGrantable actions are refused whatever the config says.
var neverGrantable = []string{"list", "delete", "admin", "write"}

// SetGrantStore attaches the grant store. Without one, the request API
// answers 501 REQUESTS_DISABLED and no grant is ever consulted.
func (s *Server) SetGrantStore(st *grant.Store) {
	s.grants = st
}

// SetAccessRequests installs the current access_requests settings. Approval
// re-checks use whatever is installed at approval time.
func (s *Server) SetAccessRequests(cfg config.AccessRequestsSettings) {
	c := cfg
	s.accessCfg.Store(&c)
}

// accessSettings returns the current settings (Enabled=false when unset).
func (s *Server) accessSettings() config.AccessRequestsSettings {
	if c := s.accessCfg.Load(); c != nil {
		return *c
	}
	return config.AccessRequestsSettings{}
}

// grantsOn reports whether grant-backed authorization is switched on.
func (s *Server) grantsOn() bool {
	return s.grants != nil && s.accessSettings().Enabled
}

// actionGrantable reports whether action may be requested under cfg.
func actionGrantable(cfg config.AccessRequestsSettings, action string) bool {
	return !slices.Contains(neverGrantable, action) && slices.Contains(cfg.GrantableActions, action)
}

// pathDenied reports whether path matches an access_requests.deny_paths glob.
func pathDenied(cfg config.AccessRequestsSettings, path string) bool {
	return session.PathInScope(path, cfg.DenyPaths)
}

// requestable is the rule for advertising request_use (plan section 10):
// feature on, action grantable, path not in deny_paths.
func (s *Server) requestable(path, action string) bool {
	if !s.grantsOn() {
		return false
	}
	cfg := s.accessSettings()
	return actionGrantable(cfg, action) && !pathDenied(cfg, path)
}

// isApprover: not a session, listed in access_requests.approvers, and still
// an agent in the ACL. The ACL check matters because short-lived tokens and
// mTLS certs authenticate by name only, so they outlive an agent delete.
// Admin ACL alone does not count. Self-approval is checked per request.
// Every approver-only path (approve, deny, ?agent= lists, full views,
// revoking others' grants) goes through this one check.
func (s *Server) isApprover(info *authInfo) bool {
	if info.UsedSession || !slices.Contains(s.accessSettings().Approvers, info.Agent) {
		return false
	}
	_, err := s.acl.GetAgent(info.Agent)
	return err == nil
}

// grantCaller describes the caller's credential for grant binding: the auth
// method plus the bearer/cert fingerprint or short-lived token issue time.
// Sessions get an empty Caller, which matches no grant and is refused by
// Create (a second guard behind dataAccess step 1: a session over mTLS
// carries the cert fingerprint, so it must never be described as "mtls").
func (s *Server) grantCaller(info *authInfo, ip string) grant.Caller {
	if info.UsedSession {
		return grant.Caller{}
	}
	c := grant.Caller{Agent: info.Agent, SourceIP: ip, AuthMethod: s.bootstrapMethod(info)}
	switch c.AuthMethod {
	case grant.AuthBearer:
		c.CredentialFP = info.BearerFP
	case grant.AuthMTLS:
		c.CredentialFP = info.CertFingerprint
	case grant.AuthToken:
		c.TokenIssuedAt = *info.TokenIssuedAt
	}
	return c
}

// --- enforcement (plan section 8) --------------------------------------------

// accessDecision is dataAccess's answer. Reason is "" when allowed, else
// "session_scope", "session_action", "acl", "grant_expired" or
// "grant_revoked". Grant is set when access comes only from a grant.
type accessDecision struct {
	Reason string
	Grant  *grant.Grant
}

// dataAccess decides a data request:
//  1. session caller: today's check (scope, action, elevated-or-ACL); grants
//     are never consulted, so a session with a caller-chosen seal key can
//     never reach a grant.
//  2. non-session caller the ACL allows: allowed.
//  3. non-session, grants on, grantable action, store healthy, Match finds an
//     active grant for this exact credential: allowed with Grant.
//  4. otherwise denied; grant_expired / grant_revoked when a matching grant
//     ended in the last 24h, else acl.
//
// list, write and delete never reach step 3 (only read_value is grantable).
func (s *Server) dataAccess(info *authInfo, path, sessionAction string, aclAction acl.Action, ip string) accessDecision {
	reason := s.baseAccessReason(info, path, sessionAction, aclAction)
	if reason == "" || info.UsedSession {
		return accessDecision{Reason: reason}
	}
	if !s.grantsOn() || !actionGrantable(s.accessSettings(), string(aclAction)) {
		return accessDecision{Reason: reason}
	}
	m := s.grants.Match(s.grantCaller(info, ip), path, string(aclAction))
	if m.Grant != nil {
		return accessDecision{Grant: m.Grant}
	}
	if m.Reason != "" {
		return accessDecision{Reason: m.Reason}
	}
	return accessDecision{Reason: reason}
}

// checkGrantSealed enforces sealed_only on grant-backed reads: without a
// validated seal key (validateSealHeader already required it to be the
// agent's registered key) the answer is 403 SEALED_REQUIRED / use_exec.
func (s *Server) checkGrantSealed(w http.ResponseWriter, r *http.Request, info *authInfo, action, path, ip string, g *grant.Grant, sealKeyValidated bool) bool {
	if g == nil || !g.SealedOnly || sealKeyValidated {
		return true
	}
	s.auditDeniedMetadata(info, action, path, ip, "sealed_required", grantAuditMetadata(r, g))
	jsonDenied(w, "access_denied", CodeSealedRequired,
		"your temporary grant for this path is only served sealed to your registered seal key",
		"use phoenix exec --redact-output, which requests and decrypts sealed values for you and hides them in the output",
		http.StatusForbidden)
	return false
}

// grantAuditMetadata is the caller metadata plus grant_id.
func grantAuditMetadata(r *http.Request, g *grant.Grant) map[string]string {
	md := callerAuditMetadata(r)
	if md == nil {
		md = map[string]string{}
	}
	md["grant_id"] = g.ID
	return md
}

// auditAllowedAccess logs an allowed read. Grant-backed reads carry
// metadata grant_id and bump the grant's use counter.
func (s *Server) auditAllowedAccess(r *http.Request, info *authInfo, action, path, ip string, sealed bool, g *grant.Grant) {
	if g == nil {
		s.auditAllowedWithSeal(r, info, action, path, ip, sealed)
		return
	}
	s.logAudit(s.audit.LogAllowedSealedWithMetadata(info.Agent, action, path, ip, sealed, grantAuditMetadata(r, g)))
	s.grants.RecordUse(g.ID)
}

// --- routes and shared plumbing ----------------------------------------------

func (s *Server) accessRoutes() {
	s.mux.HandleFunc("POST /v1/access-requests", s.handleAccessRequestCreate)
	s.mux.HandleFunc("GET /v1/access-requests", s.handleAccessRequestList)
	s.mux.HandleFunc("GET /v1/access-requests/{id}", s.handleAccessRequestGet)
	s.mux.HandleFunc("POST /v1/access-requests/{id}/approve", s.handleAccessRequestApprove)
	s.mux.HandleFunc("POST /v1/access-requests/{id}/deny", s.handleAccessRequestDeny)
	s.mux.HandleFunc("GET /v1/grants", s.handleGrantList)
	s.mux.HandleFunc("POST /v1/grants/{id}/revoke", s.handleGrantRevoke)
	s.mux.HandleFunc("GET /v1/whoami", s.handleWhoami)
}

// accessAuth authenticates a request-use call. Every response is no-store.
// Sessions are refused (403 SESSION_CANNOT_REQUEST, or APPROVER_REQUIRED on
// approver-only endpoints); a server without a grant store answers 501.
func (s *Server) accessAuth(w http.ResponseWriter, r *http.Request, approverOnly bool) (*authInfo, bool) {
	w.Header().Set("Cache-Control", "no-store")
	info, err := s.authenticateInfo(r)
	if err != nil {
		handleAuthError(w, err)
		return nil, false
	}
	if info.UsedSession {
		if approverOnly {
			writeAccessError(w, CodeApproverRequired, "session tokens cannot approve or deny access requests", http.StatusForbidden)
		} else {
			jsonDeniedStep(w, "access_denied", CodeSessionCannotRequest,
				"access requests and grants use the agent's own identity (bearer, mTLS or short-lived token), not a session",
				"", s.sessionRequestStep(r), http.StatusForbidden)
		}
		return nil, false
	}
	if s.grants == nil {
		writeAccessError(w, CodeRequestsDisabled, "access requests are not enabled on this server", http.StatusNotImplemented)
		return nil, false
	}
	return info, true
}

// sessionRequestStep is the next step for SESSION_CANNOT_REQUEST: request_use
// (resend with the agent's own identity) only when that request could
// succeed under the current settings. For POST /v1/access-requests the
// body's paths and action are checked; other endpoints name no path, so
// only "feature on and read_value grantable" applies.
func (s *Server) sessionRequestStep(r *http.Request) string {
	action, paths := grant.ActionReadValue, []string(nil)
	if r.Method == http.MethodPost && r.URL.Path == "/v1/access-requests" {
		var body accessRequestBody
		if json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body) != nil {
			return NextAskUser
		}
		if body.Action != "" {
			action = body.Action
		}
		if paths = body.Paths; len(paths) == 0 {
			return NextAskUser
		}
	}
	if s.allRequestable(paths, action) {
		return NextRequestUse
	}
	return NextAskUser
}

// allRequestable reports whether the feature is on, action is grantable and
// none of paths is in deny_paths (an empty list checks only the first two).
func (s *Server) allRequestable(paths []string, action string) bool {
	if !s.grantsOn() || !actionGrantable(s.accessSettings(), action) {
		return false
	}
	for _, p := range paths {
		if !s.requestable(p, action) {
			return false
		}
	}
	return true
}

// writeAccessError writes the denial shape for a request-use error.
func writeAccessError(w http.ResponseWriter, code, detail string, status int) {
	errMsg := "request_failed"
	if status == http.StatusForbidden {
		errMsg = "access_denied"
	}
	jsonDenied(w, errMsg, code, detail, "", status)
}

// grantErrStatus maps a grant store error code to its HTTP status (plan section 7).
var grantErrStatus = map[grant.Code]int{
	grant.CodeInvalidRequest:     http.StatusBadRequest,
	grant.CodeActionNotGrantable: http.StatusBadRequest,
	grant.CodeNotFound:           http.StatusNotFound,
	grant.CodeUnknownAgent:       http.StatusForbidden,
	grant.CodeNotPending:         http.StatusConflict,
	grant.CodeSelfApproval:       http.StatusForbidden,
	grant.CodeWideningNotAllowed: http.StatusBadRequest,
	grant.CodeEmptyGrant:         http.StatusBadRequest,
	grant.CodeGrantLimit:         http.StatusConflict,
	grant.CodeTooManyPending:     http.StatusTooManyRequests,
	grant.CodeRateLimited:        http.StatusTooManyRequests,
	grant.CodeRequestCooldown:    http.StatusTooManyRequests,
	grant.CodeAuditWriteFailed:   http.StatusInternalServerError,
	grant.CodeStoreWriteFailed:   http.StatusInternalServerError,
	grant.CodeRevokeNotDurable:   http.StatusInternalServerError,
	grant.CodeRequestsDegraded:   http.StatusServiceUnavailable,
	grant.CodeDeleteACLFailed:    http.StatusInternalServerError,
}

// writeGrantError maps a store error to the denial shape. Only the store's
// own message is shown; the underlying cause (disk errors) is logged.
// 429s carry Retry-After in whole seconds.
func writeGrantError(w http.ResponseWriter, err error) {
	var ge *grant.Error
	if !errors.As(err, &ge) {
		log.Printf("access requests: unexpected error: %v", err)
		writeAccessError(w, CodeInternalError, "internal error", http.StatusInternalServerError)
		return
	}
	status, ok := grantErrStatus[ge.Code]
	if !ok {
		status = http.StatusInternalServerError
	}
	if ge.Err != nil {
		log.Printf("access requests: %s: %v", ge.Code, ge.Err)
	}
	if status == http.StatusTooManyRequests {
		secs := int(math.Ceil(ge.RetryAfter.Seconds()))
		w.Header().Set("Retry-After", strconv.Itoa(max(secs, 1)))
	}
	writeAccessError(w, string(ge.Code), ge.Msg, status)
}

// auditRequestRejected records a refused access-request call (limits,
// deny_paths, ...). The store audits only transitions; this covers the rest.
func (s *Server) auditRequestRejected(r *http.Request, info *authInfo, op string, paths []string, ip, code string) {
	s.auditDeniedMetadata(info, op, strings.Join(paths, ","), ip, strings.ToLower(code), callerAuditMetadata(r))
}

// decodeBody reads a small JSON body. An empty body is allowed when optional.
func decodeBody(w http.ResponseWriter, r *http.Request, v any, optional bool) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		if optional && errors.Is(err, io.EOF) {
			return true
		}
		writeAccessError(w, CodeInvalidRequest, "invalid request body", http.StatusBadRequest)
		return false
	}
	return true
}

// parseTTL parses an optional duration string ("" = 0).
func parseTTL(w http.ResponseWriter, v string) (time.Duration, bool) {
	if v == "" {
		return 0, true
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		writeAccessError(w, CodeInvalidRequest, "ttl must be a positive duration like 15m", http.StatusBadRequest)
		return 0, false
	}
	return d, true
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// --- views -------------------------------------------------------------------

// requestNextStep says what the agent should do next for a request (plan
// section 7 table). g is the request's grant, if any.
func requestNextStep(rq grant.Request, g *grant.Grant, now time.Time) (step, msg string) {
	switch rq.Status {
	case grant.StatusPending:
		return NextWait, fmt.Sprintf("Waiting for a human to approve in Phoenix. Check again in 15s. Request expires at %s UTC.",
			rq.ExpiresAt.UTC().Format("15:04"))
	case grant.StatusDenied:
		return NextAskUser, "A human denied this. Do not re-request for 10 minutes; ask the user in chat if it is needed."
	case grant.StatusExpired:
		return NextAskUser, "Nobody decided in time. Ask the user before requesting again."
	}
	if g == nil {
		return NextRequestUse, "Grant ended. Request again if still needed."
	}
	switch g.State(now) {
	case grant.GrantActive:
		return NextUseExec, fmt.Sprintf("Use it with phoenix exec --redact-output --env NAME=phoenix://%s -- <command> until %s.",
			g.Paths[0], fmtTime(g.ExpiresAt))
	case grant.GrantRevoked:
		return NextAskUser, "A human revoked this. Ask the user before requesting again."
	}
	return NextRequestUse, "Grant ended. Request again if still needed."
}

// requestView is the JSON for one request. full adds approver-only facts.
func (s *Server) requestView(rq grant.Request, full bool) map[string]any {
	now := s.now()
	var g *grant.Grant
	if rq.GrantID != "" {
		if got, ok := s.grants.GetGrant(rq.GrantID); ok {
			g = &got
		}
	}
	step, msg := requestNextStep(rq, g, now)
	// Apply the current settings: a grant cannot be used while the feature
	// is off, and request_use is only advertised for requestable paths.
	switch {
	case step == NextUseExec && !s.grantsOn():
		step, msg = NextAskUser, "Access requests are turned off on this server, so the grant cannot be used. Ask the user."
	case step == NextRequestUse && !s.allRequestable(rq.Paths, rq.Action):
		step, msg = NextAskUser, "Grant ended and these paths cannot be requested right now. Ask the user."
	}
	v := map[string]any{
		"id":            rq.ID,
		"status":        string(rq.Status),
		"paths":         rq.Paths,
		"action":        rq.Action,
		"reason":        rq.Reason,
		"requested_ttl": rq.RequestedTTL.String(),
		"created_at":    fmtTime(rq.CreatedAt),
		"expires_at":    fmtTime(rq.ExpiresAt),
		"next_step":     step,
		"message":       msg,
	}
	if !rq.DecidedAt.IsZero() {
		v["decided_at"] = fmtTime(rq.DecidedAt)
	}
	if rq.Note != "" {
		v["note"] = rq.Note
	}
	if rq.GrantID != "" {
		v["grant_id"] = rq.GrantID
	}
	if g != nil {
		v["granted_paths"] = g.Paths
		v["grant_expires_at"] = fmtTime(g.ExpiresAt)
		v["grant_state"] = string(g.State(now))
		v["sealed_only"] = g.SealedOnly
	}
	if full {
		v["agent"] = rq.Agent
		v["source_ip"] = rq.SourceIP
		v["auth_method"] = rq.AuthMethod
		if rq.DecidedBy != "" {
			v["decided_by"] = rq.DecidedBy
		}
		// Per-path badge an approver needs: the agent's ACL already allows it.
		var allowed []string
		for _, p := range rq.Paths {
			if s.acl.Authorize(rq.Agent, p, acl.Action(rq.Action)) == nil {
				allowed = append(allowed, p)
			}
		}
		v["already_allowed_paths"] = allowed
	}
	return v
}

// grantView is the JSON for one grant. full adds approver-only facts.
func (s *Server) grantView(g grant.Grant, full bool) map[string]any {
	v := map[string]any{
		"id":          g.ID,
		"request_id":  g.RequestID,
		"agent":       g.Agent,
		"paths":       g.Paths,
		"action":      g.Action,
		"sealed_only": g.SealedOnly,
		"state":       string(g.State(s.now())),
		"created_at":  fmtTime(g.CreatedAt),
		"expires_at":  fmtTime(g.ExpiresAt),
		"use_count":   g.UseCount,
	}
	if !g.LastUsedAt.IsZero() {
		v["last_used_at"] = fmtTime(g.LastUsedAt)
	}
	if !g.RevokedAt.IsZero() {
		v["revoked_at"] = fmtTime(g.RevokedAt)
	}
	if full {
		v["approved_by"] = g.ApprovedBy
		v["auth_method"] = g.AuthMethod
		v["bound_source_ip"] = g.BoundSourceIP
		if g.RevokedBy != "" {
			v["revoked_by"] = g.RevokedBy
		}
	}
	return v
}

func jsonStatus(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// --- agent side --------------------------------------------------------------

type accessRequestBody struct {
	Paths  []string `json:"paths"`
	Action string   `json:"action"`
	Reason string   `json:"reason"`
	TTL    string   `json:"ttl"`
}

// handleAccessRequestCreate files a request: POST /v1/access-requests.
// 201 for a new request, 200 when an identical one is already pending.
// Requests are accepted whether or not the path exists (no existence oracle).
func (s *Server) handleAccessRequestCreate(w http.ResponseWriter, r *http.Request) {
	info, ok := s.accessAuth(w, r, false)
	if !ok {
		return
	}
	ip := clientIP(r)
	cfg := s.accessSettings()
	if !cfg.Enabled {
		writeAccessError(w, CodeRequestsDisabled, "access requests are turned off on this server", http.StatusNotImplemented)
		return
	}
	if s.grants.Health().Degraded {
		writeAccessError(w, CodeRequestsDegraded, "access requests are temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	var body accessRequestBody
	if !decodeBody(w, r, &body, false) {
		return
	}
	if body.Action == "" {
		body.Action = grant.ActionReadValue
	}
	reject := func(code, detail string, status int) {
		s.auditRequestRejected(r, info, "access_request.create", body.Paths, ip, code)
		writeAccessError(w, code, detail, status)
	}
	if !actionGrantable(cfg, body.Action) {
		reject(CodeActionNotGrantable, "only read_value can be requested", http.StatusBadRequest)
		return
	}
	paths, err := grant.NormalizePaths(body.Paths)
	if err != nil {
		msg := "invalid paths"
		var ge *grant.Error
		if errors.As(err, &ge) {
			msg = ge.Msg
		}
		reject(CodeInvalidRequest, msg, http.StatusBadRequest)
		return
	}
	body.Paths = paths
	for _, p := range paths {
		if pathDenied(cfg, p) {
			reject(CodeNotRequestable, "one or more paths can never be requested; ask the user", http.StatusForbidden)
			return
		}
	}
	allAllowed := true
	for _, p := range paths {
		if s.acl.Authorize(info.Agent, p, acl.Action(body.Action)) != nil {
			allAllowed = false
			break
		}
	}
	if allAllowed {
		reject(CodeAlreadyAllowed, "your ACL already allows this; no request needed", http.StatusConflict)
		return
	}
	if cfg.RequireSealed && !s.hasSealKey(info.Agent) {
		reject(CodeSealKeyNotRegistered, "granted values are served sealed, and this agent has no registered seal key", http.StatusBadRequest)
		return
	}
	ttl, ok := parseTTL(w, body.TTL)
	if !ok {
		return
	}
	c := s.grantCaller(info, ip)
	rq, created, err := s.grants.Create(grant.CreateInput{
		Agent: info.Agent, Paths: paths, Action: body.Action, Reason: body.Reason, TTL: ttl,
		SourceIP: ip, AuthMethod: c.AuthMethod, CredentialFP: c.CredentialFP,
	})
	if err != nil {
		s.auditRequestRejected(r, info, "access_request.create", paths, ip, string(grant.CodeOf(err)))
		writeGrantError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
		// New requests only; a duplicate of a pending one is not news.
		s.notifyAccessRequest(cfg, rq)
	}
	jsonStatus(w, status, s.requestView(rq, false))
}

// hasSealKey reports whether the agent has a registered seal key.
func (s *Server) hasSealKey(agent string) bool {
	k, err := s.acl.GetAgentSealKey(agent)
	return err == nil && k != ""
}

// handleAccessRequestList: GET /v1/access-requests[?status=&agent=].
// Approvers see every agent's requests; anyone else sees only their own.
func (s *Server) handleAccessRequestList(w http.ResponseWriter, r *http.Request) {
	info, ok := s.accessAuth(w, r, false)
	if !ok {
		return
	}
	q := r.URL.Query()
	status := grant.Status(q.Get("status"))
	switch status {
	case "", grant.StatusPending, grant.StatusApproved, grant.StatusDenied, grant.StatusExpired:
	default:
		writeAccessError(w, CodeInvalidRequest, "status must be pending, approved, denied or expired", http.StatusBadRequest)
		return
	}
	approver := s.isApprover(info)
	agent := info.Agent
	if approver {
		agent = q.Get("agent")
	} else if a := q.Get("agent"); a != "" && a != info.Agent {
		writeAccessError(w, CodeApproverRequired, "only approvers can list other agents' requests", http.StatusForbidden)
		return
	}
	items := []map[string]any{}
	for _, rq := range s.grants.ListRequests(agent, status) {
		items = append(items, s.requestView(rq, approver))
	}
	jsonOK(w, map[string]any{"requests": items})
}

// handleAccessRequestGet: GET /v1/access-requests/{id}. Agents get 404 for
// anything that is not theirs, so IDs are not an existence oracle.
func (s *Server) handleAccessRequestGet(w http.ResponseWriter, r *http.Request) {
	info, ok := s.accessAuth(w, r, false)
	if !ok {
		return
	}
	rq, found := s.grants.GetRequest(r.PathValue("id"))
	approver := s.isApprover(info)
	if !found || (!approver && rq.Agent != info.Agent) {
		writeAccessError(w, CodeNotFound, "request not found", http.StatusNotFound)
		return
	}
	jsonOK(w, s.requestView(rq, approver))
}

// handleGrantList: GET /v1/grants[?include=inactive&agent=]. Approvers see
// all grants; anyone else their own. Works while the feature is disabled.
func (s *Server) handleGrantList(w http.ResponseWriter, r *http.Request) {
	info, ok := s.accessAuth(w, r, false)
	if !ok {
		return
	}
	q := r.URL.Query()
	approver := s.isApprover(info)
	agent := info.Agent
	if approver {
		agent = q.Get("agent")
	} else if a := q.Get("agent"); a != "" && a != info.Agent {
		writeAccessError(w, CodeApproverRequired, "only approvers can list other agents' grants", http.StatusForbidden)
		return
	}
	items := []map[string]any{}
	for _, g := range s.grants.ListGrants(agent, q.Get("include") == "inactive") {
		items = append(items, s.grantView(g, approver))
	}
	jsonOK(w, map[string]any{"grants": items})
}

// handleGrantRevoke: POST /v1/grants/{id}/revoke. An approver may revoke any
// grant; an agent only its own (others look like 404). Idempotent. Works
// while the feature is disabled. A revoke that could not be saved still
// denies at once but answers 500 REVOKE_NOT_DURABLE.
func (s *Server) handleGrantRevoke(w http.ResponseWriter, r *http.Request) {
	info, ok := s.accessAuth(w, r, false)
	if !ok {
		return
	}
	g, err := s.grants.Revoke(grant.RevokeInput{
		GrantID: r.PathValue("id"), By: info.Agent, IP: clientIP(r), OwnerOnly: !s.isApprover(info),
	})
	if err != nil {
		writeGrantError(w, err)
		return
	}
	jsonOK(w, map[string]any{"grant_id": g.ID, "state": string(g.State(s.now())), "revoked_at": fmtTime(g.RevokedAt)})
}

// --- approver side -----------------------------------------------------------

type approveBody struct {
	Paths []string `json:"paths"` // nil = every requested path; [] = EMPTY_GRANT
	TTL   string   `json:"ttl"`
}

// approverAuth authenticates and requires an approver. Checked before the
// request is looked up, so non-approvers learn nothing about request IDs.
func (s *Server) approverAuth(w http.ResponseWriter, r *http.Request) (*authInfo, bool) {
	info, ok := s.accessAuth(w, r, true)
	if !ok {
		return nil, false
	}
	if !s.isApprover(info) {
		writeAccessError(w, CodeApproverRequired, "this identity is not an access-request approver", http.StatusForbidden)
		return nil, false
	}
	return info, true
}

// handleAccessRequestApprove: POST /v1/access-requests/{id}/approve with an
// optional {"paths": [subset], "ttl": "15m"}. The caller must be an API
// approver; the re-checks themselves live in approveRequest.
func (s *Server) handleAccessRequestApprove(w http.ResponseWriter, r *http.Request) {
	info, ok := s.approverAuth(w, r)
	if !ok {
		return
	}
	ip := clientIP(r)
	if !s.accessSettings().Enabled {
		writeAccessError(w, CodeRequestsDisabled, "access requests are turned off; approvals are paused", http.StatusNotImplemented)
		return
	}
	var body approveBody
	if !decodeBody(w, r, &body, true) {
		return
	}
	ttl, ok := parseTTL(w, body.TTL)
	if !ok {
		return
	}
	nr, g, err := s.approveRequest(r.PathValue("id"), info.Agent, ip, body.Paths, ttl, func(paths []string, code string) {
		s.auditRequestRejected(r, info, "access_request.approve", paths, ip, code)
	})
	if err != nil {
		var ae *ApprovalError
		if errors.As(err, &ae) {
			writeAccessError(w, ae.Code, ae.Detail, ae.Status)
			return
		}
		writeGrantError(w, err)
		return
	}
	jsonOK(w, map[string]any{
		"request_id":  nr.ID,
		"status":      string(nr.Status),
		"grant_id":    g.ID,
		"agent":       g.Agent,
		"paths":       g.Paths,
		"expires_at":  fmtTime(g.ExpiresAt),
		"sealed_only": g.SealedOnly,
	})
}

// ApprovalError is an approval refused by an API-level re-check (feature
// off, unknown request, self-approval, deny_paths, ...). Code is one of the
// denial codes in denial.go; Status is the HTTP status the API answers with.
// Grant store refusals come back as *grant.Error instead.
type ApprovalError struct {
	Code   string
	Detail string
	Status int
}

func (e *ApprovalError) Error() string { return e.Code + ": " + e.Detail }

// ErrorCode returns the denial code (lets the dashboard read it without
// importing this package).
func (e *ApprovalError) ErrorCode() string { return e.Code }

// approveRequest is the one approval path for the API and the dashboard.
// Everything is re-checked against the CURRENT config: feature on, action
// grantable, no path in deny_paths, require_sealed (and that the agent still
// has a seal key), bind_source_ip, TTL clamped to max_grant_ttl. The store
// re-checks that the agent still exists and the active-grant cap. onReject
// audits refusals (not NOT_PENDING, which is an ordinary race).
//
// It does NOT decide who may approve: the API checks the approvers list
// first, the dashboard checks its login.
func (s *Server) approveRequest(id, approver, ip string, paths []string, ttl time.Duration, onReject func(paths []string, code string)) (grant.Request, grant.Grant, error) {
	cfg := s.accessSettings()
	if s.grants == nil || !cfg.Enabled {
		return grant.Request{}, grant.Grant{}, &ApprovalError{CodeRequestsDisabled, "access requests are turned off; approvals are paused", http.StatusNotImplemented}
	}
	rq, found := s.grants.GetRequest(id)
	if !found {
		return grant.Request{}, grant.Grant{}, &ApprovalError{CodeNotFound, "request not found", http.StatusNotFound}
	}
	reject := func(code, detail string, status int) (grant.Request, grant.Grant, error) {
		onReject(rq.Paths, code)
		return grant.Request{}, grant.Grant{}, &ApprovalError{code, detail, status}
	}
	if rq.Agent == approver {
		return reject(CodeSelfApproval, "an agent cannot approve its own request", http.StatusForbidden)
	}
	if !actionGrantable(cfg, rq.Action) {
		return reject(CodeActionNotGrantable, "this action is no longer grantable", http.StatusBadRequest)
	}
	check := rq.Paths
	if paths != nil {
		check = paths
	}
	for _, p := range check {
		if pathDenied(cfg, p) {
			return reject(CodeNotRequestable, "a path in this request now matches deny_paths", http.StatusForbidden)
		}
	}
	if cfg.RequireSealed && !s.hasSealKey(rq.Agent) {
		return reject(CodeSealKeyNotRegistered, "sealed delivery is required and the agent has no registered seal key", http.StatusBadRequest)
	}
	nr, g, err := s.grants.Approve(grant.ApproveInput{
		RequestID: id, Approver: approver, ApproverIP: ip, Paths: paths, TTL: ttl,
		MaxTTL: cfg.MaxGrantTTL, SealedOnly: cfg.RequireSealed, BindSourceIP: cfg.BindSourceIP,
	})
	if err != nil {
		if grant.CodeOf(err) != grant.CodeNotPending {
			onReject(rq.Paths, string(grant.CodeOf(err)))
		}
		return grant.Request{}, grant.Grant{}, err
	}
	return nr, g, nil
}

// ApproveAccessRequestAs approves a request for an approver the caller has
// already authenticated, with the same re-checks as the API. The dashboard
// uses it with approver "dashboard@<ip>"; it is not subject to the
// access_requests.approvers list (that list is for API/CLI identities).
// Refusals are audited under the approver's name.
func (s *Server) ApproveAccessRequestAs(id, approver, ip string, paths []string, ttl time.Duration) (grant.Grant, error) {
	_, g, err := s.approveRequest(id, approver, ip, paths, ttl, func(paths []string, code string) {
		s.logAudit(s.audit.LogDenied(approver, "access_request.approve", strings.Join(paths, ","), ip, strings.ToLower(code)))
	})
	return g, err
}

// AccessRequestSettings returns the access_requests settings in force now
// (Enabled=false when the block is missing). The dashboard reads it to show
// delivery mode and the legal TTL choices.
func (s *Server) AccessRequestSettings() config.AccessRequestsSettings {
	return s.accessSettings()
}

// handleAccessRequestDeny: POST /v1/access-requests/{id}/deny with an
// optional {"note": "..."}. Works while the feature is disabled.
func (s *Server) handleAccessRequestDeny(w http.ResponseWriter, r *http.Request) {
	info, ok := s.approverAuth(w, r)
	if !ok {
		return
	}
	var body struct {
		Note string `json:"note"`
	}
	if !decodeBody(w, r, &body, true) {
		return
	}
	rq, err := s.grants.Deny(grant.DenyInput{
		RequestID: r.PathValue("id"), Denier: info.Agent, DenierIP: clientIP(r), Note: body.Note,
	})
	if err != nil {
		writeGrantError(w, err)
		return
	}
	jsonOK(w, map[string]any{"request_id": rq.ID, "status": string(rq.Status), "decided_at": fmtTime(rq.DecidedAt)})
}

// --- whoami ------------------------------------------------------------------

// handleWhoami: GET /v1/whoami. The caller's identity, its own ACL rules,
// active grants and pending requests, and the access_requests summary. A
// session caller gets its session scope and grants: [] (grants are used
// through the agent's own identity, never a session).
func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	info, err := s.authenticateInfo(r)
	if err != nil {
		handleAuthError(w, err)
		return
	}
	cfg := s.accessSettings()
	enabled := s.grantsOn()
	grantable := []string{}
	if enabled {
		grantable = cfg.GrantableActions
	}
	resp := map[string]any{
		"agent":     info.Agent,
		"source_ip": clientIP(r),
		"access_requests": map[string]any{
			"enabled":             enabled,
			"grantable_actions":   grantable,
			"sealed_required":     cfg.RequireSealed,
			"seal_key_registered": s.hasSealKey(info.Agent),
		},
	}
	if info.UsedSession {
		resp["auth_method"] = "session"
		resp["session"] = map[string]any{
			"id":           info.SessionID,
			"role":         info.SessionRole,
			"namespaces":   info.SessionNamespaces,
			"actions":      info.SessionActions,
			"elevates_acl": info.SessionElevatesACL,
		}
		resp["grants"] = []any{}
		resp["pending_requests"] = []any{}
		resp["note"] = "grants are used through the agent's own identity (bearer, mTLS or short-lived token), not a session"
		jsonOK(w, resp)
		return
	}
	resp["auth_method"] = s.bootstrapMethod(info)
	rules := []map[string]any{}
	if a, err := s.acl.GetAgent(info.Agent); err == nil {
		for _, p := range a.Permissions {
			rules = append(rules, map[string]any{"path": p.Path, "actions": p.Actions})
		}
	}
	resp["acl"] = rules
	grants := []map[string]any{}
	pending := []map[string]any{}
	if s.grants != nil {
		for _, g := range s.grants.ListGrants(info.Agent, false) {
			grants = append(grants, map[string]any{
				"id": g.ID, "paths": g.Paths, "action": g.Action,
				"expires_at": fmtTime(g.ExpiresAt), "sealed_only": g.SealedOnly,
			})
		}
		for _, rq := range s.grants.ListRequests(info.Agent, grant.StatusPending) {
			pending = append(pending, map[string]any{"id": rq.ID, "paths": rq.Paths, "expires_at": fmtTime(rq.ExpiresAt)})
		}
	}
	resp["grants"] = grants
	resp["pending_requests"] = pending
	jsonOK(w, resp)
}

// --- agent delete and status -------------------------------------------------

// deleteAgentWithGrants runs DELETE /v1/agents/{name} through the grant store:
// under its lock, durably revoke the agent's grants, expire its pending
// requests and record a tombstone, THEN remove the ACL entry. If the grant
// save fails nothing is removed (500). Writes the error response and returns
// false on failure.
func (s *Server) deleteAgentWithGrants(w http.ResponseWriter, r *http.Request, actor, target string) bool {
	if _, err := s.acl.GetAgent(target); err != nil {
		jsonError(w, "agent not found", http.StatusNotFound)
		return false
	}
	_, err := s.grants.DeleteAgent(target, actor, clientIP(r), func() error {
		return s.acl.RemoveAgent(target)
	})
	if err == nil {
		return true
	}
	var ge *grant.Error
	if errors.As(err, &ge) && ge.Code == grant.CodeDeleteACLFailed && errors.Is(ge.Err, acl.ErrAgentNotFound) {
		jsonError(w, "agent not found", http.StatusNotFound)
		return false
	}
	log.Printf("error deleting agent %q: %v", target, err)
	writeGrantError(w, err)
	return false
}

// accessStatus is the /v1/status "access_requests" section, or nil when no
// grant store is attached.
func (s *Server) accessStatus() map[string]any {
	if s.grants == nil {
		return nil
	}
	h := s.grants.Health()
	st := map[string]any{
		"enabled":       s.accessSettings().Enabled,
		"state":         "ok",
		"pending":       len(s.grants.ListRequests("", grant.StatusPending)),
		"active_grants": len(s.grants.ListGrants("", false)),
	}
	if h.Degraded {
		st["state"] = "degraded"
		st["reason"] = h.Reason
		st["writes_refused"] = h.WritesRefused
	}
	if h.QuarantinedTo != "" {
		st["quarantined_to"] = h.QuarantinedTo
	}
	return st
}

// grantAuditStatus is "degraded" while committed grant events are still
// waiting to reach the audit log (they are retried every cleanup tick).
func (s *Server) grantAuditStatus() map[string]any {
	n := s.grants.Health().AuditPending
	if n > 0 {
		return map[string]any{"state": "degraded", "pending_events": n}
	}
	return map[string]any{"state": "ok"}
}

// --- audit sink --------------------------------------------------------------

// grantAuditSink writes grant store events to the Phoenix audit log. The
// actor (approver, agent or "system") is the audit agent, the event name is
// the action, and the paths are joined into the audit path. Failed-phase
// lines are logged as denied.
type grantAuditSink struct{ l *audit.Logger }

// NewGrantAuditSink adapts the audit logger for grant.Options.Audit.
func NewGrantAuditSink(l *audit.Logger) grant.AuditSink { return grantAuditSink{l: l} }

func (g grantAuditSink) Append(e grant.Event) error {
	md := e.Metadata()
	if e.Action != "" {
		md["grant.action"] = e.Action
	}
	actor := e.Actor
	if actor == "" {
		actor = e.Agent
	}
	path := strings.Join(e.Paths, ",")
	if e.Phase == grant.PhaseFailed {
		return g.l.LogDeniedWithMetadata(actor, e.Name, path, e.ActorIP, "store_write_failed", md)
	}
	return g.l.LogAllowedWithMetadata(actor, e.Name, path, e.ActorIP, md)
}
