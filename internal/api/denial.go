package api

import (
	"errors"
	"fmt"
	"net/http"
	"unicode/utf8"

	"github.com/phoenixsec/phoenix/internal/grant"
	"github.com/phoenixsec/phoenix/internal/policy"
)

// Denial contract shared by every access denial the API returns.
//
// Each denial carries a stable `code` and a `next_step` from the closed sets
// below, so CLI, MCP and plugins can tell an agent what to do next without
// parsing free text. The public list lives in docs/denial-codes.md; keep the
// two in sync. Clients treat any code or next_step they do not know as
// NextAskUser.

// Next steps an agent may be told to take after a denial.
const (
	NextRequestUse    = "request_use"    // ask Phoenix for temporary use (request-use grants)
	NextWait          = "wait"           // a human decision is pending; poll again
	NextUseExec       = "use_exec"       // use the value through phoenix exec, not plaintext
	NextRemintSession = "remint_session" // mint a new session (or one with a different role)
	NextAskUser       = "ask_user"       // only a human can fix this
	NextNone          = "none"           // not an access problem; retrying or asking will not help
)

// Codes for data-access denials (get, set, delete, resolve).
const (
	CodeACLDenied           = "ACL_DENIED"
	CodeAttestationRequired = "ATTESTATION_REQUIRED"
	CodeSealedRequired      = "SEALED_REQUIRED"
	CodeScopeExceeded       = "SCOPE_EXCEEDED"
	CodeActionDenied        = "ACTION_DENIED"
	CodeNotFound            = "NOT_FOUND"
	CodeInvalidRef          = "INVALID_REF"
	CodeInternalError       = "INTERNAL_ERROR"
	CodeGrantExpired        = "GRANT_EXPIRED"
	CodeGrantRevoked        = "GRANT_REVOKED"
	CodeSSHGrantRequired    = "SSH_GRANT_REQUIRED"
)

// Codes for the request-use API (access.go). Store errors use the
// grant.Code strings, which are listed here too so every code the server
// can emit has a documented next step.
const (
	CodeNotRequestable       = "NOT_REQUESTABLE"
	CodeSessionCannotRequest = "SESSION_CANNOT_REQUEST"
	CodeRequestsDisabled     = "REQUESTS_DISABLED"
	CodeRequestsDegraded     = "REQUESTS_DEGRADED"
	CodeAlreadyAllowed       = "ALREADY_ALLOWED"
	CodeSealKeyNotRegistered = "SEAL_KEY_NOT_REGISTERED"
	CodeApproverRequired     = "APPROVER_REQUIRED"
	CodeInvalidRequest       = "INVALID_REQUEST"
	CodeActionNotGrantable   = "ACTION_NOT_GRANTABLE"
	CodeSelfApproval         = "SELF_APPROVAL"
	CodeWideningNotAllowed   = "WIDENING_NOT_ALLOWED"
	CodeEmptyGrant           = "EMPTY_GRANT"
	CodeNotPending           = "NOT_PENDING"
	CodeGrantLimit           = "GRANT_LIMIT"
	CodeTooManyPending       = "TOO_MANY_PENDING"
	CodeRateLimited          = "RATE_LIMITED"
	CodeRequestCooldown      = "REQUEST_COOLDOWN"
	CodeUnknownAgent         = "UNKNOWN_AGENT"
	CodeAuditWriteFailed     = "AUDIT_WRITE_FAILED"
	CodeStoreWriteFailed     = "STORE_WRITE_FAILED"
	CodeRevokeNotDurable     = "REVOKE_NOT_DURABLE"
	CodeAgentDeleteACLFailed = "AGENT_DELETE_ACL_FAILED"
)

// denialNextStep maps every code the server emits to its next step.
// Codes missing from this map fall back to NextAskUser.
var denialNextStep = map[string]string{
	CodeACLDenied:           NextAskUser,
	CodeAttestationRequired: NextAskUser,
	CodeSealedRequired:      NextUseExec,
	CodeScopeExceeded:       NextRemintSession,
	CodeActionDenied:        NextRemintSession,
	CodeNotFound:            NextNone,
	CodeInvalidRef:          NextNone,
	CodeInternalError:       NextAskUser,
	// GRANT_EXPIRED and SESSION_CANNOT_REQUEST are upgraded to request_use
	// by denialNextStep / sessionRequestStep when the path is requestable.
	// request_use is never static: it depends on the current settings.
	CodeGrantExpired: NextAskUser,
	CodeGrantRevoked: NextAskUser,
	// The sign endpoint upgrades this to request_use itself: see denySSHSign.
	CodeSSHGrantRequired: NextAskUser,

	// Request-use API codes.
	CodeNotRequestable:       NextAskUser,
	CodeSessionCannotRequest: NextAskUser,
	CodeRequestsDisabled:     NextAskUser,
	CodeRequestsDegraded:     NextAskUser,
	CodeAlreadyAllowed:       NextNone,
	CodeSealKeyNotRegistered: NextAskUser,
	CodeApproverRequired:     NextAskUser,
	CodeInvalidRequest:       NextNone,
	CodeActionNotGrantable:   NextAskUser,
	CodeSelfApproval:         NextAskUser,
	CodeWideningNotAllowed:   NextNone,
	CodeEmptyGrant:           NextNone,
	CodeNotPending:           NextNone,
	CodeGrantLimit:           NextAskUser,
	CodeTooManyPending:       NextWait,
	CodeRateLimited:          NextAskUser,
	CodeRequestCooldown:      NextAskUser,
	CodeUnknownAgent:         NextAskUser,
	CodeAuditWriteFailed:     NextAskUser,
	CodeStoreWriteFailed:     NextAskUser,
	CodeRevokeNotDurable:     NextAskUser,
	CodeAgentDeleteACLFailed: NextAskUser,

	// Session codes.
	"SESSION_EXPIRED":     NextRemintSession,
	"SESSION_INVALID":     NextRemintSession,
	"SESSION_REVOKED":     NextAskUser,
	"SESSION_REQUIRED":    NextNone,
	"SEAL_KEY_MISMATCH":   NextRemintSession,
	"SEAL_KEY_REQUIRED":   NextAskUser,
	"ROLE_NOT_FOUND":      NextAskUser,
	"BOOTSTRAP_FAILED":    NextAskUser,
	"ADMIN_AUTH_REQUIRED": NextAskUser,
}

// nextStepFor returns the next step for a denial code.
func nextStepFor(code string) string {
	if step, ok := denialNextStep[code]; ok {
		return step
	}
	return NextAskUser
}

// refDenial is one entry in /v1/resolve's error_codes map: the per-ref
// counterpart of a jsonDenied body.
type refDenial struct {
	Code     string `json:"code"`
	NextStep string `json:"next_step"`
}

func newRefDenial(code string) refDenial {
	return refDenial{Code: code, NextStep: nextStepFor(code)}
}

// denialNextStep is nextStepFor plus the request_use rule (plan section 10):
// request_use is only advertised when the feature is on, the action is
// grantable and the path is not in deny_paths. ACL_DENIED, GRANT_EXPIRED and
// the session scope/action denials on a requestable path say request_use
// (the request and the use then go through the agent's own identity).
func (s *Server) denialNextStep(code, path, action string) string {
	switch code {
	case CodeACLDenied, CodeGrantExpired, CodeScopeExceeded, CodeActionDenied:
		if s.requestable(path, action) {
			return NextRequestUse
		}
	}
	return nextStepFor(code)
}

// writeDataDenial audits and writes the denial for a get/set/delete whose
// dataAccess reason is non-empty. The session audit entries are exactly the
// ones the handlers wrote before grants existed.
func (s *Server) writeDataDenial(w http.ResponseWriter, r *http.Request, info *authInfo, action, path, ip, reason string) {
	switch reason {
	case "session_scope":
		s.auditLogSessionDenied(r, info.Agent, "scope_check", path, ip, "session_scope", info.SessionID)
		jsonDeniedStep(w, "access_denied", CodeScopeExceeded,
			fmt.Sprintf("path %q is outside session scope for role %q", path, info.SessionRole),
			"request a session with a role that includes this namespace",
			s.denialNextStep(CodeScopeExceeded, path, action), http.StatusForbidden)
	case "session_action":
		s.auditLogSessionDenied(r, info.Agent, action, path, ip, "session_action", info.SessionID)
		jsonDeniedStep(w, "access_denied", CodeActionDenied,
			fmt.Sprintf("action %q is not permitted by session role %q", action, info.SessionRole),
			"request a session with a role that includes this action",
			s.denialNextStep(CodeActionDenied, path, action), http.StatusForbidden)
	case grant.ReasonGrantExpired:
		s.auditDenied(r, info, action, path, ip, reason)
		jsonDeniedStep(w, "access_denied", CodeGrantExpired,
			"your temporary grant for this path has ended",
			"request temporary use again if it is still needed",
			s.denialNextStep(CodeGrantExpired, path, action), http.StatusForbidden)
	case grant.ReasonGrantRevoked:
		s.auditDenied(r, info, action, path, ip, reason)
		jsonDeniedStep(w, "access_denied", CodeGrantRevoked,
			"a human revoked your temporary grant for this path",
			"ask the user before requesting again",
			NextAskUser, http.StatusForbidden)
	default:
		s.auditDenied(r, info, action, path, ip, "acl")
		s.writeACLDenied(w, action, path)
	}
}

// resolveDenial maps a dataAccess reason to the per-ref code and the legacy
// errors-map message used by /v1/resolve.
func resolveDenial(reason string) (code, msg string) {
	switch reason {
	case "session_scope":
		return CodeScopeExceeded, "path outside session scope"
	case "session_action":
		return CodeActionDenied, "action read_value not permitted by session role"
	case grant.ReasonGrantExpired:
		return CodeGrantExpired, "access denied: temporary grant has ended"
	case grant.ReasonGrantRevoked:
		return CodeGrantRevoked, "access denied: temporary grant was revoked"
	}
	return CodeACLDenied, "access denied: read_value permission required"
}

// writeACLDenied writes the denial for a caller whose ACL does not allow
// action on the path. It never says whether the secret exists. The next
// step is request_use only when the path is requestable.
func (s *Server) writeACLDenied(w http.ResponseWriter, action, path string) {
	step := s.denialNextStep(CodeACLDenied, path, action)
	remediation := "ask the Phoenix operator to grant access"
	if step == NextRequestUse {
		remediation = "request temporary use: POST /v1/access-requests (agent's own identity, not a session)"
	}
	jsonDeniedStep(w, "access_denied", CodeACLDenied,
		fmt.Sprintf("%s is not allowed on this path for your identity", action),
		remediation, step, http.StatusForbidden)
}

// attestationDenialCode picks the code for an attestFull error:
// SEALED_REQUIRED when only sealed delivery was missing, else ATTESTATION_REQUIRED.
func attestationDenialCode(err error) string {
	var de *policy.DeniedError
	if errors.As(err, &de) && de.SealedRequired {
		return CodeSealedRequired
	}
	return CodeAttestationRequired
}

// denyAttestation audits and writes the denial for a request that did not
// meet the path's attestation policy. The policy error goes only to the audit
// log (metadata "denial.detail"), so the response does not reveal policy rules.
// The audit reason stays "attestation" for existing audit filters.
func (s *Server) denyAttestation(w http.ResponseWriter, r *http.Request, info *authInfo, action, path, ip string, err error) {
	s.auditDeniedDetail(r, info, action, path, ip, "attestation", err.Error())
	if attestationDenialCode(err) == CodeSealedRequired {
		jsonDenied(w, "access_denied", CodeSealedRequired,
			"this path is only served sealed to your registered seal key",
			"use phoenix exec --redact-output, which requests and decrypts sealed values for you and hides them in the output",
			http.StatusForbidden)
		return
	}
	writeAttestationRequired(w)
}

// writeAttestationRequired writes the generic ATTESTATION_REQUIRED denial.
// It never says which requirement failed; that goes to the audit log.
func writeAttestationRequired(w http.ResponseWriter) {
	jsonDenied(w, "access_denied", CodeAttestationRequired,
		"this path requires attestation that the request did not meet",
		"ask the Phoenix operator which attestation this path requires",
		http.StatusForbidden)
}

// auditDeniedDetail is auditDenied plus a "denial.detail" metadata entry for
// detail that must reach the audit log but not the caller.
func (s *Server) auditDeniedDetail(r *http.Request, info *authInfo, action, path, ip, reason, detail string) {
	s.auditDeniedMetadata(info, action, path, ip, reason, denialAuditMetadata(r, detail))
}

// auditDeniedMetadata writes a denied audit entry with the given metadata,
// as a session entry when the caller used a session token.
func (s *Server) auditDeniedMetadata(info *authInfo, action, path, ip, reason string, metadata map[string]string) {
	agent := ""
	if info != nil {
		agent = info.Agent
	}
	if info != nil && info.UsedSession {
		s.logAudit(s.audit.LogSessionDeniedWithMetadata(agent, action, path, ip, reason, info.SessionID, metadata))
		return
	}
	s.logAudit(s.audit.LogDeniedWithMetadata(agent, action, path, ip, reason, metadata))
}

// denialAuditMetadata returns the request's caller audit metadata plus
// "denial.detail", capped by capDenialDetail.
func denialAuditMetadata(r *http.Request, detail string) map[string]string {
	metadata := callerAuditMetadata(r)
	if metadata == nil {
		metadata = make(map[string]string, 1)
	}
	metadata["denial.detail"] = capDenialDetail(detail)
	return metadata
}

// maxDenialDetailBytes caps the stored denial.detail. The detail can embed
// caller-controlled text (for example a source IP or role name), and
// /v1/resolve logs it once per ref, so it must stay small.
const maxDenialDetailBytes = 512

// denialDetailTruncated marks a denial.detail that was cut by capDenialDetail.
const denialDetailTruncated = "...(truncated)"

// capDenialDetail limits s to maxDenialDetailBytes, including the marker,
// without splitting a UTF-8 character.
func capDenialDetail(s string) string {
	if len(s) <= maxDenialDetailBytes {
		return s
	}
	cut := maxDenialDetailBytes - len(denialDetailTruncated)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + denialDetailTruncated
}
