package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"unicode/utf8"

	"github.com/phoenixsec/phoenix/internal/policy"
	"github.com/phoenixsec/phoenix/internal/ref"
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

	// Session and step-up codes.
	"SESSION_EXPIRED":             NextRemintSession,
	"SESSION_INVALID":             NextRemintSession,
	"SESSION_REVOKED":             NextAskUser,
	"SESSION_REQUIRED":            NextNone,
	"SEAL_KEY_MISMATCH":           NextRemintSession,
	"SEAL_KEY_REQUIRED":           NextAskUser,
	"APPROVAL_REQUIRED":           NextWait,
	"STEP_UP_REAPPROVAL_REQUIRED": NextRemintSession,
	"ROLE_NOT_FOUND":              NextAskUser,
	"BOOTSTRAP_FAILED":            NextAskUser,
	"ATTESTATION_FAILED":          NextAskUser,
	"ADMIN_AUTH_REQUIRED":         NextAskUser,
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

// jsonACLDenied writes the denial for a caller whose ACL does not allow
// action on the path. It never says whether the secret exists.
func jsonACLDenied(w http.ResponseWriter, action string) {
	jsonDenied(w, "access_denied", CodeACLDenied,
		fmt.Sprintf("%s is not allowed on this path for your identity", action),
		"ask the Phoenix operator to grant access",
		http.StatusForbidden)
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
			"use phoenix exec, which requests and decrypts sealed values for you",
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

// denyResolveAttestation handles request-level attestation failures in
// /v1/resolve (nonce, timestamp skew, client certificate, signature). These
// happen before any ref is checked and need no access to any path, so they
// write a single audit entry (the first ref's path, plus "resolve.refs" with
// the ref count) rather than one per ref, which a caller could inflate.
// The caller gets one generic ATTESTATION_REQUIRED denial.
func (s *Server) denyResolveAttestation(w http.ResponseWriter, r *http.Request, info *authInfo, ip string, refs []string, detail string) {
	path := ""
	if len(refs) > 0 {
		path = refs[0]
		if p, err := ref.Parse(refs[0]); err == nil {
			path = p
		}
	}
	metadata := denialAuditMetadata(r, detail)
	metadata["resolve.refs"] = strconv.Itoa(len(refs))
	s.auditDeniedMetadata(info, "resolve", path, ip, "attestation", metadata)
	writeAttestationRequired(w)
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
// caller-controlled text (for example the X-Phoenix-Tool header), and
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

// writeSessionAttestationFailed writes the generic ATTESTATION_FAILED denial
// for session mint and renew. The failed requirement goes to the audit log
// (denial.detail), not to the caller.
func writeSessionAttestationFailed(w http.ResponseWriter) {
	jsonDenied(w, "access_denied", "ATTESTATION_FAILED",
		"the request did not meet this role's attestation requirements",
		"ask the Phoenix operator which attestation this role requires",
		http.StatusForbidden)
}
