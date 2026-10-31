package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// Client side of the server's denial contract (internal/api/denial.go,
// docs/denial-codes.md). The CLI, phoenix exec and the MCP server use these
// helpers to show a denial's code and a fixed, client-authored next step.

// refDenial is one entry of /v1/resolve's error_codes map.
type refDenial struct {
	Code     string `json:"code"`
	NextStep string `json:"next_step"`
}

// nextStepHints holds the text shown for each next_step. The text is ours,
// not the server's, so a hostile or buggy server cannot inject instructions.
var nextStepHints = map[string]string{
	"request_use":    `request temporary use from a human: phoenix request <path> --reason "why you need it"`,
	"wait":           "a human decision is pending; check again shortly",
	"use_exec":       "use phoenix exec --env NAME=phoenix://<path> -- <command>; it requests and decrypts sealed values for you",
	"remint_session": "mint a new session, or one whose role covers this path and action",
	"ask_user":       "ask the user or Phoenix operator; this cannot be fixed by retrying",
	"none":           "check the reference; retrying will not help",
}

// nextStepHint returns the hint for a next_step. Unknown or missing values
// are treated as ask_user.
func nextStepHint(step string) string {
	if hint, ok := nextStepHints[step]; ok {
		return hint
	}
	return nextStepHints["ask_user"]
}

// hintPathPattern is what a path must look like to be pasted into a
// suggested command: plain path characters only, so the hint can never
// carry shell metacharacters, spaces or control characters.
var hintPathPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$`)

// hintPath returns p (without a phoenix:// prefix) when it is safe to show
// inside a suggested command, or "".
func hintPath(p string) string {
	p = strings.TrimPrefix(p, "phoenix://")
	if !hintPathPattern.MatchString(p) {
		return ""
	}
	return p
}

// denialHintForPath is denialHint with the concrete request command for
// request_use: phoenix request infra/b2/app-key --reason "...".
func denialHintForPath(code, step, path string) string {
	hint := denialHint(code, step)
	if p := hintPath(path); p != "" && hint == nextStepHints["request_use"] {
		hint = strings.Replace(hint, "<path>", p, 1)
	}
	return hint
}

// knownDenialCodes is every code in docs/denial-codes.md. A code outside this
// set gets the ask_user hint whatever next_step the server sent.
var knownDenialCodes = map[string]bool{
	"ACL_DENIED": true, "ATTESTATION_REQUIRED": true, "SEALED_REQUIRED": true,
	"SCOPE_EXCEEDED": true, "ACTION_DENIED": true, "NOT_FOUND": true,
	"INVALID_REF": true, "INTERNAL_ERROR": true,
	"SESSION_EXPIRED": true, "SESSION_INVALID": true, "SESSION_REVOKED": true,
	"SESSION_REQUIRED": true, "SEAL_KEY_MISMATCH": true, "SEAL_KEY_REQUIRED": true,
	"APPROVAL_REQUIRED": true, "STEP_UP_REAPPROVAL_REQUIRED": true,
	"ROLE_NOT_FOUND": true, "ROLE_NOT_ALLOWED": true, "BOOTSTRAP_FAILED": true,
	"ATTESTATION_FAILED": true, "ADMIN_AUTH_REQUIRED": true,
	// Request-use grants.
	"GRANT_EXPIRED": true, "GRANT_REVOKED": true, "NOT_REQUESTABLE": true,
	"SESSION_CANNOT_REQUEST": true, "REQUESTS_DISABLED": true, "REQUESTS_DEGRADED": true,
	"ALREADY_ALLOWED": true, "SEAL_KEY_NOT_REGISTERED": true, "APPROVER_REQUIRED": true,
	"INVALID_REQUEST": true, "ACTION_NOT_GRANTABLE": true, "SELF_APPROVAL": true,
	"WIDENING_NOT_ALLOWED": true, "EMPTY_GRANT": true, "NOT_PENDING": true,
	"GRANT_LIMIT": true, "TOO_MANY_PENDING": true, "RATE_LIMITED": true,
	"REQUEST_COOLDOWN": true, "UNKNOWN_AGENT": true, "AUDIT_WRITE_FAILED": true,
	"STORE_WRITE_FAILED": true, "REVOKE_NOT_DURABLE": true, "AGENT_DELETE_ACL_FAILED": true,
}

// denialHint returns the hint for a denial. The server's next_step is used
// only when both the code and the step are known; anything else (unknown,
// malformed or missing) gets the ask_user hint.
func denialHint(code, step string) string {
	if !knownDenialCodes[code] {
		return nextStepHints["ask_user"]
	}
	return nextStepHint(step)
}

// serverDenial is a structured denial body. Other fields the server sends
// (remediation, approve_command, ...) are deliberately not read: clients
// show only their own text for what to do next.
type serverDenial struct {
	Error    string `json:"error"`
	Code     string `json:"code"`
	Detail   string `json:"detail"`
	NextStep string `json:"next_step"`
}

// parseServerDenial decodes body and reports whether it is a structured
// denial (has a non-empty code). Legacy servers send no code.
func parseServerDenial(body []byte) (serverDenial, bool) {
	var d serverDenial
	if json.Unmarshal(body, &d) != nil || d.Code == "" {
		return d, false
	}
	return d, true
}

// formatDenial renders a structured denial as "[CODE] detail" plus a
// "next: <hint>" line prefixed by indent. Malformed codes are dropped and
// server text is cleaned. Used by every CLI and MCP denial formatter.
func formatDenial(d serverDenial, indent string) string {
	return formatDenialForPath(d, indent, "")
}

// formatDenialForPath is formatDenial for a known secret path, so a
// request_use hint names the exact phoenix request command.
func formatDenialForPath(d serverDenial, indent, path string) string {
	text := d.Detail
	if text == "" {
		text = d.Error
	}
	msg := cleanServerText(text)
	if code := cleanCode(d.Code); code != "" {
		msg = fmt.Sprintf("[%s] %s", code, msg)
	}
	return fmt.Sprintf("%s\n%snext: %s", msg, indent, denialHintForPath(d.Code, d.NextStep, path))
}

// approvalIDPattern matches IDs from internal/approval ("apr_" + hex).
var approvalIDPattern = regexp.MustCompile(`^apr_[0-9a-f]{1,128}$`)

// approveCommand returns "phoenix approve <id>", built locally, or "" when
// the server's approval ID does not look like one.
func approveCommand(id string) string {
	if !approvalIDPattern.MatchString(id) {
		return ""
	}
	return "phoenix approve " + id
}

// displayRef cleans a ref taken from a server response map key before it
// is printed.
func displayRef(ref string) string {
	return cleanServerText(ref)
}

// maxServerTextRunes caps server-supplied text shown to users and agents.
const maxServerTextRunes = 300

// cleanServerText makes server-supplied text safe to print: it drops control
// characters (including terminal escape sequences), Unicode format characters
// (bidi overrides, zero-width), and caps the length.
func cleanServerText(s string) string {
	return cleanTextMax(s, maxServerTextRunes)
}

// maxPathRunes matches the grant store's longest allowed path, so a path
// is never shortened: two paths that differ only near the end must look
// different when a human approves them.
const maxPathRunes = 512

// cleanPath is cleanServerText for secret paths: same character filtering,
// but no truncation below the longest valid path.
func cleanPath(s string) string {
	return cleanTextMax(s, maxPathRunes)
}

// cleanTextMax drops control and Unicode format characters and caps the
// text at max runes, adding "..." when it cuts.
func cleanTextMax(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if n == max {
			b.WriteString("...")
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// cleanCode keeps a denial code only if it looks like one (A-Z, 0-9, _).
func cleanCode(code string) string {
	if code == "" || len(code) > 64 {
		return ""
	}
	for _, r := range code {
		if !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_') {
			return ""
		}
	}
	return code
}

// formatRefError renders one failed ref from a /v1/resolve response:
// "[CODE] message (next: hint)". Servers without error_codes still get
// the legacy message.
func formatRefError(ref, msg string, codes map[string]refDenial) string {
	msg = cleanServerText(msg)
	d, ok := codes[ref]
	if !ok {
		return msg
	}
	if code := cleanCode(d.Code); code != "" {
		msg = fmt.Sprintf("[%s] %s", code, msg)
	}
	return fmt.Sprintf("%s (next: %s)", msg, denialHintForPath(d.Code, d.NextStep, ref))
}
