package dashboard

import (
	"errors"
	"net"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/grant"
)

// The facts behind a request card: what a human needs to see before deciding,
// built from server records and never from the agent's reason. The page that
// shows them is in requests.go.

// AccessApprover is the part of the API server the dashboard needs.
// *api.Server implements it.
type AccessApprover interface {
	// ApproveAccessRequestAs approves with the API's re-checks for an
	// approver the dashboard has already authenticated.
	ApproveAccessRequestAs(id, approver, ip string, how grant.Approval) (grant.Request, grant.Grant, error)
	// RemoveAlwaysAs takes back the access one request's "always" put on an
	// agent's list for one path.
	RemoveAlwaysAs(agent, path, requestID, by, ip string) error
	// RequestTokenCurrent reports whether the agent still has the token that
	// made the request.
	RequestTokenCurrent(rq grant.Request) bool
	// GrantTokenCurrent reports whether the agent still has the token the
	// grant was given to; without it the grant opens nothing.
	GrantTokenCurrent(g grant.Grant) bool
	// AccessRequestSettings is the access_requests config in force now.
	AccessRequestSettings() config.AccessRequestsSettings
}

// maxReasonDisplay caps the agent's reason on the approval card.
const maxReasonDisplay = 300

// historyWindow is how far back a card shows the agent's earlier requests.
const historyWindow = 24 * time.Hour

// pathFact is one requested path with the badges an approver must see.
type pathFact struct {
	Path           string
	Missing        bool // no secret at this path
	Hidden         bool // the agent's ACL has no "list" on it, so it cannot see the name
	AlreadyAllowed bool // the agent's ACL already allows the action
	SSHLogin       bool // not a secret: approving lets the agent log in to this machine
}

// attestFact is one hard attestation requirement from the path's policy
// rule and whether the request's credential met it when it asked.
type attestFact struct {
	Path        string
	Requirement string
	Status      string // "met", "not met" or "checked at each use"
}

// pathFacts works out the three badges for one path.
func (h *Handler) pathFacts(rq grant.Request, p string) pathFact {
	if rq.Action == grant.ActionSSHLogin {
		return pathFact{Path: p, SSHLogin: true}
	}
	f := pathFact{Path: p}
	if h.deps.Backend != nil {
		// List, not Get: no secret value is decrypted to draw a badge.
		paths, err := h.deps.Backend.List(p)
		f.Missing = err == nil && !slices.Contains(paths, p)
	}
	if h.deps.ACL != nil {
		f.Hidden = h.deps.ACL.Authorize(rq.Agent, p, acl.ActionList) != nil
		f.AlreadyAllowed = h.deps.ACL.Authorize(rq.Agent, p, acl.Action(rq.Action)) == nil
	}
	return f
}

// attestFacts lists the hard requirements of the path's attestation rule
// and whether the requesting credential met them at request time. Approval
// never waives them; the server re-checks them at every use.
func (h *Handler) attestFacts(rq grant.Request, p string, sealKeyOK bool) []attestFact {
	if h.deps.Policy == nil {
		return nil
	}
	rule, _ := h.deps.Policy.RuleFor(p)
	if rule == nil {
		return nil
	}
	var out []attestFact
	add := func(req string, met *bool) {
		st := "checked at each use"
		if met != nil {
			st = "not met"
			if *met {
				st = "met"
			}
		}
		out = append(out, attestFact{Path: p, Requirement: req, Status: st})
	}
	is := func(b bool) *bool { return &b }
	if len(rule.AllowedIPs) > 0 {
		add("source IP in "+strings.Join(rule.AllowedIPs, ", "), is(ipAllowed(rq.SourceIP, rule.AllowedIPs)))
	}
	if rule.RequireSealed {
		add("sealed delivery", is(sealKeyOK))
	}
	return out
}

// ipAllowed matches an IP against exact IPs and CIDRs, like the policy engine.
func ipAllowed(ip string, allowed []string) bool {
	parsed := net.ParseIP(ip)
	for _, a := range allowed {
		if a == ip {
			return true
		}
		if _, n, err := net.ParseCIDR(a); err == nil && parsed != nil && n.Contains(parsed) {
			return true
		}
	}
	return false
}

// ttlChoices is the legal TTL dropdown: 5m, 15m, 1h and the requested TTL,
// keeping only values >= 1m and <= requested, each capped at the current
// max_grant_ttl (the store would clamp to it anyway). Sorted, no repeats.
func ttlChoices(requested, maxTTL time.Duration) []time.Duration {
	var out []time.Duration
	for _, d := range []time.Duration{5 * time.Minute, 15 * time.Minute, time.Hour, requested} {
		if d < grant.MinGrantTTL || d > requested {
			continue
		}
		if maxTTL > 0 && d > maxTTL {
			d = maxTTL
		}
		if !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	slices.Sort(out)
	return out
}

// shortDur prints a duration without trailing zero units: 5m, 1h, 1h30m.
func shortDur(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = s[:len(s)-2]
	}
	if strings.HasSuffix(s, "h0m") {
		s = s[:len(s)-2]
	}
	return s
}

// cleanDisplayText strips control, bidi and zero-width characters and caps
// the length. html/template escapes the result; no links are ever rendered.
// The store already cleans the reason at create time; this is a second
// guard for anything that reached grants.json another way.
func cleanDisplayText(s string, maxRunes int) string {
	var b strings.Builder
	n := 0
	for _, r := range strings.ToValidUTF8(s, "") {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if n == maxRunes {
			b.WriteString("...")
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// accessEnabled reports whether the request-use pieces are wired in.
func (h *Handler) accessEnabled() bool {
	return h.deps.Grants != nil && h.deps.Access != nil
}

// pendingAccessCount is the number of pending access requests (0 when off).
func (h *Handler) pendingAccessCount() int {
	if h.deps.Grants == nil {
		return 0
	}
	return len(h.deps.Grants.ListRequests("", grant.StatusPending))
}

// accessErrorText is the fixed red message for each error code. Only codes in
// this table are shown, so a crafted link cannot put arbitrary red text on the
// page.
var accessErrorText = map[string]string{
	"REVOKE_NOT_DURABLE":      "REVOKE_NOT_DURABLE: access is off until the next restart, but the change was NOT saved. Fix the disk and do it again, or rotate the secret.",
	"REQUESTS_DISABLED":       "Access requests are turned off on this server; approvals are paused.",
	"REQUESTS_DEGRADED":       "The grants file cannot be written right now; no approvals until it is fixed. See Overview.",
	"NOT_FOUND":               "That no longer exists.",
	"NOT_PENDING":             "That request was already answered or has expired.",
	"NOT_REQUESTABLE":         "A path in this request now matches access_requests.deny_paths and cannot be granted.",
	"ACTION_NOT_GRANTABLE":    "This action is no longer grantable under the current config.",
	"SEAL_KEY_NOT_REGISTERED": "Sealed delivery is required and the agent has no registered seal key.",
	"CREDENTIAL_CHANGED":      "This agent's token was replaced after it asked, so the answer would go to the wrong token. The agent has to ask again.",
	"ALWAYS_NOT_ALLOWED":      "This request cannot be allowed always.",
	"ACL_WRITE_FAILED":        "The agent's access list could not be saved; nothing changed.",
	"EMPTY_GRANT":             "Tick at least one path to allow, or answer No.",
	"WIDENING_NOT_ALLOWED":    "An answer can only remove paths or shorten the time, never add.",
	"INVALID_TTL":             "Pick one of the listed times.",
	"INVALID_USES":            "Uses must be a whole number from 1 to 1000, or empty for any number.",
	"INVALID_REQUEST":         "The answer was not valid.",
	"GRANT_LIMIT":             "This agent already has the maximum number of active grants. Revoke one first.",
	"UNKNOWN_AGENT":           "The requesting agent no longer exists.",
	"SELF_APPROVAL":           "An agent cannot approve its own request.",
	"STORE_WRITE_FAILED":      "The answer could not be saved; nothing changed.",
	"APPROVAL_MAYBE_SAVED":    "The answer could not be confirmed as saved, and undoing it also failed: it may still take effect after a restart. Fix the disk, then check this page and revoke it if it is not wanted.",
	"AUDIT_WRITE_FAILED":      "The audit log could not be written; nothing changed.",
	"NOT_CONFIGURED":          "Access requests are not wired into this dashboard.",
}

// accessErrorMessage maps a redirect's error code to its fixed text.
func accessErrorMessage(code string) string {
	if code == "" {
		return ""
	}
	if msg, ok := accessErrorText[code]; ok {
		return msg
	}
	return "The action failed."
}

// errCode returns the denial code of an approve/deny/revoke error.
func errCode(err error) string {
	var ge *grant.Error
	if errors.As(err, &ge) && ge.MaybeSaved {
		return "APPROVAL_MAYBE_SAVED" // dashboard-only key; never "nothing changed"
	}
	if c := grant.CodeOf(err); c != "" {
		return string(c)
	}
	var coded interface{ ErrorCode() string } // *api.ApprovalError
	if errors.As(err, &coded) {
		return coded.ErrorCode()
	}
	return "FAILED"
}
