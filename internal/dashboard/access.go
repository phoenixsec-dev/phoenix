package dashboard

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/grant"
)

// Request-use grants on the dashboard (plan sections 11 and 12).
//
// The approvals page shows one card per pending access request with every
// fact a human needs to decide, built from server records (never from the
// agent's reason). Approve goes through the API server's shared approval
// path (AccessApprover), so the dashboard and the API apply the exact same
// re-checks. Deny and revoke call the grant store directly, as the API does.
// Every decision is recorded as "dashboard@<ip>".

// AccessApprover is the part of the API server the dashboard needs.
// *api.Server implements it.
type AccessApprover interface {
	// ApproveAccessRequestAs approves with the API's re-checks for an
	// approver the dashboard has already authenticated.
	ApproveAccessRequestAs(id, approver, ip string, paths []string, ttl time.Duration) (grant.Grant, error)
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

// ttlChoice is one entry of the TTL dropdown.
type ttlChoice struct {
	Value    string
	Selected bool
}

// historyItem is one of the agent's other requests in the last 24h.
type historyItem struct {
	ID     string
	Status string
	Paths  string
	When   time.Time
}

// accessCard is everything one approval card shows.
type accessCard struct {
	ID            string
	Agent         string
	SourceIP      string
	AuthMethod    string
	Action        string
	Paths         []pathFact
	RequestedTTL  string
	TTLChoices    []ttlChoice
	Delivery      string
	SealKeyOK     bool
	SealRequired  bool
	Attestation   []attestFact
	Reason        string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	History       []historyItem
	HistoryDenied int
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

// accessCards builds the approval cards for every pending request, oldest first.
func (h *Handler) accessCards() []accessCard {
	if !h.accessEnabled() {
		return nil
	}
	cfg := h.deps.Access.AccessRequestSettings()
	var cards []accessCard
	for _, rq := range h.deps.Grants.ListRequests("", grant.StatusPending) {
		cards = append(cards, h.buildCard(rq, cfg))
	}
	return cards
}

// buildCard collects the facts for one request (plan section 11, "What the
// approver must see").
func (h *Handler) buildCard(rq grant.Request, cfg config.AccessRequestsSettings) accessCard {
	c := accessCard{
		ID:           rq.ID,
		Agent:        rq.Agent,
		SourceIP:     rq.SourceIP,
		AuthMethod:   rq.AuthMethod,
		Action:       rq.Action,
		RequestedTTL: shortDur(rq.RequestedTTL),
		Reason:       cleanDisplayText(rq.Reason, maxReasonDisplay),
		CreatedAt:    rq.CreatedAt,
		ExpiresAt:    rq.ExpiresAt,
		SealRequired: cfg.RequireSealed,
	}
	if h.deps.ACL != nil {
		k, err := h.deps.ACL.GetAgentSealKey(rq.Agent)
		c.SealKeyOK = err == nil && k != ""
	}
	if cfg.RequireSealed {
		c.Delivery = "sealed only, to the agent's registered seal key (used through phoenix exec)"
	} else {
		c.Delivery = "plaintext or sealed, as the agent asks"
	}
	sshLogin := rq.Action == grant.ActionSSHLogin
	if sshLogin {
		c.SealRequired = false
		c.Delivery = "a login certificate that ends with this approval, usable only from the IP above"
	}
	for _, p := range rq.Paths {
		c.Paths = append(c.Paths, h.pathFacts(rq, p))
		// Attestation rules guard secrets. Signing a login does not check them,
		// so the card must not say it does.
		if !sshLogin {
			c.Attestation = append(c.Attestation, h.attestFacts(rq, p, c.SealKeyOK)...)
		}
	}
	choices := ttlChoices(rq.RequestedTTL, cfg.MaxGrantTTL)
	for i, d := range choices {
		// Default to the longest legal choice: what the agent asked for,
		// unless the current max_grant_ttl is lower.
		c.TTLChoices = append(c.TTLChoices, ttlChoice{Value: shortDur(d), Selected: i == len(choices)-1})
	}
	since := time.Now().Add(-historyWindow)
	for _, other := range h.deps.Grants.ListRequests(rq.Agent, "") {
		if other.ID == rq.ID || other.CreatedAt.Before(since) {
			continue
		}
		if other.Status == grant.StatusDenied {
			c.HistoryDenied++
		}
		c.History = append(c.History, historyItem{
			ID: other.ID, Status: string(other.Status), Paths: strings.Join(other.Paths, ", "), When: other.CreatedAt,
		})
	}
	return c
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

// --- handlers ----------------------------------------------------------------

// accessErrorText is the fixed red message for each error code the access
// handlers redirect with. Only codes in this table are shown, so a crafted
// link cannot put arbitrary red text on the approvals page.
var accessErrorText = map[string]string{
	"REVOKE_NOT_DURABLE":      "REVOKE_NOT_DURABLE: the grant is revoked until the next restart but the change was NOT saved. Fix the disk and retry the revoke, or rotate the secret.",
	"REQUESTS_DISABLED":       "Access requests are turned off on this server; approvals are paused.",
	"REQUESTS_DEGRADED":       "The grants file cannot be written right now; no approvals until it is fixed. See Overview.",
	"NOT_FOUND":               "That request or grant no longer exists.",
	"NOT_PENDING":             "That request was already decided or has expired.",
	"NOT_REQUESTABLE":         "A path in this request now matches access_requests.deny_paths and cannot be granted.",
	"ACTION_NOT_GRANTABLE":    "This action is no longer grantable under the current config.",
	"SEAL_KEY_NOT_REGISTERED": "Sealed delivery is required and the agent has no registered seal key.",
	"EMPTY_GRANT":             "Tick at least one path to approve, or deny the request.",
	"WIDENING_NOT_ALLOWED":    "An approval can only remove paths or shorten the time, never add.",
	"INVALID_TTL":             "Pick one of the listed durations.",
	"INVALID_REQUEST":         "The approval was not valid.",
	"GRANT_LIMIT":             "This agent already has the maximum number of active grants. Revoke one first.",
	"UNKNOWN_AGENT":           "The requesting agent no longer exists.",
	"SELF_APPROVAL":           "An agent cannot approve its own request.",
	"STORE_WRITE_FAILED":      "The decision could not be saved; nothing changed.",
	"APPROVAL_MAYBE_SAVED":    "The approval could not be confirmed as saved, and undoing it also failed: it may still take effect after a restart. Fix the disk, then check Grants and revoke it if it is not wanted.",
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

// redirectAccess sends the browser back to page with either a success flash
// or an error code (shown through accessErrorText).
func redirectAccess(w http.ResponseWriter, r *http.Request, page, flash, errorCode string) {
	q := url.Values{}
	if flash != "" {
		q.Set("flash", flash)
	}
	if errorCode != "" {
		q.Set("error", errorCode)
	}
	http.Redirect(w, r, page+"?"+q.Encode(), http.StatusSeeOther)
}

// handleAccessApprove: POST /dashboard/access-requests/{id}/approve.
// Form: path (repeated; the ticked boxes) and ttl (one of the dropdown
// choices). The TTL must be one of the legal choices for this request.
func (h *Handler) handleAccessApprove(w http.ResponseWriter, r *http.Request) {
	const page = "/dashboard/approvals"
	if !h.accessEnabled() {
		redirectAccess(w, r, page, "", "NOT_CONFIGURED")
		return
	}
	id := r.PathValue("id")
	rq, ok := h.deps.Grants.GetRequest(id)
	if !ok {
		redirectAccess(w, r, page, "", "NOT_FOUND")
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectAccess(w, r, page, "", "INVALID_REQUEST")
		return
	}
	paths := r.PostForm["path"]
	if len(paths) == 0 {
		redirectAccess(w, r, page, "", "EMPTY_GRANT")
		return
	}
	ttl, err := time.ParseDuration(r.PostFormValue("ttl"))
	if err != nil || !slices.Contains(ttlChoices(rq.RequestedTTL, h.deps.Access.AccessRequestSettings().MaxGrantTTL), ttl) {
		redirectAccess(w, r, page, "", "INVALID_TTL")
		return
	}
	ip := extractClientIP(r)
	g, err := h.deps.Access.ApproveAccessRequestAs(id, "dashboard@"+ip, ip, paths, ttl)
	if err != nil {
		log.Printf("dashboard: approve %s: %v", id, err)
		redirectAccess(w, r, page, "", errCode(err))
		return
	}
	redirectAccess(w, r, page, fmt.Sprintf("approved %s: %s for %s (grant %s)",
		id, strings.Join(g.Paths, ", "), shortDur(g.ExpiresAt.Sub(g.CreatedAt)), g.ID), "")
}

// handleAccessDeny: POST /dashboard/access-requests/{id}/deny with an
// optional note (cleaned and capped by the store).
func (h *Handler) handleAccessDeny(w http.ResponseWriter, r *http.Request) {
	const page = "/dashboard/approvals"
	if h.deps.Grants == nil {
		redirectAccess(w, r, page, "", "NOT_CONFIGURED")
		return
	}
	id := r.PathValue("id")
	ip := extractClientIP(r)
	if _, err := h.deps.Grants.Deny(grant.DenyInput{
		RequestID: id, Denier: "dashboard@" + ip, DenierIP: ip, Note: r.FormValue("note"),
	}); err != nil {
		log.Printf("dashboard: deny %s: %v", id, err)
		redirectAccess(w, r, page, "", errCode(err))
		return
	}
	redirectAccess(w, r, page, "denied "+id, "")
}

// grantRow is one line of the grants page.
type grantRow struct {
	grant.Grant
	State string
	Ended time.Time
}

// handleGrants: GET /dashboard/grants[?view=recent]. Active grants with a
// Revoke button, or the recently expired/revoked ones.
func (h *Handler) handleGrants(w http.ResponseWriter, r *http.Request) {
	view := r.URL.Query().Get("view")
	if view != "recent" {
		view = "active"
	}
	var rows []grantRow
	if h.deps.Grants != nil {
		now := time.Now()
		for _, g := range h.deps.Grants.ListGrants("", view == "recent") {
			st := g.State(now)
			if view == "recent" && st == grant.GrantActive {
				continue
			}
			row := grantRow{Grant: g, State: string(st), Ended: g.ExpiresAt}
			if !g.RevokedAt.IsZero() && g.RevokedAt.Before(g.ExpiresAt) {
				row.Ended = g.RevokedAt
			}
			rows = append(rows, row)
		}
	}
	if view == "recent" {
		sort.Slice(rows, func(i, j int) bool { return rows[i].Ended.After(rows[j].Ended) })
	}
	h.render(w, "grants.html", map[string]interface{}{
		"CSRF":       r.Header.Get("X-Csrf-Token"),
		"Active":     "grants",
		"View":       view,
		"Grants":     rows,
		"Configured": h.deps.Grants != nil,
		"Flash":      r.URL.Query().Get("flash"),
		"Error":      accessErrorMessage(r.URL.Query().Get("error")),
	})
}

// handleGrantRevoke: POST /dashboard/grants/{id}/revoke. A revoke that could
// not be saved still denies at once, but the page says so in red
// (REVOKE_NOT_DURABLE) instead of reporting success.
func (h *Handler) handleGrantRevoke(w http.ResponseWriter, r *http.Request) {
	const page = "/dashboard/grants"
	if h.deps.Grants == nil {
		redirectAccess(w, r, page, "", "NOT_CONFIGURED")
		return
	}
	id := r.PathValue("id")
	ip := extractClientIP(r)
	if _, err := h.deps.Grants.Revoke(grant.RevokeInput{GrantID: id, By: "dashboard@" + ip, IP: ip}); err != nil {
		log.Printf("dashboard: revoke %s: %v", id, err)
		redirectAccess(w, r, page, "", errCode(err))
		return
	}
	redirectAccess(w, r, page, "revoked "+id, "")
}
