package dashboard

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/grant"
)

// The Requests page: what agents are asking for, what is open now, what is on
// "always", and what happened before.
//
// It is live. requests.js asks for /dashboard/requests/feed every two seconds
// from every dashboard page: new requests become cards in the list, or a popup
// on any other page. Plain short requests were chosen over a held-open stream
// because they need nothing from a reverse proxy and recover by themselves
// after a lost connection. Cards are rendered here, by one template, so the
// first page load, the live list and the popup cannot differ. Nothing on the
// page depends on the script except being live.

const requestsPage = "/dashboard/requests"

// quickTTL is the "15 minutes" button. Less when the agent asked for less, or
// the server allows less.
const quickTTL = 15 * time.Minute

const (
	maxHistoryRows = 50
	maxExpiredRows = 20
	// endedWindow is how long the feed reports how a request ended, so a card
	// still on someone's screen can say so.
	endedWindow = time.Hour
)

// requestRoutes adds the page and its actions.
func (h *Handler) requestRoutes() {
	h.mux.HandleFunc("GET /dashboard/requests", h.fromOtherSite(h.requireAuth(h.handleRequests)))
	h.mux.HandleFunc("GET /dashboard/requests/{id}", h.fromOtherSite(h.requireAuth(h.handleRequests)))
	h.mux.HandleFunc("GET /dashboard/requests/feed", h.handleRequestFeed)
	h.mux.HandleFunc("POST /dashboard/requests/{id}/answer", h.requireAuth(h.handleAnswer))
	h.mux.HandleFunc("POST /dashboard/requests/grants/{id}/revoke", h.requireAuth(h.handleGrantRevoke))
	h.mux.HandleFunc("POST /dashboard/requests/always/remove", h.requireAuth(h.handleAlwaysRemove))
	// Addresses from before Approvals and Grants became one page. A fragment
	// (#req_...) survives the redirect and requests.js follows it.
	h.mux.Handle("GET /dashboard/approvals", http.RedirectHandler(requestsPage, http.StatusFound))
	h.mux.Handle("GET /dashboard/grants", http.RedirectHandler(requestsPage+"#active", http.StatusFound))
}

// --- what the page shows -----------------------------------------------------

// requestCard is one waiting request with everything needed to answer it.
type requestCard struct {
	ID         string
	CSRF       string
	Agent      string
	SourceIP   string
	AuthMethod string
	Question   string // "May courier use infra/b2/app-key?"
	Machine    string // the machine of an SSH login, else ""
	Reason     string
	Paths      []pathFact
	ExpiresAt  time.Time
	QuickLabel string // "15 minutes"
	OnceWithin string // how long a single use stays open
	AlwaysOK   bool
	TTLs       []string // choices under "Other limits"; the last is the default
	Problems   []string // why a yes would fail right now
	Delivery   string
	Attest     []attestFact
	RecentAsks int // this agent's other requests in the last 24h
	RecentNos  int
}

// activeRow is one open grant.
type activeRow struct {
	ID        string
	CSRF      string
	Agent     string
	What      string
	Uses      string
	ExpiresAt time.Time
	LastUsed  time.Time
	By        string
	Revoked   bool // revoked, but possibly not saved yet
}

// alwaysRow is one path on an agent's access list because of an "always".
type alwaysRow struct {
	acl.AlwaysRule
	CSRF string
}

// pastRow is one answered or expired request.
type pastRow struct {
	ID      string
	Agent   string
	What    string
	Outcome string
	Badge   string // CSS state: approved, denied, expired, revoked
	When    time.Time
	Note    string
}

// requestsView is the whole page below the title.
type requestsView struct {
	Active  []activeRow
	Always  []alwaysRow
	Expired []pastRow
	History []pastRow
}

// waitingCards builds the cards for every pending request, oldest first.
func (h *Handler) waitingCards(csrf string) []requestCard {
	if !h.accessEnabled() {
		return nil
	}
	var cards []requestCard
	for _, rq := range h.deps.Grants.ListRequests("", grant.StatusPending) {
		cards = append(cards, h.card(rq, csrf))
	}
	return cards
}

// card collects the facts for one request.
func (h *Handler) card(rq grant.Request, csrf string) requestCard {
	cfg := h.deps.Access.AccessRequestSettings()
	sshLogin := rq.Action == grant.ActionSSHLogin
	c := requestCard{
		ID: rq.ID, CSRF: csrf, Agent: rq.Agent, SourceIP: rq.SourceIP, AuthMethod: rq.AuthMethod,
		Reason: cleanDisplayText(rq.Reason, maxReasonDisplay), ExpiresAt: rq.ExpiresAt,
		AlwaysOK: rq.Action == grant.ActionReadValue,
	}
	switch {
	case sshLogin:
		c.Machine = strings.TrimPrefix(rq.Paths[0], "ssh/")
		c.Question = fmt.Sprintf("May %s have a root login on %s?", rq.Agent, c.Machine)
	case len(rq.Paths) == 1:
		c.Question = fmt.Sprintf("May %s use %s?", rq.Agent, rq.Paths[0])
	default:
		c.Question = fmt.Sprintf("May %s use %d secrets?", rq.Agent, len(rq.Paths))
	}
	choices := ttlChoices(rq.RequestedTTL, cfg.MaxGrantTTL)
	for _, d := range choices {
		c.TTLs = append(c.TTLs, shortDur(d))
	}
	if len(choices) > 0 {
		c.OnceWithin = longDur(choices[len(choices)-1])
	}
	c.QuickLabel = longDur(quickLimit(rq, cfg.MaxGrantTTL))

	sealKeyOK := true
	if h.deps.ACL != nil {
		k, err := h.deps.ACL.GetAgentSealKey(rq.Agent)
		sealKeyOK = err == nil && k != ""
		switch _, err := h.deps.ACL.GetAgent(rq.Agent); {
		case err != nil:
			c.Problems = append(c.Problems, "This agent no longer exists.")
		case !h.deps.Access.RequestTokenCurrent(rq):
			c.Problems = append(c.Problems, "This agent's token was replaced after it asked. It has to ask again.")
		}
	}
	if cfg.RequireSealed && !sealKeyOK && !sshLogin {
		c.Problems = append(c.Problems, "The agent has no registered seal key, and this server only hands out sealed values.")
	}
	if !cfg.Enabled {
		c.Problems = append(c.Problems, "Access requests are turned off on this server.")
	}
	switch {
	case sshLogin:
		c.Delivery = "Works from " + rq.SourceIP + " only. Revoking it here also ends logins that are still open."
	case cfg.RequireSealed:
		c.Delivery = "Once and timed answers hand the value over sealed, for phoenix exec."
	}
	for _, p := range rq.Paths {
		c.Paths = append(c.Paths, h.pathFacts(rq, p))
		// Attestation rules guard secrets. Signing a login does not check them,
		// so the card must not say it does.
		if !sshLogin {
			c.Attest = append(c.Attest, h.attestFacts(rq, p, sealKeyOK)...)
		}
	}
	// Counted from when this request was made, so the card does not change
	// under someone reading it.
	for _, other := range h.deps.Grants.ListRequests(rq.Agent, "") {
		if other.ID == rq.ID || other.CreatedAt.Before(rq.CreatedAt.Add(-historyWindow)) || other.CreatedAt.After(rq.CreatedAt) {
			continue
		}
		c.RecentAsks++
		if other.Status == grant.StatusDenied {
			c.RecentNos++
		}
	}
	return c
}

// quickLimit is how long the "15 minutes" button gives this request.
func quickLimit(rq grant.Request, maxTTL time.Duration) time.Duration {
	d := min(quickTTL, rq.RequestedTTL)
	if maxTTL > 0 {
		d = min(d, maxTTL)
	}
	return d
}

// requestsView collects everything below the waiting cards.
func (h *Handler) requestsView(csrf string) requestsView {
	var v requestsView
	if h.deps.ACL != nil {
		for _, r := range h.deps.ACL.ListAlways() {
			v.Always = append(v.Always, alwaysRow{r, csrf})
		}
	}
	if h.deps.Grants == nil {
		return v
	}
	now := time.Now()
	// While the grants file cannot be saved, a revoke may not be on disk yet.
	// Keep those here with a Revoke that tries the save again.
	unsaved := h.deps.Grants.Health().Degraded
	for _, g := range h.deps.Grants.ListGrants("", unsaved) {
		st := g.State(now)
		revoked := st == grant.GrantRevoked && now.Before(g.ExpiresAt)
		if st != grant.GrantActive && !revoked {
			continue
		}
		if !revoked && h.deps.Access != nil && !h.deps.Access.GrantTokenCurrent(g) {
			continue // replacing the agent's token ended it
		}
		v.Active = append(v.Active, activeRow{
			ID: g.ID, CSRF: csrf, Agent: g.Agent, What: what(g.Action, g.Paths), Uses: usesText(g),
			ExpiresAt: g.ExpiresAt, LastUsed: g.LastUsedAt, By: g.ApprovedBy, Revoked: revoked,
		})
	}
	// Pick the rows to show before working out their texts.
	var expired, past []grant.Request
	for _, rq := range h.deps.Grants.ListRequests("", "") {
		switch rq.Status {
		case grant.StatusPending:
		case grant.StatusExpired:
			expired = append(expired, rq)
		default:
			past = append(past, rq)
		}
	}
	rows := func(rqs []grant.Request, n int) []pastRow {
		sort.SliceStable(rqs, func(i, j int) bool { return endedAt(rqs[i]).After(endedAt(rqs[j])) })
		var out []pastRow
		for _, rq := range rqs[:min(n, len(rqs))] {
			out = append(out, h.pastRow(rq, now))
		}
		return out
	}
	v.Expired, v.History = rows(expired, maxExpiredRows), rows(past, maxHistoryRows)
	return v
}

// endedAt is when a request stopped waiting.
func endedAt(rq grant.Request) time.Time {
	if rq.DecidedAt.IsZero() {
		return rq.ExpiresAt
	}
	return rq.DecidedAt
}

// pastRow is one request that is no longer waiting, with the paths that were
// allowed, or the ones asked for when none were.
func (h *Handler) pastRow(rq grant.Request, now time.Time) pastRow {
	paths := rq.Paths
	if len(rq.GrantedPaths) > 0 {
		paths = rq.GrantedPaths
	} else if g, ok := h.deps.Grants.GetGrant(rq.GrantID); ok {
		paths = g.Paths
	}
	row := pastRow{ID: rq.ID, Agent: rq.Agent, What: what(rq.Action, paths), Note: cleanDisplayText(rq.Note, maxReasonDisplay)}
	row.Outcome, row.Badge, row.When = h.outcome(rq, now)
	return row
}

// outcome says how a request that is no longer waiting ended, with a CSS state
// and when.
func (h *Handler) outcome(rq grant.Request, now time.Time) (text, badge string, when time.Time) {
	switch rq.Status {
	case grant.StatusExpired:
		if !rq.DecidedAt.IsZero() {
			return "Expired: " + rq.Note, "expired", rq.DecidedAt
		}
		return "Expired: nobody answered in time", "expired", rq.ExpiresAt
	case grant.StatusDenied:
		return "No, by " + rq.DecidedBy, "denied", rq.DecidedAt
	case grant.StatusPending:
		return "Waiting", "pending", rq.CreatedAt
	}
	by := " by " + rq.DecidedBy
	if rq.Always {
		listed, allowed := h.alwaysNow(rq)
		switch {
		case listed:
			return "Always," + by, "approved", rq.DecidedAt
		case allowed:
			return "Always," + by + "; another rule allows it now", "approved", rq.DecidedAt
		}
		return "Always," + by + "; removed since", "revoked", rq.DecidedAt
	}
	g, ok := h.deps.Grants.GetGrant(rq.GrantID)
	if !ok {
		return "Allowed" + by, "approved", rq.DecidedAt
	}
	limit := longDur(g.ExpiresAt.Sub(g.CreatedAt))
	switch {
	case g.MaxUses == 1:
		text = "Once," + by
	case g.MaxUses > 1:
		text = fmt.Sprintf("%d uses or %s,%s", g.MaxUses, limit, by)
	default:
		text = strings.ToUpper(limit[:1]) + limit[1:] + "," + by
	}
	switch g.State(now) {
	case grant.GrantActive:
		return text, "approved", rq.DecidedAt
	case grant.GrantUsed:
		return text + "; used", "approved", rq.DecidedAt
	case grant.GrantRevoked:
		return text + "; revoked by " + g.RevokedBy, "revoked", rq.DecidedAt
	}
	return text + "; time ran out", "expired", rq.DecidedAt
}

// alwaysNow reports whether an "always" answer is still on the agent's access
// list, and if not, whether the list allows any of its paths anyway.
func (h *Handler) alwaysNow(rq grant.Request) (listed, allowed bool) {
	if h.deps.ACL == nil {
		return false, false
	}
	a, err := h.deps.ACL.GetAgent(rq.Agent)
	if err != nil {
		return false, false
	}
	for _, p := range a.Permissions {
		listed = listed || (p.Always != nil && !p.Always.Staged && p.Always.RequestID == rq.ID)
	}
	for _, p := range rq.GrantedPaths {
		allowed = allowed || h.deps.ACL.Authorize(rq.Agent, p, acl.ActionReadValue) == nil
	}
	return listed, allowed
}

// what names what a request or grant is for.
func what(action string, paths []string) string {
	if action == grant.ActionSSHLogin {
		return "root login on " + strings.TrimPrefix(paths[0], "ssh/")
	}
	return strings.Join(paths, ", ")
}

// usesText says what a grant's use limit has left, or how often it was used.
func usesText(g grant.Grant) string {
	if g.MaxUses == 0 {
		return fmt.Sprintf("%d so far", g.UseCount)
	}
	left := int64(0)
	for _, p := range g.Paths {
		left += g.UsesLeft(p)
	}
	total := g.MaxUses * int64(len(g.Paths))
	if left == 0 && g.Action == grant.ActionSSHLogin {
		return "certificate issued; none left"
	}
	return fmt.Sprintf("%d of %d left", left, total)
}

// longDur is shortDur in words for a button: "15 minutes", "1 hour", "1h30m".
func longDur(d time.Duration) string {
	unit := func(n int64, name string) string {
		if n == 1 {
			return "1 " + name
		}
		return fmt.Sprintf("%d %ss", n, name)
	}
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		return unit(int64(d/time.Hour), "hour")
	case d < time.Hour && d%time.Minute == 0:
		return unit(int64(d/time.Minute), "minute")
	}
	return shortDur(d)
}

// --- page --------------------------------------------------------------------

// handleRequests: GET /dashboard/requests and /dashboard/requests/{id}. The
// second is what notifications link to: the same page with that request first,
// or, when it is no longer waiting, how it ended.
func (h *Handler) handleRequests(w http.ResponseWriter, r *http.Request) {
	csrf := r.Header.Get("X-Csrf-Token")
	focus := r.PathValue("id")
	data := map[string]interface{}{
		"CSRF": csrf, "Active": "requests", "Focus": focus,
		"Error":     accessErrorMessage(r.URL.Query().Get("error")),
		"Done":      requestDoneText[r.URL.Query().Get("done")],
		"AccessOn":  h.accessEnabled(),
		"Cards":     h.waitingCards(csrf),
		"View":      h.requestsView(csrf),
		"NowMillis": time.Now().UnixMilli(),
	}
	if cards := data["Cards"].([]requestCard); focus != "" && !slices.ContainsFunc(cards, func(c requestCard) bool { return c.ID == focus }) {
		data["FocusMissing"] = true
		if h.accessEnabled() {
			if rq, ok := h.deps.Grants.GetRequest(focus); ok {
				data["FocusEnded"] = h.pastRow(rq, time.Now())
			}
		}
	}
	h.render(w, "requests.html", data)
}

// requestDoneText is the fixed message for each ?done= code, so a crafted link cannot
// put words on the page.
var requestDoneText = map[string]string{
	"revoked":       "Revoked. A value already handed over is not taken back.",
	"removed":       "Removed. The agent can no longer read it.",
	"removed-open":  "Removed from Always. The agent also has an open grant for it; revoke that under Active now if you want it gone too.",
	"removed-still": "Removed, but another rule on this agent's access list still lets it read that secret.",
}

// backToRequests sends a browser without the script back to the page.
func backToRequests(w http.ResponseWriter, r *http.Request, id, done, errorCode string) {
	q := url.Values{}
	if done != "" {
		q.Set("done", done)
	}
	if errorCode != "" {
		q.Set("error", errorCode)
	}
	to := requestsPage
	if requestIDPattern.MatchString(id) {
		to += "/" + id
	}
	if len(q) > 0 {
		to += "?" + q.Encode()
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// answerReply is what requests.js gets back from a tap.
type answerReply struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	State   string `json:"state,omitempty"` // CSS state of the outcome
	Closed  bool   `json:"closed"`          // the request is no longer waiting
}

// finish answers a tap: JSON for the script, a redirect for a plain form.
func (h *Handler) finish(w http.ResponseWriter, r *http.Request, id, done string, code string) {
	if !strings.Contains(r.Header.Get("Accept"), "application/json") {
		backToRequests(w, r, id, done, code)
		return
	}
	reply := answerReply{OK: code == "", Message: requestDoneText[done]}
	if code != "" {
		reply.Message = accessErrorMessage(code)
	}
	if id != "" && h.deps.Grants != nil {
		if rq, ok := h.deps.Grants.GetRequest(id); ok && rq.Status != grant.StatusPending {
			text, badge, _ := h.outcome(rq, time.Now())
			reply.Closed, reply.State = true, badge
			if code == "" {
				reply.Message = text
			} else {
				reply.Message += " (" + text + ")"
			}
		}
	}
	answerJSON(w, http.StatusOK, reply)
}

func answerJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// handleAnswer: POST /dashboard/requests/{id}/answer. Form: choice (no, once,
// time, always, custom), path (repeated; the ticked boxes), note (for no), ttl
// and uses (for custom). Every limit is worked out here from the request, never
// taken from the button.
func (h *Handler) handleAnswer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !h.accessEnabled() {
		h.finish(w, r, "", "", "NOT_CONFIGURED")
		return
	}
	rq, ok := h.deps.Grants.GetRequest(id)
	if !ok {
		h.finish(w, r, "", "", "NOT_FOUND")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.finish(w, r, id, "", "INVALID_REQUEST")
		return
	}
	ip := extractClientIP(r)
	by := "dashboard@" + ip
	var err error
	switch choice := r.PostFormValue("choice"); choice {
	case "no":
		_, err = h.deps.Grants.Deny(grant.DenyInput{RequestID: id, Denier: by, DenierIP: ip, Note: r.PostFormValue("note")})
	case "once", "time", "always", "custom":
		how := grant.Approval{Paths: r.PostForm["path"]}
		if len(how.Paths) == 0 {
			h.finish(w, r, id, "", "EMPTY_GRANT")
			return
		}
		maxTTL := h.deps.Access.AccessRequestSettings().MaxGrantTTL
		switch choice {
		case "once":
			how.Uses = 1
		case "time":
			how.TTL = quickLimit(rq, maxTTL)
		case "always":
			how.Always = true
		case "custom":
			ttl, terr := time.ParseDuration(r.PostFormValue("ttl"))
			if terr != nil || !slices.Contains(ttlChoices(rq.RequestedTTL, maxTTL), ttl) {
				h.finish(w, r, id, "", "INVALID_TTL")
				return
			}
			how.TTL = ttl
			if v := strings.TrimSpace(r.PostFormValue("uses")); v != "" {
				n, nerr := strconv.ParseInt(v, 10, 64)
				if nerr != nil || n < 1 || n > grant.MaxUsesLimit {
					h.finish(w, r, id, "", "INVALID_USES")
					return
				}
				how.Uses = n
			}
		}
		_, _, err = h.deps.Access.ApproveAccessRequestAs(id, by, ip, how)
	default:
		h.finish(w, r, id, "", "INVALID_REQUEST")
		return
	}
	code := ""
	if err != nil {
		log.Printf("dashboard: answering %s: %v", id, err)
		code = errCode(err)
	}
	h.finish(w, r, id, "", code)
}

// handleGrantRevoke: POST /dashboard/requests/grants/{id}/revoke. A revoke that
// could not be saved still denies at once, but the page says so in red
// (REVOKE_NOT_DURABLE) instead of reporting success.
func (h *Handler) handleGrantRevoke(w http.ResponseWriter, r *http.Request) {
	if h.deps.Grants == nil {
		h.finish(w, r, "", "", "NOT_CONFIGURED")
		return
	}
	id := r.PathValue("id")
	ip := extractClientIP(r)
	if _, err := h.deps.Grants.Revoke(grant.RevokeInput{GrantID: id, By: "dashboard@" + ip, IP: ip}); err != nil {
		log.Printf("dashboard: revoke %s: %v", id, err)
		h.finish(w, r, "", "", errCode(err))
		return
	}
	h.finish(w, r, "", "revoked", "")
}

// handleAlwaysRemove: POST /dashboard/requests/always/remove. Form: agent, path
// and the request it came from, so an old page cannot remove a newer answer.
func (h *Handler) handleAlwaysRemove(w http.ResponseWriter, r *http.Request) {
	if !h.accessEnabled() {
		h.finish(w, r, "", "", "NOT_CONFIGURED")
		return
	}
	ip := extractClientIP(r)
	agent, path := r.PostFormValue("agent"), r.PostFormValue("path")
	if err := h.deps.Access.RemoveAlwaysAs(agent, path, r.PostFormValue("request"), "dashboard@"+ip, ip); err != nil {
		log.Printf("dashboard: remove always: %v", err)
		h.finish(w, r, "", "", errCode(err))
		return
	}
	// Say so when something else goes on allowing it.
	openGrant := slices.ContainsFunc(h.deps.Grants.ListGrants(agent, false), func(g grant.Grant) bool {
		return g.Action == grant.ActionReadValue && slices.Contains(g.Paths, path) && g.UsesLeft(path) != 0 &&
			h.deps.Access.GrantTokenCurrent(g)
	})
	switch {
	case h.deps.ACL != nil && h.deps.ACL.Authorize(agent, path, acl.ActionReadValue) == nil:
		h.finish(w, r, "", "removed-still", "")
	case openGrant:
		h.finish(w, r, "", "removed-open", "")
	default:
		h.finish(w, r, "", "removed", "")
	}
}

// --- feed --------------------------------------------------------------------

// requestFeed is what requests.js polls.
type requestFeed struct {
	Rev      string        `json:"rev"` // changes when anything below does
	Now      int64         `json:"now"` // server clock, for the countdown
	Waiting  []feedCard    `json:"waiting"`
	Ended    []feedEnd     `json:"ended"`
	Sections template.HTML `json:"sections,omitempty"` // only for the Requests page
}

type feedCard struct {
	ID   string        `json:"id"`
	HTML template.HTML `json:"html"`
}

type feedEnd struct {
	ID    string `json:"id"`
	Text  string `json:"text"`
	State string `json:"state"`
}

// handleRequestFeed: GET /dashboard/requests/feed[?rev=&page=1]. 204 when
// nothing changed since rev. It checks the login itself instead of through
// requireAuth, for two reasons: an open tab must not look like someone using
// the dashboard, and a tab left open after its login ended must not fill the
// audit log with a denial every two seconds.
func (h *Handler) handleRequestFeed(w http.ResponseWriter, r *http.Request) {
	p, err := h.verifyCookie(r)
	if err != nil {
		answerJSON(w, http.StatusUnauthorized, map[string]string{"error": "signed out"})
		return
	}
	now := time.Now()
	feed := requestFeed{Waiting: []feedCard{}, Ended: []feedEnd{}}
	if h.accessEnabled() {
		for _, rq := range h.deps.Grants.ListRequests("", grant.StatusPending) {
			feed.Waiting = append(feed.Waiting, feedCard{rq.ID, h.cards.get(rq.ID+p.CSRF, now, func() template.HTML {
				return h.fragment("request-card", h.card(rq, p.CSRF))
			})})
		}
		for _, rq := range h.deps.Grants.ListRequests("", "") {
			if rq.Status == grant.StatusPending || now.Sub(endedAt(rq)) >= endedWindow {
				continue
			}
			text, badge, _ := h.outcome(rq, now)
			feed.Ended = append(feed.Ended, feedEnd{rq.ID, text, badge})
		}
	}
	if r.URL.Query().Get("page") != "" {
		feed.Sections = h.fragment("request-sections", h.requestsView(p.CSRF))
	}
	raw, _ := json.Marshal(feed)
	sum := sha256.Sum256(raw)
	feed.Rev = hex.EncodeToString(sum[:8])
	if feed.Rev == r.URL.Query().Get("rev") {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	feed.Now = now.UnixMilli()
	answerJSON(w, http.StatusOK, feed)
}

// cardCache keeps rendered cards for a few seconds. Drawing one asks the
// secrets backend which paths exist, and with 1Password behind it that is too
// slow to do every two seconds for every open tab.
type cardCache struct {
	mu   sync.Mutex
	html map[string]cachedCard
}

type cachedCard struct {
	html template.HTML
	at   time.Time
}

const cardCacheFor = 20 * time.Second

func (c *cardCache) get(key string, now time.Time, draw func() template.HTML) template.HTML {
	c.mu.Lock()
	old, ok := c.html[key]
	c.mu.Unlock()
	if ok && now.Sub(old.at) < cardCacheFor {
		return old.html
	}
	html := draw()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.html == nil {
		c.html = map[string]cachedCard{}
	}
	for k, v := range c.html {
		if now.Sub(v.at) >= cardCacheFor {
			delete(c.html, k)
		}
	}
	c.html[key] = cachedCard{html, now}
	return html
}

// fragment renders one named template of the Requests page on its own.
func (h *Handler) fragment(name string, data any) template.HTML {
	var b bytes.Buffer
	if err := h.tmpls["requests.html"].ExecuteTemplate(&b, name, data); err != nil {
		log.Printf("dashboard: rendering %s: %v", name, err)
		return ""
	}
	return template.HTML(b.String())
}

// --- getting here from a notification ----------------------------------------

var requestIDPattern = regexp.MustCompile(`^req_[0-9a-f]{32}$`)

// loginPath is where a browser without a login is sent. Coming from a request
// page it remembers which one, so a tapped notification ends at the request.
func loginPath(r *http.Request) string {
	if to := safeNext(r.URL.Path); r.Method == http.MethodGet && to != "" {
		return "/dashboard/login?next=" + url.QueryEscape(to)
	}
	return "/dashboard/login"
}

// safeNext accepts only the Requests page or one request, so the login page
// can never be used to send someone anywhere else. Anything else is "".
func safeNext(next string) string {
	if next == requestsPage {
		return next
	}
	if id, ok := strings.CutPrefix(next, requestsPage+"/"); ok && requestIDPattern.MatchString(id) {
		return next
	}
	return ""
}

// nextParam carries a login form's next over to another try.
func nextParam(r *http.Request) string {
	if next := safeNext(r.FormValue("next")); next != "" {
		return "&next=" + url.QueryEscape(next)
	}
	return ""
}

// fromOtherSite handles a link tapped on another site, such as the ntfy web
// page. The login cookie is SameSite=Strict, so the browser holds it back on
// that first load and a signed-in person would land on the login page. One
// reload from our own page sends it. The page only shows things, so loading it
// from a link does nothing.
func (h *Handler) fromOtherSite(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, err := r.Cookie("phoenix_dash")
		to := safeNext(r.URL.Path)
		if err == nil || to == "" || r.Header.Get("Sec-Fetch-Site") != "cross-site" {
			next(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, `<!DOCTYPE html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=%s"><title>Phoenix</title><a href="%s">Open Phoenix</a>`, to, to)
	}
}
