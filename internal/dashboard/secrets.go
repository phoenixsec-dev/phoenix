package dashboard

import (
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/grant"
	"github.com/phoenixsec/phoenix/internal/policy"
	"github.com/phoenixsec/phoenix/internal/store"
)

// The secrets pages: find, open, add and edit secrets (docs/dashboard.md).
//
// Pages are built from metadata only. The one place a value leaves the server
// is handleSecretValue: a POST, answered as no-store JSON, after the login
// cookie, the CSRF token, a same-origin check, a recently typed password, the
// path's policy rule and a written audit line. Every POST here answers JSON,
// because the page must be able to ask for the password and try again without
// sending a typed value back as HTML.

// maxSecretForm caps a POST here. A value may be 1 MB, as in the API, and
// form encoding can triple it.
const maxSecretForm = 4 << 20

// maxSecretValue is the largest value the dashboard stores, as in the API.
const maxSecretValue = 1 << 20

// newSecretName is what a new secret may be called from the dashboard: the
// plain characters that work unescaped in phoenix:// references and URLs.
var newSecretName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*(/[A-Za-z0-9_][A-Za-z0-9._-]*)+$`)

// secretRoutes registers the secrets pages.
func (h *Handler) secretRoutes() {
	page := func(path string, f http.HandlerFunc) { h.mux.HandleFunc("GET "+path, h.requireAuth(f)) }
	// The body is capped before requireAuth reads the form for the CSRF token.
	post := func(path string, f http.HandlerFunc) {
		checked := h.requireSameOrigin(h.requireAuth(f))
		h.mux.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxSecretForm)
			checked(w, r)
		})
	}
	page("/dashboard/secrets", h.handleSecrets)
	page("/dashboard/secrets/open", h.handleSecretOpen)
	page("/dashboard/secrets/new", h.handleSecretNewPage)
	page("/dashboard/secrets/details", h.handleSecretEditPage("details"))
	page("/dashboard/secrets/replace", h.handleSecretEditPage("replace"))
	post("/dashboard/reauth", h.handleReauth)
	post("/dashboard/secrets/value", h.requireRecent(h.handleSecretValue))
	post("/dashboard/secrets/new", h.requireRecent(h.handleSecretAdd))
	post("/dashboard/secrets/details", h.requireRecent(h.handleSecretDetails))
	post("/dashboard/secrets/replace", h.requireRecent(h.handleSecretReplace))
}

// secretRow is one line of the list. Search is the text the box matches.
type secretRow struct {
	Path        string
	Description string
	Username    string
	Tags        []string
	Search      string
	Hidden      bool // does not match the q the page was opened with
}

// matchesAll reports whether every word of q is in text (both lowercased).
// dashboard.js does the same as you type.
func matchesAll(text, q string) bool {
	for _, word := range strings.Fields(strings.ToLower(q)) {
		if !strings.Contains(text, word) {
			return false
		}
	}
	return true
}

// handleSecrets: GET /dashboard/secrets[?q=words]. The list holds every
// secret's name, description, tags and username; the page filters it as you
// type. No value is read to build it.
func (h *Handler) handleSecrets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	var rows []secretRow
	failed := h.deps.Backend == nil
	shown := 0
	if !failed {
		paths, err := h.deps.Backend.List("")
		if err != nil {
			log.Printf("dashboard: listing secrets: %v", err)
			failed = true
		}
		slices.Sort(paths)
		for _, p := range paths {
			row := secretRow{Path: p}
			if m, err := h.deps.Backend.Metadata(p); err == nil {
				row.Description, row.Username, row.Tags = m.Description, m.Username, m.Tags
			}
			row.Search = strings.ToLower(p + " " + row.Description + " " + row.Username + " " + strings.Join(row.Tags, " "))
			row.Hidden = !matchesAll(row.Search, q)
			if !row.Hidden {
				shown++
			}
			rows = append(rows, row)
		}
	}
	h.render(w, "secrets.html", map[string]interface{}{
		"CSRF":     r.Header.Get("X-Csrf-Token"),
		"Active":   "secrets",
		"Q":        q,
		"Rows":     rows,
		"Shown":    shown,
		"Failed":   failed,
		"ReadOnly": h.readOnly(),
	})
}

// readOnly reports whether secrets can be added and edited here.
func (h *Handler) readOnly() bool {
	return h.deps.Backend == nil || h.deps.Backend.ReadOnly()
}

// secretMeta returns a secret's metadata, or false if there is no such
// secret. Existence comes from List: some backends' Metadata does not check.
func (h *Handler) secretMeta(path string) (*store.SecretMetadata, bool) {
	if h.deps.Backend == nil || store.ValidatePath(path) != nil {
		return nil, false
	}
	paths, err := h.deps.Backend.List(path)
	if err != nil || !slices.Contains(paths, path) {
		return nil, false
	}
	m, err := h.deps.Backend.Metadata(path)
	if err != nil {
		return nil, false
	}
	return m, true
}

// secretReader is one agent that may read a secret's value now.
type secretReader struct {
	Agent string
	Until string // when its temporary access ends; "" = its own permission
}

// secretReaders lists who may read path: agents whose permissions allow it,
// then agents with temporary access.
func (h *Handler) secretReaders(path string) []secretReader {
	var out []secretReader
	if h.deps.ACL != nil {
		names := h.deps.ACL.ListAgents()
		sort.Strings(names)
		for _, n := range names {
			if h.deps.ACL.Authorize(n, path, acl.ActionReadValue) == nil {
				out = append(out, secretReader{Agent: n})
			}
		}
	}
	if h.accessEnabled() && h.deps.Access.AccessRequestSettings().Enabled {
		now := time.Now()
		for _, g := range h.deps.Grants.ListGrants("", false) {
			if g.Action == grant.ActionReadValue && g.State(now) == grant.GrantActive && slices.Contains(g.Paths, path) {
				out = append(out, secretReader{Agent: g.Agent, Until: ttlRemain(g.ExpiresAt)})
			}
		}
	}
	return out
}

// secretRules describes the path's policy rule in plain words.
func (h *Handler) secretRules(path string) []string {
	if h.deps.Policy == nil {
		return nil
	}
	rule, _ := h.deps.Policy.RuleFor(path)
	if rule == nil {
		return nil
	}
	var out []string
	if len(rule.AllowedIPs) > 0 {
		out = append(out, "only from "+strings.Join(rule.AllowedIPs, ", "))
	}
	if rule.RequireSealed {
		out = append(out, "only sealed (encrypted to the agent's own key)")
	}
	return out
}

// directIP is the address of the network connection. Policy rules use it, as
// the API does, never a forwarded header a client could write itself.
func directIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// policyBlock says in plain words why the path's policy rule stops this
// request, or "" if it does not. reading is false for writes, which a "sealed
// delivery only" rule does not concern.
func (h *Handler) policyBlock(r *http.Request, path string, reading bool) string {
	if h.deps.Policy == nil {
		return ""
	}
	ip := directIP(r)
	err := h.deps.Policy.Evaluate(path, &policy.RequestContext{SourceIP: ip, SealKeyPresented: !reading})
	if err == nil {
		return ""
	}
	var denied *policy.DeniedError
	if errors.As(err, &denied) && denied.SealedRequired {
		return "A rule says this secret is only handed out sealed to an agent, so it can't be shown here."
	}
	return "A rule says this secret can only be used from certain machines, and you are connecting from " + ip + "."
}

// revealBlock says why a secret's value cannot be shown here, or "".
func (h *Handler) revealBlock(r *http.Request, path string) string {
	if !h.reveal {
		return "Showing secrets in the dashboard is switched off on this server."
	}
	return h.policyBlock(r, path, true)
}

// doneText is the green message after a change; only these codes are shown.
var doneText = map[string]string{
	"added":    "Saved.",
	"replaced": "New value saved.",
	"details":  "Details saved. The value was not touched.",
}

// notFoundPage answers 404 for a secret that does not exist.
func (h *Handler) notFoundPage(w http.ResponseWriter, r *http.Request, path string) {
	w.WriteHeader(http.StatusNotFound)
	h.render(w, "secret.html", map[string]interface{}{
		"CSRF": r.Header.Get("X-Csrf-Token"), "Active": "secrets", "Path": path, "Missing": true,
	})
}

// handleSecretOpen: GET /dashboard/secrets/open?path=... shows everything
// about one secret except its value.
func (h *Handler) handleSecretOpen(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	m, ok := h.secretMeta(path)
	if !ok {
		h.notFoundPage(w, r, path)
		return
	}
	// A hand-edited store file can hold any link: only http(s) becomes one.
	link := m.URL
	if store.ValidateURL(link) != nil {
		link = ""
	}
	updatedBy := m.UpdatedBy
	if updatedBy == "" {
		updatedBy = m.CreatedBy // older versions kept the last writer there
	}
	h.render(w, "secret.html", map[string]interface{}{
		"CSRF":      r.Header.Get("X-Csrf-Token"),
		"Active":    "secrets",
		"Path":      path,
		"Meta":      m,
		"UpdatedBy": updatedBy,
		"Link":      link,
		"LinkHost":  linkHost(link),
		"Readers":   h.secretReaders(path),
		"Rules":     h.secretRules(path),
		"Blocked":   h.revealBlock(r, path),
		"ReadOnly":  h.readOnly(),
		"Done":      doneText[r.URL.Query().Get("done")],
		"Plain":     unencrypted(r),
	})
}

// linkHost is the site a link goes to. It is shown next to the button, so a
// changed link can be noticed before the password is pasted there.
func linkHost(link string) string {
	u, err := url.Parse(link)
	if err != nil {
		return ""
	}
	return u.Host
}

// unencrypted reports whether the page is on plain HTTP over a network, where
// values and the password could be read on the way.
func unencrypted(r *http.Request) bool {
	ip := net.ParseIP(directIP(r))
	return !isTLS(r) && (ip == nil || !ip.IsLoopback())
}

// handleSecretNewPage: GET /dashboard/secrets/new.
func (h *Handler) handleSecretNewPage(w http.ResponseWriter, r *http.Request) {
	h.renderSecretForm(w, r, "new", "", &store.SecretMetadata{})
}

// handleSecretEditPage: GET /dashboard/secrets/details and .../replace. The
// replace form starts empty; the stored value is never sent to it.
func (h *Handler) handleSecretEditPage(mode string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")
		m, ok := h.secretMeta(path)
		if !ok {
			h.notFoundPage(w, r, path)
			return
		}
		h.renderSecretForm(w, r, mode, path, m)
	}
}

// renderSecretForm draws the add, details or new-value form.
func (h *Handler) renderSecretForm(w http.ResponseWriter, r *http.Request, mode, path string, m *store.SecretMetadata) {
	h.render(w, "secret_edit.html", map[string]interface{}{
		"CSRF":     r.Header.Get("X-Csrf-Token"),
		"Active":   "secrets",
		"Mode":     mode,
		"Path":     path,
		"Meta":     m,
		"Tags":     strings.Join(m.Tags, ", "),
		"ReadOnly": h.readOnly(),
		"Plain":    unencrypted(r),
	})
}

// auditMeta is the audit metadata of a dashboard action: which login did it.
func (h *Handler) auditMeta(r *http.Request, extra ...string) map[string]string {
	md := map[string]string{}
	if l, ok := h.currentLogin(r); ok {
		md["dashboard.login"] = l.ID
	}
	for i := 0; i+1 < len(extra); i += 2 {
		md[extra[i]] = extra[i+1]
	}
	return md
}

// denySecret audits a refused action and answers with the reason.
func (h *Handler) denySecret(w http.ResponseWriter, r *http.Request, action, path, reason, msg string, extra ...string) {
	ip := extractClientIP(r)
	if h.deps.Audit != nil {
		h.deps.Audit.LogDeniedWithMetadata("dashboard@"+ip, action, path, ip, reason, h.auditMeta(r, extra...))
	}
	writeError(w, http.StatusForbidden, msg)
}

// handleSecretValue: POST /dashboard/secrets/value with path and use ("show"
// or "copy"). The only place the dashboard hands out a value. Audited as
// read_value before the value is sent; no audit line, no value.
func (h *Handler) handleSecretValue(w http.ResponseWriter, r *http.Request) {
	path, use := r.PostFormValue("path"), r.PostFormValue("use")
	if use != "show" && use != "copy" {
		writeError(w, http.StatusBadRequest, "Bad request.")
		return
	}
	if h.deps.Backend == nil || h.deps.Audit == nil {
		writeError(w, http.StatusServiceUnavailable, "Secrets are not available on this server.")
		return
	}
	if !h.reveal {
		h.denySecret(w, r, "read_value", path, "reveal_off", h.revealBlock(r, path), "dashboard.use", use)
		return
	}
	if msg := h.policyBlock(r, path, true); msg != "" {
		h.denySecret(w, r, "read_value", path, "attestation", msg, "dashboard.use", use)
		return
	}
	secret, err := h.deps.Backend.Get(path)
	if errors.Is(err, store.ErrSecretNotFound) || errors.Is(err, store.ErrInvalidPath) {
		writeError(w, http.StatusNotFound, "There is no secret with that name.")
		return
	}
	if err != nil {
		log.Printf("dashboard: reading secret %q: %v", path, err)
		writeError(w, http.StatusInternalServerError, "The secret could not be read.")
		return
	}
	ip := extractClientIP(r)
	if err := h.deps.Audit.LogAllowedWithMetadata("dashboard@"+ip, "read_value", path, ip, h.auditMeta(r, "dashboard.use", use)); err != nil {
		log.Printf("dashboard: audit write failed, value of %q not shown: %v", path, err)
		writeError(w, http.StatusInternalServerError, "The audit log can't be written, so the value was not shown.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"value": secret.Value})
}

// formChange collects the metadata fields a form sent. A field the form left
// out is kept.
func formChange(r *http.Request) store.MetadataChange {
	get := func(name string) *string {
		if _, ok := r.PostForm[name]; !ok {
			return nil
		}
		v := strings.TrimSpace(r.PostForm.Get(name))
		return &v
	}
	ch := store.MetadataChange{Description: get("description"), Username: get("username"), URL: get("url")}
	if t := get("tags"); t != nil {
		tags := []string{}
		for _, tag := range strings.Split(*t, ",") {
			if tag = strings.TrimSpace(tag); tag != "" {
				tags = append(tags, tag)
			}
		}
		ch.Tags = &tags
	}
	return ch
}

// formValue is the new value a form sent, with the stray spaces and newlines
// a paste often carries removed, as the CLI's prompt does.
func formValue(w http.ResponseWriter, r *http.Request) (string, bool) {
	v := strings.TrimSpace(r.PostFormValue("value"))
	if v == "" {
		writeError(w, http.StatusBadRequest, "Enter a value.")
		return "", false
	}
	if len(v) > maxSecretValue {
		writeError(w, http.StatusBadRequest, "The value is too big (at most 1 MB).")
		return "", false
	}
	return v, true
}

// writable answers with an error unless secrets can be changed here.
func (h *Handler) writable(w http.ResponseWriter) bool {
	if h.readOnly() {
		writeError(w, http.StatusMethodNotAllowed, "Secrets can't be changed on this server (read-only backend).")
		return false
	}
	return true
}

// finishWrite answers a change: on success it audits it and says where to go.
func (h *Handler) finishWrite(w http.ResponseWriter, r *http.Request, err error, action, path, done string, fields []string) {
	ip := extractClientIP(r)
	switch {
	case err == nil:
		extra := []string{}
		if len(fields) > 0 {
			extra = append(extra, "changed", strings.Join(fields, ","))
		}
		if h.deps.Audit != nil {
			if aerr := h.deps.Audit.LogAllowedWithMetadata("dashboard@"+ip, action, path, ip, h.auditMeta(r, extra...)); aerr != nil {
				log.Printf("WARNING: audit log write failed for %s %q by dashboard@%s: %v", action, path, ip, aerr)
			}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"ok": true, "next": "/dashboard/secrets/open?done=" + done + "&path=" + url.QueryEscape(path),
		})
	case errors.Is(err, store.ErrSecretExists):
		writeError(w, http.StatusConflict, "A secret with that name already exists. Open it and use New value.")
	case errors.Is(err, store.ErrSecretNotFound), errors.Is(err, store.ErrInvalidPath):
		writeError(w, http.StatusNotFound, "There is no secret with that name.")
	default:
		log.Printf("dashboard: %s %q: %v", action, path, err)
		writeError(w, http.StatusInternalServerError, "It could not be saved. Nothing changed.")
	}
}

// handleSecretAdd: POST /dashboard/secrets/new. Never overwrites.
func (h *Handler) handleSecretAdd(w http.ResponseWriter, r *http.Request) {
	if !h.writable(w) {
		return
	}
	path := strings.TrimSpace(r.PostFormValue("path"))
	if !newSecretName.MatchString(path) || store.ValidatePath(path) != nil {
		writeError(w, http.StatusBadRequest, "The name needs a folder and a name, like personal/petstore. Letters, numbers, dots, dashes and underscores only.")
		return
	}
	value, ok := formValue(w, r)
	if !ok {
		return
	}
	ch := formChange(r)
	if err := ch.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, sentence(err))
		return
	}
	if msg := h.policyBlock(r, path, false); msg != "" {
		h.denySecret(w, r, "write", path, "attestation", msg)
		return
	}
	err := h.deps.Backend.Write(path, value, "dashboard@"+extractClientIP(r), ch, store.WriteNew)
	h.finishWrite(w, r, err, "write", path, "added", nil)
}

// handleSecretReplace: POST /dashboard/secrets/replace, a new value for an
// existing secret. Needs confirm=yes: the old value is gone afterwards.
func (h *Handler) handleSecretReplace(w http.ResponseWriter, r *http.Request) {
	if !h.writable(w) {
		return
	}
	path := r.PostFormValue("path")
	value, ok := formValue(w, r)
	if !ok {
		return
	}
	if r.PostFormValue("confirm") != "yes" {
		writeError(w, http.StatusBadRequest, "Tick the box to confirm that the old value will be gone.")
		return
	}
	if msg := h.policyBlock(r, path, false); msg != "" {
		h.denySecret(w, r, "write", path, "attestation", msg)
		return
	}
	err := h.deps.Backend.Write(path, value, "dashboard@"+extractClientIP(r), store.MetadataChange{}, store.WriteExisting)
	h.finishWrite(w, r, err, "write", path, "replaced", nil)
}

// handleSecretDetails: POST /dashboard/secrets/details changes the
// description, tags, username and link without touching the value.
func (h *Handler) handleSecretDetails(w http.ResponseWriter, r *http.Request) {
	if !h.writable(w) {
		return
	}
	path := r.PostFormValue("path")
	ch := formChange(r)
	fields := ch.Fields()
	if len(fields) == 0 {
		writeError(w, http.StatusBadRequest, "Nothing was changed.")
		return
	}
	if err := ch.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, sentence(err))
		return
	}
	h.finishWrite(w, r, h.deps.Backend.Describe(path, ch), "describe", path, "details", fields)
}

// sentence turns an error text into a message for the page.
func sentence(err error) string {
	s := err.Error()
	return strings.ToUpper(s[:1]) + s[1:] + "."
}
