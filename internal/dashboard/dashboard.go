// Package dashboard implements a lightweight operator web UI for Phoenix.
// All templates, CSS, JS, and SVG are embedded via go:embed — no external deps.
package dashboard

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/approval"
	"github.com/phoenixsec/phoenix/internal/audit"
	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/policy"
	"github.com/phoenixsec/phoenix/internal/session"
	"github.com/phoenixsec/phoenix/internal/store"

	"golang.org/x/crypto/bcrypt"
)

// Login rate limiting — exponential backoff per IP.
const (
	loginMaxFailures = 5
	loginBaseDelay   = 1 * time.Second
	loginMaxDelay    = 60 * time.Second
	loginCleanupAge  = 10 * time.Minute
)

type loginRateEntry struct {
	failures  int
	blockedAt time.Time
}

type loginRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*loginRateEntry
}

func newLoginRateLimiter() *loginRateLimiter {
	rl := &loginRateLimiter{entries: make(map[string]*loginRateEntry)}
	go rl.cleanupLoop()
	return rl
}

func (rl *loginRateLimiter) check(ip string) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e, ok := rl.entries[ip]
	if !ok || e.failures < loginMaxFailures {
		return nil
	}
	exp := e.failures - loginMaxFailures
	if exp > 6 {
		exp = 6
	}
	delay := loginBaseDelay * (1 << exp)
	if delay > loginMaxDelay {
		delay = loginMaxDelay
	}
	if time.Since(e.blockedAt) < delay {
		return fmt.Errorf("too many login attempts, retry in %s", (delay - time.Since(e.blockedAt)).Truncate(time.Second))
	}
	return nil
}

func (rl *loginRateLimiter) recordFailure(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e, ok := rl.entries[ip]
	if !ok {
		e = &loginRateEntry{}
		rl.entries[ip] = e
	}
	e.failures++
	e.blockedAt = time.Now()
}

func (rl *loginRateLimiter) recordSuccess(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.entries, ip)
}

func (rl *loginRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(loginCleanupAge)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-loginCleanupAge)
		for ip, e := range rl.entries {
			if e.blockedAt.Before(cutoff) {
				delete(rl.entries, ip)
			}
		}
		rl.mu.Unlock()
	}
}

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Deps holds pointers to the stores the dashboard needs.
// The dashboard accesses these directly — it does not proxy through the HTTP API.
type Deps struct {
	Sessions     *session.Store
	SessionRoles map[string]config.RoleConfig
	Approvals    *approval.Store
	AuditPath    string
	Backend      store.SecretBackend
	ACL          *acl.ACL
	Policy       *policy.Engine
	StartTime    time.Time
	Audit        *audit.Logger
}

// Handler serves the dashboard web UI.
type Handler struct {
	deps       Deps
	tmpl       *template.Template
	cookieKey  []byte // 32 bytes, HMAC signing
	passwordH  []byte // bcrypt hash (nil if PIN mode)
	pin        string // raw PIN (empty if password mode)
	sessionTTL time.Duration
	loginRL    *loginRateLimiter
	mux        *http.ServeMux
}

// cookiePayload is the signed cookie content.
type cookiePayload struct {
	Exp  int64  `json:"exp"`
	CSRF string `json:"csrf"`
}

// New creates a dashboard handler from config and deps.
func New(cfg config.DashboardConfig, deps Deps) (*Handler, error) {
	// Generate cookie signing key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating cookie key: %w", err)
	}

	h := &Handler{
		deps:       deps,
		cookieKey:  key,
		sessionTTL: 4 * time.Hour,
		loginRL:    newLoginRateLimiter(),
		mux:        http.NewServeMux(),
	}

	// Parse session TTL
	if cfg.SessionTTL != "" {
		d, err := time.ParseDuration(cfg.SessionTTL)
		if err == nil {
			h.sessionTTL = d
		}
	}

	// Set up auth: password (bcrypt) or PIN
	if cfg.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(cfg.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("hashing password: %w", err)
		}
		h.passwordH = hash
	} else if cfg.PIN != "" {
		h.pin = cfg.PIN
	}

	// Parse templates with functions
	funcMap := template.FuncMap{
		"truncate":  truncate,
		"fmtTime":   fmtTime,
		"fmtAgo":    fmtAgo,
		"ttlRemain": ttlRemain,
		"join":      strings.Join,
		"upper":     strings.ToUpper,
		"hasPrefix": strings.HasPrefix,
	}

	tmpl, err := template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parsing templates: %w", err)
	}
	h.tmpl = tmpl

	// Static file server (strip /dashboard/static/ prefix)
	staticSub, _ := fs.Sub(staticFS, "static")
	staticHandler := http.FileServer(http.FS(staticSub))

	// Routes
	h.mux.HandleFunc("GET /dashboard/login", h.handleLoginPage)
	h.mux.HandleFunc("POST /dashboard/login", h.handleLogin)
	h.mux.HandleFunc("POST /dashboard/logout", h.handleLogout)
	h.mux.HandleFunc("GET /dashboard/", h.requireAuth(h.handleOverview))
	h.mux.HandleFunc("GET /dashboard/approvals", h.requireAuth(h.handleApprovals))
	h.mux.HandleFunc("POST /dashboard/approvals/{id}/approve", h.requireAuth(h.handleApprove))
	h.mux.HandleFunc("POST /dashboard/approvals/{id}/deny", h.requireAuth(h.handleDeny))
	h.mux.HandleFunc("GET /dashboard/sessions", h.requireAuth(h.handleSessions))
	h.mux.HandleFunc("POST /dashboard/sessions/{id}/revoke", h.requireAuth(h.handleRevoke))
	h.mux.HandleFunc("GET /dashboard/audit", h.requireAuth(h.handleAudit))
	h.mux.HandleFunc("GET /dashboard/roles", h.requireAuth(h.handleRoles))
	h.mux.Handle("GET /dashboard/static/", http.StripPrefix("/dashboard/static/", staticHandler))

	return h, nil
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// --- Auth ---

func (h *Handler) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	h.render(w, "login.html", map[string]interface{}{
		"Error": r.URL.Query().Get("error"),
	})
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := extractClientIP(r)

	// Rate limit check
	if err := h.loginRL.check(clientIP); err != nil {
		if h.deps.Audit != nil {
			h.deps.Audit.LogDenied("dashboard", "dashboard.login", "rate_limited", clientIP, err.Error())
		}
		http.Redirect(w, r, "/dashboard/login?error="+escapeFlash(err.Error()), http.StatusSeeOther)
		return
	}

	credential := r.FormValue("credential")

	ok := false
	if h.passwordH != nil {
		ok = bcrypt.CompareHashAndPassword(h.passwordH, []byte(credential)) == nil
	} else if h.pin != "" {
		ok = len(credential) > 0 && hmac.Equal([]byte(h.pin), []byte(credential))
	}

	if !ok {
		h.loginRL.recordFailure(clientIP)
		if h.deps.Audit != nil {
			h.deps.Audit.LogDenied("dashboard", "dashboard.login", "login", clientIP, "invalid_credentials")
		}
		http.Redirect(w, r, "/dashboard/login?error=invalid+credentials", http.StatusSeeOther)
		return
	}

	h.loginRL.recordSuccess(clientIP)

	// Generate CSRF token
	csrfBytes := make([]byte, 16)
	rand.Read(csrfBytes)
	csrf := hex.EncodeToString(csrfBytes)

	// Create signed cookie
	payload := cookiePayload{
		Exp:  time.Now().Add(h.sessionTTL).Unix(),
		CSRF: csrf,
	}
	cookie, err := h.signCookie(payload)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "phoenix_dash",
		Value:    cookie,
		Path:     "/dashboard/",
		HttpOnly: true,
		Secure:   isTLS(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(h.sessionTTL.Seconds()),
	})

	if h.deps.Audit != nil {
		h.deps.Audit.LogAllowed("dashboard@"+clientIP, "dashboard.login", "login", clientIP)
	}

	http.Redirect(w, r, "/dashboard/", http.StatusSeeOther)
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "phoenix_dash",
		Value:    "",
		Path:     "/dashboard/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/dashboard/login", http.StatusSeeOther)
}

// requireAuth wraps a handler with cookie auth and CSRF validation for POST.
func (h *Handler) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		payload, err := h.verifyCookie(r)
		if err != nil {
			http.Redirect(w, r, "/dashboard/login", http.StatusSeeOther)
			return
		}

		// CSRF check on POST
		if r.Method == "POST" {
			formCSRF := r.FormValue("_csrf")
			if !hmac.Equal([]byte(payload.CSRF), []byte(formCSRF)) {
				http.Error(w, "CSRF validation failed", http.StatusForbidden)
				return
			}
		}

		// Inject CSRF into request context via query param for templates
		r.Header.Set("X-Csrf-Token", payload.CSRF)
		next(w, r)
	}
}

func (h *Handler) signCookie(p cookiePayload) (string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, h.cookieKey)
	mac.Write(data)
	sig := hex.EncodeToString(mac.Sum(nil))
	return hex.EncodeToString(data) + "." + sig, nil
}

func (h *Handler) verifyCookie(r *http.Request) (*cookiePayload, error) {
	c, err := r.Cookie("phoenix_dash")
	if err != nil {
		return nil, err
	}

	parts := strings.SplitN(c.Value, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid cookie format")
	}

	data, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}

	sig, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, h.cookieKey)
	mac.Write(data)
	if !hmac.Equal(mac.Sum(nil), sig) {
		return nil, fmt.Errorf("invalid signature")
	}

	var p cookiePayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}

	if time.Now().Unix() > p.Exp {
		return nil, fmt.Errorf("cookie expired")
	}

	return &p, nil
}

// --- Page Handlers ---

func (h *Handler) handleOverview(w http.ResponseWriter, r *http.Request) {
	// Gather stats
	secretCount := 0
	if h.deps.Backend != nil {
		secretCount = h.deps.Backend.Count()
	}

	agentCount := 0
	if h.deps.ACL != nil {
		agentCount = len(h.deps.ACL.ListAgents())
	}

	activeSessionCount := 0
	if h.deps.Sessions != nil {
		activeSessionCount = h.deps.Sessions.ActiveCount()
	}

	pendingApprovals := 0
	if h.deps.Approvals != nil {
		pendingApprovals = len(h.deps.Approvals.ListPending())
	}

	// Recent audit
	var recentAudit []audit.Entry
	if h.deps.AuditPath != "" {
		recentAudit, _ = audit.Query(h.deps.AuditPath, audit.QueryOptions{Limit: 10})
	}
	// Reverse for newest first
	for i, j := 0, len(recentAudit)-1; i < j; i, j = i+1, j-1 {
		recentAudit[i], recentAudit[j] = recentAudit[j], recentAudit[i]
	}

	h.render(w, "overview.html", map[string]interface{}{
		"CSRF":             r.Header.Get("X-Csrf-Token"),
		"Active":           "overview",
		"SecretCount":      secretCount,
		"AgentCount":       agentCount,
		"SessionCount":     activeSessionCount,
		"PendingApprovals": pendingApprovals,
		"Uptime":           fmtAgo(h.deps.StartTime),
		"RecentAudit":      recentAudit,
		"SessionsEnabled":  h.deps.Sessions != nil,
	})
}

func (h *Handler) handleApprovals(w http.ResponseWriter, r *http.Request) {
	if h.deps.Approvals == nil {
		h.render(w, "approvals.html", map[string]interface{}{
			"CSRF":     r.Header.Get("X-Csrf-Token"),
			"Active":   "approvals",
			"Pending":  nil,
			"Resolved": nil,
			"Flash":    r.URL.Query().Get("flash"),
		})
		return
	}

	all := h.deps.Approvals.ListAll()

	var pending, resolved []*approval.Approval
	for _, a := range all {
		if a.Status == approval.StatusPending {
			pending = append(pending, a)
		} else {
			resolved = append(resolved, a)
		}
	}

	// Sort pending by created (oldest first), resolved by created (newest first)
	sort.Slice(pending, func(i, j int) bool {
		return pending[i].CreatedAt.Before(pending[j].CreatedAt)
	})
	sort.Slice(resolved, func(i, j int) bool {
		return resolved[i].CreatedAt.After(resolved[j].CreatedAt)
	})

	h.render(w, "approvals.html", map[string]interface{}{
		"CSRF":     r.Header.Get("X-Csrf-Token"),
		"Active":   "approvals",
		"Pending":  pending,
		"Resolved": resolved,
		"Flash":    r.URL.Query().Get("flash"),
	})
}

func (h *Handler) handleApprove(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if h.deps.Approvals == nil {
		http.Redirect(w, r, "/dashboard/approvals?flash=approvals+not+configured", http.StatusSeeOther)
		return
	}

	apr := h.deps.Approvals.Get(id)
	if apr == nil {
		http.Redirect(w, r, "/dashboard/approvals?flash=approval+not+found", http.StatusSeeOther)
		return
	}
	if apr.Status != approval.StatusPending {
		http.Redirect(w, r, "/dashboard/approvals?flash=approval+already+"+string(apr.Status), http.StatusSeeOther)
		return
	}

	// Shared safety checks
	role, valErr := approval.ValidateForMint(apr, h.deps.SessionRoles)
	if valErr != nil {
		http.Redirect(w, r, "/dashboard/approvals?flash="+escapeFlash(valErr.Error()), http.StatusSeeOther)
		return
	}

	// Mint session
	ttl := sessionTTL(role.MaxTTL)
	tokenStr, sess, mintErr := h.deps.Sessions.Create(
		apr.Role, apr.Agent, apr.SealPubKey,
		role.Namespaces, role.Actions,
		apr.BootstrapMethod, apr.CertFingerprint, apr.SourceIP, ttl,
	)
	if mintErr != nil {
		log.Printf("dashboard: session mint error: %v", mintErr)
		http.Redirect(w, r, "/dashboard/approvals?flash=mint+error", http.StatusSeeOther)
		return
	}

	// Record approval
	clientIP := extractClientIP(r)
	approverTTY := "dashboard:" + clientIP
	if aprErr := h.deps.Approvals.Approve(id, "dashboard", clientIP, approverTTY, tokenStr, sess.ID, sess.ExpiresAt); aprErr != nil {
		http.Redirect(w, r, "/dashboard/approvals?flash="+escapeFlash(aprErr.Error()), http.StatusSeeOther)
		return
	}

	// Audit
	if h.deps.Audit != nil {
		h.deps.Audit.LogAllowed("dashboard@"+clientIP, "approval.approved", apr.Role, clientIP)
	}

	http.Redirect(w, r, "/dashboard/approvals?flash=approved+"+id, http.StatusSeeOther)
}

func (h *Handler) handleDeny(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if h.deps.Approvals == nil {
		http.Redirect(w, r, "/dashboard/approvals?flash=approvals+not+configured", http.StatusSeeOther)
		return
	}

	clientIP := extractClientIP(r)
	if err := h.deps.Approvals.Deny(id, "dashboard", clientIP); err != nil {
		http.Redirect(w, r, "/dashboard/approvals?flash="+escapeFlash(err.Error()), http.StatusSeeOther)
		return
	}

	if h.deps.Audit != nil {
		h.deps.Audit.LogAllowed("dashboard@"+clientIP, "approval.denied", id, clientIP)
	}

	http.Redirect(w, r, "/dashboard/approvals?flash=denied+"+id, http.StatusSeeOther)
}

func (h *Handler) handleSessions(w http.ResponseWriter, r *http.Request) {
	var sessions []*session.Session
	if h.deps.Sessions != nil {
		sessions = h.deps.Sessions.List()
	}

	roleFilter := r.URL.Query().Get("role")
	agentFilter := r.URL.Query().Get("agent")

	if roleFilter != "" || agentFilter != "" {
		var filtered []*session.Session
		for _, s := range sessions {
			if roleFilter != "" && s.Role != roleFilter {
				continue
			}
			if agentFilter != "" && !strings.Contains(s.Agent, agentFilter) {
				continue
			}
			filtered = append(filtered, s)
		}
		sessions = filtered
	}

	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].CreatedAt.After(sessions[j].CreatedAt)
	})

	// Collect role names for filter dropdown
	var roleNames []string
	for name := range h.deps.SessionRoles {
		roleNames = append(roleNames, name)
	}
	sort.Strings(roleNames)

	h.render(w, "sessions.html", map[string]interface{}{
		"CSRF":        r.Header.Get("X-Csrf-Token"),
		"Active":      "sessions",
		"Sessions":    sessions,
		"Roles":       roleNames,
		"RoleFilter":  roleFilter,
		"AgentFilter": agentFilter,
		"Flash":       r.URL.Query().Get("flash"),
	})
}

func (h *Handler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if h.deps.Sessions == nil {
		http.Redirect(w, r, "/dashboard/sessions?flash=sessions+not+configured", http.StatusSeeOther)
		return
	}

	if err := h.deps.Sessions.Revoke(id); err != nil {
		http.Redirect(w, r, "/dashboard/sessions?flash="+escapeFlash(err.Error()), http.StatusSeeOther)
		return
	}

	clientIP := extractClientIP(r)
	if h.deps.Audit != nil {
		h.deps.Audit.LogAllowed("dashboard@"+clientIP, "session.revoke", id, clientIP)
	}

	http.Redirect(w, r, "/dashboard/sessions?flash=revoked+"+id, http.StatusSeeOther)
}

func (h *Handler) handleAudit(w http.ResponseWriter, r *http.Request) {
	agentFilter := r.URL.Query().Get("agent")
	statusFilter := r.URL.Query().Get("status")
	limitStr := r.URL.Query().Get("limit")

	limit := 50
	switch limitStr {
	case "100":
		limit = 100
	case "500":
		limit = 500
	}

	opts := audit.QueryOptions{Limit: limit}
	if agentFilter != "" {
		opts.Agent = agentFilter
	}

	var entries []audit.Entry
	if h.deps.AuditPath != "" {
		entries, _ = audit.Query(h.deps.AuditPath, opts)
	}

	// Filter by status client-side (audit.Query doesn't support it)
	if statusFilter != "" {
		var filtered []audit.Entry
		for _, e := range entries {
			if e.Status == statusFilter {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	// Reverse for newest first
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}

	h.render(w, "audit.html", map[string]interface{}{
		"CSRF":         r.Header.Get("X-Csrf-Token"),
		"Active":       "audit",
		"Entries":      entries,
		"AgentFilter":  agentFilter,
		"StatusFilter": statusFilter,
		"Limit":        limit,
	})
}

func (h *Handler) handleRoles(w http.ResponseWriter, r *http.Request) {
	// Build ordered role list
	type roleDisplay struct {
		Name   string
		Config config.RoleConfig
	}
	var roles []roleDisplay
	for name, cfg := range h.deps.SessionRoles {
		roles = append(roles, roleDisplay{Name: name, Config: cfg})
	}
	sort.Slice(roles, func(i, j int) bool {
		return roles[i].Name < roles[j].Name
	})

	h.render(w, "roles.html", map[string]interface{}{
		"CSRF":   r.Header.Get("X-Csrf-Token"),
		"Active": "roles",
		"Roles":  roles,
	})
}

// --- Rendering ---

func (h *Handler) render(w http.ResponseWriter, name string, data map[string]interface{}) {
	// Count pending approvals for nav badge
	if h.deps.Approvals != nil {
		data["PendingCount"] = len(h.deps.Approvals.ListPending())
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("dashboard: template error: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// --- Helpers ---

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format("2006-01-02 15:04:05 UTC")
}

func fmtAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
	}
}

func ttlRemain(t time.Time) string {
	d := time.Until(t)
	if d <= 0 {
		return "expired"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}

func sessionTTL(maxTTL string) time.Duration {
	if maxTTL == "" {
		return 0
	}
	d, err := time.ParseDuration(maxTTL)
	if err != nil {
		return 0
	}
	return d
}

func extractClientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.SplitN(fwd, ",", 2)[0]
	}
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}

func escapeFlash(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, " ", "+"), "&", "%26")
}

// isTLS returns true if the request arrived over TLS (direct or via reverse proxy).
func isTLS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
