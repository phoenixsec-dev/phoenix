package dashboard

import (
	"encoding/json"
	"net/http"
	"time"
)

// Recent sign-in. Showing, copying or changing a secret needs the password to
// have been typed in this browser within the last recentAuthWindow, not just a
// valid cookie. The window is fixed: using it does not extend it.

// recentAuthWindow is how long typing the password (at login, or when asked
// again) unlocks secret values and changes.
const recentAuthWindow = 5 * time.Minute

// find returns a copy of the login with this cookie nonce.
func (lt *loginTable) find(nonce string) (dashLogin, bool) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	l, ok := lt.byNonce[nonce]
	if !ok {
		return dashLogin{}, false
	}
	return *l, true
}

// recent reports whether the password was typed for this login within the
// window.
func (lt *loginTable) recent(nonce string, now time.Time) bool {
	l, ok := lt.find(nonce)
	return ok && now.Before(l.authAt.Add(recentAuthWindow))
}

// reauthenticate records that the password was typed again for a login and
// moves the login to a new cookie nonce, so a copy of the old cookie stops
// working instead of sharing the new window. False if the login has ended.
func (lt *loginTable) reauthenticate(oldNonce, newNonce string, now time.Time) bool {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	l, ok := lt.byNonce[oldNonce]
	if !ok || !now.Before(l.Expires) {
		return false
	}
	delete(lt.byNonce, oldNonce)
	l.nonce, l.authAt = newNonce, now
	lt.byNonce[newNonce] = l
	return true
}

// currentLogin returns the login behind an authenticated request.
func (h *Handler) currentLogin(r *http.Request) (dashLogin, bool) {
	p, err := h.verifyCookie(r)
	if err != nil {
		return dashLogin{}, false
	}
	return h.logins.find(p.Nonce)
}

// requireRecent lets a request through only within the window after the
// password was typed. Otherwise it answers 401 with reauth set, and the page
// asks for the password and tries again.
func (h *Handler) requireRecent(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := h.verifyCookie(r)
		if err != nil || !h.logins.recent(p.Nonce, time.Now()) {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": "Type your password again.", "reauth": true})
			return
		}
		next(w, r)
	}
}

// requireSameOrigin refuses a request a browser says came from another site.
// It backs up the CSRF token, and SameSite=Strict, which lets sibling
// subdomains through.
func (h *Handler) requireSameOrigin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
			if h.deps.Audit != nil {
				h.deps.Audit.LogDenied("dashboard", "dashboard.csrf", r.URL.Path, extractClientIP(r), "cross_site_request")
			}
			writeError(w, http.StatusForbidden, "This request came from another site.")
			return
		}
		next(w, r)
	}
}

// handleReauth: POST /dashboard/reauth with "password". It takes the same
// password as login and counts failures in the same limiter, both per address
// and per login, so a stolen cookie cannot guess from many addresses. One at a
// time: parallel guesses cannot all get in before the first failure counts.
func (h *Handler) handleReauth(w http.ResponseWriter, r *http.Request) {
	ip := extractClientIP(r)
	p, err := h.verifyCookie(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "You are signed out.")
		return
	}
	login, ok := h.logins.find(p.Nonce)
	if !ok {
		writeError(w, http.StatusUnauthorized, "You are signed out.")
		return
	}
	loginKey := "login:" + login.ID
	meta := map[string]string{"dashboard.login": login.ID}

	h.reauthMu.Lock()
	defer h.reauthMu.Unlock()
	for _, key := range []string{ip, loginKey} {
		if err := h.loginRL.check(key); err != nil {
			if h.deps.Audit != nil {
				h.deps.Audit.LogDeniedWithMetadata("dashboard@"+ip, "dashboard.reauth", "rate_limited", ip, err.Error(), meta)
			}
			writeError(w, http.StatusTooManyRequests, "Too many wrong passwords. Wait a minute and try again.")
			return
		}
	}
	if !h.checkCredential(r.PostFormValue("password")) {
		h.loginRL.recordFailure(ip)
		h.loginRL.recordFailure(loginKey)
		if h.deps.Audit != nil {
			h.deps.Audit.LogDeniedWithMetadata("dashboard@"+ip, "dashboard.reauth", "login", ip, "invalid_credentials", meta)
		}
		writeError(w, http.StatusForbidden, "Wrong password.")
		return
	}

	// The CSRF token stays, so forms already open in other tabs still work.
	now := time.Now()
	next := *p
	next.Nonce = randomHex(16)
	cookie, err := h.signCookie(next)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Something went wrong.")
		return
	}
	if !h.logins.reauthenticate(p.Nonce, next.Nonce, now) {
		writeError(w, http.StatusUnauthorized, "You are signed out.")
		return
	}
	h.loginRL.recordSuccess(ip)
	h.loginRL.recordSuccess(loginKey)
	h.setLoginCookie(w, r, cookie, time.Until(time.Unix(p.Exp, 0)))
	if h.deps.Audit != nil {
		h.deps.Audit.LogAllowedWithMetadata("dashboard@"+ip, "dashboard.reauth", "login", ip, meta)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

// writeJSON sends a JSON reply that nothing may store.
func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// writeError sends {"error": msg}; msg is shown to the person as is.
func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]interface{}{"error": msg})
}
