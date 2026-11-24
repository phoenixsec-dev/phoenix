package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
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
func (l dashLogin) recent(now time.Time) bool {
	return now.Before(l.authAt.Add(recentAuthWindow))
}

// signedIn reports whether the login with this ID is still signed in. Unlike
// valid it survives the cookie moving to a new nonce.
func (lt *loginTable) signedIn(id string, now time.Time) bool {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	for _, l := range lt.byNonce {
		if l.ID == id {
			return now.Before(l.Expires)
		}
	}
	return false
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

// loginKey is the request context key of the login requireRecent admitted.
type loginKey struct{}

// requireRecent lets a request through only within the window after the
// password was typed. Otherwise it answers 401 with reauth set, and the page
// asks for the password and tries again. The login goes along in the request
// context, so whatever happens to it meanwhile, the audit line names it.
func (h *Handler) requireRecent(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		l, ok := h.currentLogin(r)
		if !ok || !l.recent(time.Now()) {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": "Type your password again.", "reauth": true})
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), loginKey{}, l)))
	}
}

// requestLogin is the login requireRecent admitted this request for.
func requestLogin(r *http.Request) (dashLogin, bool) {
	l, ok := r.Context().Value(loginKey{}).(dashLogin)
	return l, ok
}

// sameOrigin reports whether a POST came from the dashboard's own pages. It
// backs up the CSRF token, and SameSite=Strict, which lets sibling subdomains
// through. Browsers too old to say so with Sec-Fetch-Site still send Origin.
// A client that sends neither is not a browser another site can drive.
func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin"
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host != "" && strings.EqualFold(u.Host, r.Host)
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
	keys := []string{ip, "login:" + login.ID}
	meta := map[string]string{"dashboard.login": login.ID}

	if err := h.loginRL.admit(keys...); err != nil {
		if h.deps.Audit != nil {
			h.deps.Audit.LogDeniedWithMetadata("dashboard@"+ip, "dashboard.reauth", "rate_limited", ip, err.Error(), meta)
		}
		writeError(w, http.StatusTooManyRequests, "Too many wrong passwords. Wait a minute and try again.")
		return
	}
	if !h.checkCredential(r.PostFormValue("password")) {
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
	h.loginRL.recordSuccess(keys...)
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
