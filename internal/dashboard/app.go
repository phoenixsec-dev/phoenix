package dashboard

import (
	"net/http"
	"strings"
)

// The installable app (manifest, service worker) and the headers every
// dashboard response carries.

// contentSecurityPolicy allows only the dashboard's own files and no framing.
// Scripts must be files under /dashboard/static/; an inline one will not run.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; " +
	"img-src 'self'; connect-src 'self'; manifest-src 'self'; worker-src 'self'; " +
	"form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

// setSecurityHeaders sets the headers for every dashboard response: no
// framing, no foreign scripts, no caching of anything but static files.
func setSecurityHeaders(w http.ResponseWriter, r *http.Request) {
	hd := w.Header()
	hd.Set("Content-Security-Policy", contentSecurityPolicy)
	hd.Set("X-Frame-Options", "DENY")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Referrer-Policy", "same-origin")
	hd.Set("Cross-Origin-Opener-Policy", "same-origin")
	hd.Set("Cross-Origin-Resource-Policy", "same-origin")
	if strings.HasPrefix(r.URL.Path, "/dashboard/static/") || r.URL.Path == "/dashboard/sw.js" {
		hd.Set("Cache-Control", "no-cache") // kept, but checked first
	} else {
		hd.Set("Cache-Control", "no-store")
	}
}

// appRoutes registers the service worker. It is served from /dashboard/, not
// /dashboard/static/, because a worker only covers pages under its own path.
func (h *Handler) appRoutes() {
	h.mux.HandleFunc("GET /dashboard/sw.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, staticFS, "static/sw.js")
	})
}

// handleMore: GET /dashboard/more, the pages that do not fit a phone's bar.
func (h *Handler) handleMore(w http.ResponseWriter, r *http.Request) {
	h.render(w, "more.html", map[string]interface{}{
		"CSRF":   r.Header.Get("X-Csrf-Token"),
		"Active": "more",
	})
}
