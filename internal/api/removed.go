package api

import "net/http"

// removedRoutes are API routes Phoenix no longer has. They answer 410 Gone
// with the reason, so an old client or script learns what happened instead
// of getting a bare 404. No authentication: the answer reveals nothing.
var removedRoutes = map[string]string{
	"POST /v1/token/mint":   "short-lived tokens were removed: the server trusted whatever process details the caller sent. Use a role session (POST /v1/session/mint)",
	"POST /v1/challenge":    "nonce challenges were removed: only signed resolve with a client certificate could ever pass them",
	"POST /v1/certs/issue":  "client certificates (mTLS) were removed. Agents log in with bearer tokens over HTTPS",
	"POST /v1/certs/revoke": "client certificates (mTLS) were removed. Agents log in with bearer tokens over HTTPS",
	"POST /v1/proxy":        "the proxy endpoint was removed: it was never built and always answered 501",
	"GET /v1/approvals":     "step-up approvals were removed. Use access requests (GET /v1/access-requests)",
	"/v1/approval/":         "step-up approvals were removed. Use access requests (/v1/access-requests/{id})",
}

// removedRouteRoutes registers the 410 handlers for removedRoutes.
func (s *Server) removedRouteRoutes() {
	for pattern, msg := range removedRoutes {
		s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			jsonError(w, msg, http.StatusGone)
		})
	}
}
