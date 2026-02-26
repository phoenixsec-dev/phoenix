// Package api implements the Phoenix REST API server.
package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"git.home/vector/phoenix/internal/acl"
	"git.home/vector/phoenix/internal/audit"
	"git.home/vector/phoenix/internal/store"
)

// Server is the Phoenix HTTP API server.
type Server struct {
	store    *store.Store
	acl      *acl.ACL
	audit    *audit.Logger
	auditPath string
	mux      *http.ServeMux
}

// NewServer creates a new API server with all dependencies.
func NewServer(s *store.Store, a *acl.ACL, al *audit.Logger, auditPath string) *Server {
	srv := &Server{
		store:     s,
		acl:       a,
		audit:     al,
		auditPath: auditPath,
		mux:       http.NewServeMux(),
	}
	srv.routes()
	return srv
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /v1/health", s.handleHealth)
	s.mux.HandleFunc("GET /v1/secrets/", s.handleGetSecret)
	s.mux.HandleFunc("PUT /v1/secrets/", s.handleSetSecret)
	s.mux.HandleFunc("DELETE /v1/secrets/", s.handleDeleteSecret)
	s.mux.HandleFunc("GET /v1/audit", s.handleAuditQuery)
	s.mux.HandleFunc("POST /v1/agents", s.handleCreateAgent)
	s.mux.HandleFunc("GET /v1/agents", s.handleListAgents)
}

// extractToken gets the bearer token from the Authorization header.
func extractToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

// clientIP extracts the client IP from the request.
func clientIP(r *http.Request) string {
	// Check X-Forwarded-For for proxy setups
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	// Strip port from RemoteAddr
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// secretPath extracts the secret path from the URL.
func secretPath(r *http.Request) string {
	return strings.TrimPrefix(r.URL.Path, "/v1/secrets/")
}

// jsonError sends a JSON error response.
func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// jsonOK sends a JSON success response.
func jsonOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]interface{}{
		"status":  "ok",
		"secrets": s.store.Count(),
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token == "" {
		jsonError(w, "missing authorization token", http.StatusUnauthorized)
		return
	}

	agentName, err := s.acl.Authenticate(token)
	if err != nil {
		jsonError(w, "invalid token", http.StatusUnauthorized)
		return
	}

	path := secretPath(r)
	ip := clientIP(r)

	// List mode: path is empty or ends with /
	if path == "" || strings.HasSuffix(path, "/") {
		allPaths := s.store.List(path)
		var visible []string
		for _, p := range allPaths {
			if s.acl.Authorize(agentName, p, acl.ActionRead) == nil {
				visible = append(visible, p)
			}
		}
		s.audit.LogAllowed(agentName, "list", path, ip)
		jsonOK(w, map[string]interface{}{"paths": visible})
		return
	}

	// Single secret read
	if err := s.acl.Authorize(agentName, path, acl.ActionRead); err != nil {
		s.audit.LogDenied(agentName, "read", path, ip, "acl")
		jsonError(w, "access denied", http.StatusForbidden)
		return
	}

	secret, err := s.store.Get(path)
	if err == store.ErrInvalidPath {
		jsonError(w, "invalid secret path", http.StatusBadRequest)
		return
	}
	if err == store.ErrSecretNotFound {
		jsonError(w, "secret not found", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("error reading secret %q: %v", path, err)
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.audit.LogAllowed(agentName, "read", path, ip)
	jsonOK(w, secret)
}

// setSecretRequest is the JSON body for creating/updating secrets.
type setSecretRequest struct {
	Value       string   `json:"value"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

func (s *Server) handleSetSecret(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token == "" {
		jsonError(w, "missing authorization token", http.StatusUnauthorized)
		return
	}

	agentName, err := s.acl.Authenticate(token)
	if err != nil {
		jsonError(w, "invalid token", http.StatusUnauthorized)
		return
	}

	path := secretPath(r)
	ip := clientIP(r)

	if err := s.acl.Authorize(agentName, path, acl.ActionWrite); err != nil {
		s.audit.LogDenied(agentName, "write", path, ip, "acl")
		jsonError(w, "access denied", http.StatusForbidden)
		return
	}

	var req setSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Value == "" {
		jsonError(w, "value is required", http.StatusBadRequest)
		return
	}

	if err := s.store.Set(path, req.Value, agentName, req.Description, req.Tags); err != nil {
		if err == store.ErrInvalidPath {
			jsonError(w, "invalid secret path", http.StatusBadRequest)
			return
		}
		log.Printf("error setting secret %q: %v", path, err)
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.audit.LogAllowed(agentName, "write", path, ip)
	jsonOK(w, map[string]string{"status": "ok", "path": path})
}

func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token == "" {
		jsonError(w, "missing authorization token", http.StatusUnauthorized)
		return
	}

	agentName, err := s.acl.Authenticate(token)
	if err != nil {
		jsonError(w, "invalid token", http.StatusUnauthorized)
		return
	}

	path := secretPath(r)
	ip := clientIP(r)

	if err := s.acl.Authorize(agentName, path, acl.ActionDelete); err != nil {
		s.audit.LogDenied(agentName, "delete", path, ip, "acl")
		jsonError(w, "access denied", http.StatusForbidden)
		return
	}

	if err := s.store.Delete(path); err != nil {
		if err == store.ErrInvalidPath {
			jsonError(w, "invalid secret path", http.StatusBadRequest)
			return
		}
		if err == store.ErrSecretNotFound {
			jsonError(w, "secret not found", http.StatusNotFound)
			return
		}
		log.Printf("error deleting secret %q: %v", path, err)
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.audit.LogAllowed(agentName, "delete", path, ip)
	jsonOK(w, map[string]string{"status": "ok", "path": path})
}

func (s *Server) handleAuditQuery(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token == "" {
		jsonError(w, "missing authorization token", http.StatusUnauthorized)
		return
	}

	agentName, err := s.acl.Authenticate(token)
	if err != nil {
		jsonError(w, "invalid token", http.StatusUnauthorized)
		return
	}

	// Only admin agents can query the audit log
	if err := s.acl.Authorize(agentName, "audit", acl.ActionAdmin); err != nil {
		jsonError(w, "access denied: admin required", http.StatusForbidden)
		return
	}

	opts := audit.QueryOptions{}

	if since := r.URL.Query().Get("since"); since != "" {
		t, err := time.Parse(time.RFC3339, since)
		if err != nil {
			jsonError(w, "invalid 'since' format (use RFC3339)", http.StatusBadRequest)
			return
		}
		opts.Since = &t
	}

	if agent := r.URL.Query().Get("agent"); agent != "" {
		opts.Agent = agent
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		var limit int
		fmt.Sscanf(limitStr, "%d", &limit)
		if limit > 0 {
			opts.Limit = limit
		}
	}

	entries, err := audit.Query(s.auditPath, opts)
	if err != nil {
		log.Printf("error querying audit log: %v", err)
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	jsonOK(w, map[string]interface{}{"entries": entries})
}

// createAgentRequest is the JSON body for agent registration.
type createAgentRequest struct {
	Name        string           `json:"name"`
	Token       string           `json:"token"`
	Permissions []acl.Permission `json:"permissions"`
}

func (s *Server) handleCreateAgent(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token == "" {
		jsonError(w, "missing authorization token", http.StatusUnauthorized)
		return
	}

	agentName, err := s.acl.Authenticate(token)
	if err != nil {
		jsonError(w, "invalid token", http.StatusUnauthorized)
		return
	}

	// Only admin agents can create other agents
	if err := s.acl.Authorize(agentName, "agents", acl.ActionAdmin); err != nil {
		jsonError(w, "access denied: admin required", http.StatusForbidden)
		return
	}

	var req createAgentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name == "" || req.Token == "" {
		jsonError(w, "name and token are required", http.StatusBadRequest)
		return
	}

	if err := s.acl.AddAgent(req.Name, req.Token, req.Permissions); err != nil {
		log.Printf("error creating agent %q: %v", req.Name, err)
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.audit.LogAllowed(agentName, "create-agent", req.Name, clientIP(r))
	jsonOK(w, map[string]string{"status": "ok", "agent": req.Name})
}

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token == "" {
		jsonError(w, "missing authorization token", http.StatusUnauthorized)
		return
	}

	agentName, err := s.acl.Authenticate(token)
	if err != nil {
		jsonError(w, "invalid token", http.StatusUnauthorized)
		return
	}

	if err := s.acl.Authorize(agentName, "agents", acl.ActionAdmin); err != nil {
		jsonError(w, "access denied: admin required", http.StatusForbidden)
		return
	}

	names := s.acl.ListAgents()
	jsonOK(w, map[string]interface{}{"agents": names})
}
