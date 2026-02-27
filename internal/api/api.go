// Package api implements the Phoenix REST API server.
package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"git.home/vector/phoenix/internal/acl"
	"git.home/vector/phoenix/internal/audit"
	"git.home/vector/phoenix/internal/ca"
	"git.home/vector/phoenix/internal/crypto"
	"git.home/vector/phoenix/internal/ref"
	"git.home/vector/phoenix/internal/store"
)

// MaxRequestBodyBytes limits the size of request bodies to prevent DoS.
const MaxRequestBodyBytes = 1 << 20 // 1 MB

// Server is the Phoenix HTTP API server.
type Server struct {
	store         *store.Store
	acl           *acl.ACL
	audit         *audit.Logger
	auditPath     string
	masterKeyPath string // path to master.key file (needed for KEK rotation)
	ca            *ca.CA // nil when mTLS is disabled
	bearerEnabled bool   // whether bearer token auth is allowed
	mux           *http.ServeMux
}

// NewServer creates a new API server with all dependencies.
// Bearer auth is enabled by default.
func NewServer(s *store.Store, a *acl.ACL, al *audit.Logger, auditPath string) *Server {
	srv := &Server{
		store:         s,
		acl:           a,
		audit:         al,
		auditPath:     auditPath,
		bearerEnabled: true,
		mux:           http.NewServeMux(),
	}
	srv.routes()
	return srv
}

// SetCA configures the CA for mTLS authentication.
// When set, the server will accept client certificates as an alternative
// to bearer tokens. The certificate CN is used as the agent identity.
func (s *Server) SetCA(c *ca.CA) {
	s.ca = c
}

// SetBearerEnabled controls whether bearer token authentication is allowed.
func (s *Server) SetBearerEnabled(enabled bool) {
	s.bearerEnabled = enabled
}

// SetMasterKeyPath sets the path to the master key file.
// Required for the rotate-master endpoint to persist the new key.
func (s *Server) SetMasterKeyPath(path string) {
	s.masterKeyPath = path
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
	s.mux.HandleFunc("POST /v1/certs/issue", s.handleIssueCert)
	s.mux.HandleFunc("POST /v1/rotate-master", s.handleRotateMaster)
	s.mux.HandleFunc("POST /v1/resolve", s.handleResolve)
}

// authenticate identifies the calling agent from the request.
// It tries mTLS client certificate first (if CA is configured and client
// presented a cert), then falls back to bearer token authentication.
// Both paths are gated by their respective feature flags.
// Returns the agent name or an error.
func (s *Server) authenticate(r *http.Request) (string, error) {
	// Try mTLS first: check for verified client certificate
	if s.ca != nil && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		agentName, err := s.ca.VerifyClientCert(r.TLS.PeerCertificates)
		if err == nil {
			return agentName, nil
		}
		// mTLS verification failed — log but fall through to bearer
		log.Printf("mTLS auth failed for %s: %v", clientIP(r), err)
	}

	// Fall back to bearer token if enabled
	if !s.bearerEnabled {
		return "", fmt.Errorf("no valid authentication credentials provided")
	}
	token := extractToken(r)
	if token == "" {
		return "", fmt.Errorf("no authentication credentials provided")
	}
	return s.acl.Authenticate(token)
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
// X-Forwarded-For is intentionally ignored — Phoenix is not behind a
// reverse proxy, and trusting XFF allows audit log IP spoofing.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
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
	agentName, err := s.authenticate(r)
	if err != nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
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
	agentName, err := s.authenticate(r)
	if err != nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
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
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
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
	agentName, err := s.authenticate(r)
	if err != nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
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
	agentName, err := s.authenticate(r)
	if err != nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
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
	agentName, err := s.authenticate(r)
	if err != nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Only admin agents can create other agents
	if err := s.acl.Authorize(agentName, "agents", acl.ActionAdmin); err != nil {
		jsonError(w, "access denied: admin required", http.StatusForbidden)
		return
	}

	var req createAgentRequest
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
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
	agentName, err := s.authenticate(r)
	if err != nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err := s.acl.Authorize(agentName, "agents", acl.ActionAdmin); err != nil {
		jsonError(w, "access denied: admin required", http.StatusForbidden)
		return
	}

	names := s.acl.ListAgents()
	jsonOK(w, map[string]interface{}{"agents": names})
}

// issueCertRequest is the JSON body for certificate issuance.
type issueCertRequest struct {
	AgentName string `json:"agent_name"`
}

func (s *Server) handleIssueCert(w http.ResponseWriter, r *http.Request) {
	if s.ca == nil {
		jsonError(w, "mTLS is not enabled", http.StatusNotImplemented)
		return
	}

	agentName, err := s.authenticate(r)
	if err != nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Only admin agents can issue certificates
	if err := s.acl.Authorize(agentName, "certs", acl.ActionAdmin); err != nil {
		jsonError(w, "access denied: admin required", http.StatusForbidden)
		return
	}

	var req issueCertRequest
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.AgentName == "" {
		jsonError(w, "agent_name is required", http.StatusBadRequest)
		return
	}

	bundle, err := s.ca.IssueAgentCert(req.AgentName)
	if err != nil {
		log.Printf("error issuing cert for %q: %v", req.AgentName, err)
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.audit.LogAllowed(agentName, "issue-cert", req.AgentName, clientIP(r))
	jsonOK(w, map[string]interface{}{
		"status":  "ok",
		"agent":   req.AgentName,
		"cert":    string(bundle.CertPEM),
		"key":     string(bundle.KeyPEM),
		"ca_cert": string(bundle.CACert),
	})
}

func (s *Server) handleRotateMaster(w http.ResponseWriter, r *http.Request) {
	agentName, err := s.authenticate(r)
	if err != nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Only admin agents can rotate the master key
	if err := s.acl.Authorize(agentName, "master-key", acl.ActionAdmin); err != nil {
		jsonError(w, "access denied: admin required", http.StatusForbidden)
		return
	}

	ip := clientIP(r)

	if s.masterKeyPath == "" {
		jsonError(w, "master key path not configured", http.StatusInternalServerError)
		return
	}

	// Verify provider is FileKeyProvider before we start
	provider, ok := s.store.Provider().(*crypto.FileKeyProvider)
	if !ok {
		log.Printf("rotation not supported: provider is %T, not FileKeyProvider", s.store.Provider())
		jsonError(w, "rotation not supported for this provider type", http.StatusInternalServerError)
		return
	}

	// Backup the old master key as .prev
	oldKey, err := os.ReadFile(s.masterKeyPath)
	if err != nil {
		log.Printf("error reading old master key: %v", err)
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	prevPath := s.masterKeyPath + ".prev"
	if err := os.WriteFile(prevPath, oldKey, 0600); err != nil {
		log.Printf("error backing up master key to %s: %v", prevPath, err)
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Rotate with afterSave callback: the callback writes the new key file
	// atomically while the store lock is held, preventing any window where
	// the store has new DEKs but the key file still has the old key.
	rotated, err := s.store.RotateMasterKey(func() error {
		pendingKey := provider.PendingMasterKey()
		if pendingKey == nil {
			return fmt.Errorf("no pending key after rotation")
		}
		return crypto.SaveMasterKeyAtomic(s.masterKeyPath, pendingKey)
	})
	if err != nil {
		log.Printf("error rotating master key: %v", err)
		jsonError(w, "rotation failed", http.StatusInternalServerError)
		return
	}

	s.audit.LogAllowed(agentName, "rotate-master", fmt.Sprintf("%d namespaces", rotated), ip)
	log.Printf("master key rotated by %s: %d namespaces re-wrapped", agentName, rotated)

	jsonOK(w, map[string]interface{}{
		"status":  "ok",
		"rotated": rotated,
		"backup":  prevPath,
	})
}

// resolveRequest is the JSON body for batch reference resolution.
type resolveRequest struct {
	Refs []string `json:"refs"`
}

func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	agentName, err := s.authenticate(r)
	if err != nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ip := clientIP(r)

	var req resolveRequest
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if len(req.Refs) == 0 {
		jsonError(w, "refs is required and must not be empty", http.StatusBadRequest)
		return
	}

	values := make(map[string]string)
	errors := make(map[string]string)

	for _, refStr := range req.Refs {
		path, err := ref.Parse(refStr)
		if err != nil {
			errors[refStr] = err.Error()
			continue
		}

		if err := s.acl.Authorize(agentName, path, acl.ActionRead); err != nil {
			s.audit.LogDenied(agentName, "resolve", path, ip, "acl")
			errors[refStr] = "access denied"
			continue
		}

		secret, err := s.store.Get(path)
		if err != nil {
			if err == store.ErrSecretNotFound {
				errors[refStr] = "secret not found"
			} else if err == store.ErrInvalidPath {
				errors[refStr] = "invalid path"
			} else {
				log.Printf("error resolving %q for %s: %v", path, agentName, err)
				errors[refStr] = "internal error"
			}
			continue
		}

		s.audit.LogAllowed(agentName, "resolve", path, ip)
		values[refStr] = secret.Value
	}

	resp := map[string]interface{}{
		"values": values,
	}
	if len(errors) > 0 {
		resp["errors"] = errors
	}
	jsonOK(w, resp)
}
