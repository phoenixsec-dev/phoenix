// Package api implements the Phoenix REST API server.
package api

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"git.home/vector/phoenix/internal/acl"
	"git.home/vector/phoenix/internal/audit"
	"git.home/vector/phoenix/internal/ca"
	"git.home/vector/phoenix/internal/crypto"
	"git.home/vector/phoenix/internal/nonce"
	"git.home/vector/phoenix/internal/policy"
	"git.home/vector/phoenix/internal/ref"
	"git.home/vector/phoenix/internal/store"
	"git.home/vector/phoenix/internal/token"
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
	ca            *ca.CA            // nil when mTLS is disabled
	policy        *policy.Engine    // nil when no attestation policy configured
	bearerEnabled bool              // whether bearer token auth is allowed
	nonces        *nonce.Store      // nil when nonce challenge is not configured
	tokens        *token.Issuer     // nil when short-lived tokens are not configured
	startTime     time.Time         // server start time for uptime reporting
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
		startTime:     time.Now(),
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

// SetPolicy configures the attestation policy engine.
// When set, secret access is subject to attestation requirements
// (source IP binding, cert fingerprint pinning, mTLS enforcement)
// in addition to ACL checks.
func (s *Server) SetPolicy(p *policy.Engine) {
	s.policy = p
}

// SetNonceStore configures the nonce store for challenge-response flows.
func (s *Server) SetNonceStore(ns *nonce.Store) {
	s.nonces = ns
}

// SetTokenIssuer configures the short-lived token issuer.
func (s *Server) SetTokenIssuer(ti *token.Issuer) {
	s.tokens = ti
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
	s.mux.HandleFunc("POST /v1/certs/revoke", s.handleRevokeCert)
	s.mux.HandleFunc("POST /v1/rotate-master", s.handleRotateMaster)
	s.mux.HandleFunc("POST /v1/resolve", s.handleResolve)
	s.mux.HandleFunc("POST /v1/challenge", s.handleChallenge)
	s.mux.HandleFunc("GET /v1/status", s.handleStatus)
	s.mux.HandleFunc("POST /v1/token/mint", s.handleMintToken)
}

// authInfo contains authentication result and attestation evidence.
type authInfo struct {
	Agent           string
	UsedMTLS        bool
	UsedBearer      bool
	CertFingerprint string // "sha256:<hex>" or empty
}

// authenticate identifies the calling agent from the request.
// It tries mTLS client certificate first (if CA is configured and client
// presented a cert), then falls back to bearer token authentication.
// Both paths are gated by their respective feature flags.
// Returns the agent name or an error.
func (s *Server) authenticate(r *http.Request) (string, error) {
	info, err := s.authenticateInfo(r)
	if err != nil {
		return "", err
	}
	return info.Agent, nil
}

// authenticateInfo identifies the calling agent and collects attestation
// evidence from the request (auth method, cert fingerprint, etc.).
func (s *Server) authenticateInfo(r *http.Request) (*authInfo, error) {
	// Try mTLS first: check for verified client certificate
	if s.ca != nil && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		agentName, err := s.ca.VerifyClientCert(r.TLS.PeerCertificates)
		if err == nil {
			fp := certFingerprint(r.TLS.PeerCertificates[0].Raw)
			return &authInfo{
				Agent:           agentName,
				UsedMTLS:        true,
				CertFingerprint: fp,
			}, nil
		}
		// mTLS verification failed — log but fall through to bearer
		log.Printf("mTLS auth failed for %s: %v", clientIP(r), err)
	}

	// Fall back to bearer token if enabled
	if !s.bearerEnabled {
		return nil, fmt.Errorf("no valid authentication credentials provided")
	}
	token := extractToken(r)
	if token == "" {
		return nil, fmt.Errorf("no authentication credentials provided")
	}
	agent, err := s.acl.Authenticate(token)
	if err != nil {
		return nil, err
	}
	return &authInfo{
		Agent:      agent,
		UsedBearer: true,
	}, nil
}

// certFingerprint computes "sha256:<hex>" from raw DER certificate bytes.
func certFingerprint(raw []byte) string {
	hash := sha256.Sum256(raw)
	return fmt.Sprintf("sha256:%X", hash[:])
}

// attest checks attestation policy for the given secret path.
// Returns nil if no policy is configured or if the request passes.
func (s *Server) attest(r *http.Request, path string, info *authInfo) error {
	if s.policy == nil {
		return nil
	}
	ctx := &policy.RequestContext{
		UsedMTLS:        info.UsedMTLS,
		UsedBearer:      info.UsedBearer,
		SourceIP:        clientIP(r),
		CertFingerprint: info.CertFingerprint,
	}
	return s.policy.Evaluate(path, ctx)
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
	info, err := s.authenticateInfo(r)
	if err != nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	agentName := info.Agent

	path := secretPath(r)
	ip := clientIP(r)

	// List mode: path is empty or ends with /
	if path == "" || strings.HasSuffix(path, "/") {
		allPaths := s.store.List(path)
		var visible []string
		for _, p := range allPaths {
			if s.acl.Authorize(agentName, p, acl.ActionRead) != nil {
				continue
			}
			// Attestation check: hide paths the caller can't attest for
			if s.attest(r, p, info) != nil {
				continue
			}
			visible = append(visible, p)
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

	// Attestation policy check
	if err := s.attest(r, path, info); err != nil {
		s.audit.LogDenied(agentName, "read", path, ip, "attestation")
		jsonError(w, "attestation required: "+err.Error(), http.StatusForbidden)
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
	info, err := s.authenticateInfo(r)
	if err != nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	agentName := info.Agent

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
			s.audit.LogDenied(agentName, "resolve", refStr, ip, "malformed_ref")
			errors[refStr] = err.Error()
			continue
		}

		if err := s.acl.Authorize(agentName, path, acl.ActionRead); err != nil {
			s.audit.LogDenied(agentName, "resolve", path, ip, "acl")
			errors[refStr] = "access denied"
			continue
		}

		// Attestation policy check (per-ref)
		if err := s.attest(r, path, info); err != nil {
			s.audit.LogDenied(agentName, "resolve", path, ip, "attestation")
			errors[refStr] = "attestation required"
			continue
		}

		secret, err := s.store.Get(path)
		if err != nil {
			if err == store.ErrSecretNotFound {
				s.audit.LogDenied(agentName, "resolve", path, ip, "not_found")
				errors[refStr] = "secret not found"
			} else if err == store.ErrInvalidPath {
				s.audit.LogDenied(agentName, "resolve", path, ip, "invalid_path")
				errors[refStr] = "invalid path"
			} else {
				s.audit.LogDenied(agentName, "resolve", path, ip, "internal_error")
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

// handleChallenge issues a one-time nonce for challenge-response attestation.
func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if s.nonces == nil {
		jsonError(w, "nonce challenge not enabled", http.StatusNotImplemented)
		return
	}

	// Authentication required to get a challenge
	_, err := s.authenticate(r)
	if err != nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	entry, err := s.nonces.Generate()
	if err != nil {
		log.Printf("error generating nonce: %v", err)
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	jsonOK(w, map[string]interface{}{
		"nonce":   entry.Nonce,
		"expires": entry.Expires.UTC().Format(time.RFC3339),
	})
}

// revokeCertRequest is the JSON body for certificate revocation.
type revokeCertRequest struct {
	SerialNumber string `json:"serial_number"`
	AgentName    string `json:"agent_name"`
}

// handleRevokeCert revokes a certificate by serial number.
func (s *Server) handleRevokeCert(w http.ResponseWriter, r *http.Request) {
	if s.ca == nil {
		jsonError(w, "mTLS is not enabled", http.StatusNotImplemented)
		return
	}

	agentName, err := s.authenticate(r)
	if err != nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Only admin agents can revoke certificates
	if err := s.acl.Authorize(agentName, "certs", acl.ActionAdmin); err != nil {
		jsonError(w, "access denied: admin required", http.StatusForbidden)
		return
	}

	var req revokeCertRequest
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.SerialNumber == "" {
		jsonError(w, "serial_number is required", http.StatusBadRequest)
		return
	}

	serial := new(big.Int)
	if _, ok := serial.SetString(req.SerialNumber, 10); !ok {
		jsonError(w, "invalid serial_number format", http.StatusBadRequest)
		return
	}

	revokeAgent := req.AgentName
	if revokeAgent == "" {
		revokeAgent = "unknown"
	}

	if err := s.ca.RevokeCert(serial, revokeAgent); err != nil {
		log.Printf("error revoking cert serial %s: %v", req.SerialNumber, err)
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.audit.LogAllowed(agentName, "revoke-cert", req.SerialNumber, clientIP(r))
	jsonOK(w, map[string]string{
		"status":        "ok",
		"serial_number": req.SerialNumber,
		"agent_name":    revokeAgent,
	})
}

// handleStatus returns a comprehensive server status overview.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	agentName, err := s.authenticate(r)
	if err != nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Only admin agents can view full status
	if err := s.acl.Authorize(agentName, "status", acl.ActionAdmin); err != nil {
		jsonError(w, "access denied: admin required", http.StatusForbidden)
		return
	}

	uptime := time.Since(s.startTime).Round(time.Second)

	status := map[string]interface{}{
		"status":  "ok",
		"uptime":  uptime.String(),
		"secrets": s.store.Count(),
		"agents":  len(s.acl.ListAgents()),
		"time":    time.Now().UTC().Format(time.RFC3339),
	}

	// Policy summary
	if s.policy != nil {
		rules := s.policy.Rules()
		policySummary := make(map[string]interface{}, len(rules))
		for pattern, rule := range rules {
			var checks []string
			if rule.RequireMTLS {
				checks = append(checks, "mTLS")
			}
			if rule.DenyBearer {
				checks = append(checks, "deny-bearer")
			}
			if len(rule.AllowedIPs) > 0 {
				checks = append(checks, "IP-bound")
			}
			if rule.CertFingerprint != "" {
				checks = append(checks, "cert-pinned")
			}
			if len(rule.AllowedTools) > 0 {
				checks = append(checks, "tool-scoped")
			}
			if rule.TimeWindow != "" {
				checks = append(checks, "time-window")
			}
			if rule.Process != nil {
				checks = append(checks, "process-attested")
			}
			if rule.RequireNonce {
				checks = append(checks, "nonce-required")
			}
			if rule.RequireFreshAttestation {
				checks = append(checks, "fresh-credential")
			}
			policySummary[pattern] = strings.Join(checks, " + ")
		}
		status["policy_rules"] = len(rules)
		status["policy"] = policySummary
	}

	// CA status
	if s.ca != nil {
		status["mtls"] = "enabled"
	} else {
		status["mtls"] = "disabled"
	}

	// Nonce store status
	if s.nonces != nil {
		status["nonce_pending"] = s.nonces.Pending()
	}

	// Recent audit
	entries, err := audit.Query(s.auditPath, audit.QueryOptions{Limit: 5})
	if err == nil && len(entries) > 0 {
		status["recent_audit"] = entries
	}

	jsonOK(w, status)
}

// mintTokenRequest is the JSON body for token minting.
type mintTokenRequest struct {
	Agent string `json:"agent"`
}

// handleMintToken creates a short-lived token for an agent.
func (s *Server) handleMintToken(w http.ResponseWriter, r *http.Request) {
	if s.tokens == nil {
		jsonError(w, "short-lived tokens not enabled", http.StatusNotImplemented)
		return
	}

	agentName, err := s.authenticate(r)
	if err != nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Only admin agents can mint tokens for other agents
	if err := s.acl.Authorize(agentName, "tokens", acl.ActionAdmin); err != nil {
		jsonError(w, "access denied: admin required", http.StatusForbidden)
		return
	}

	var req mintTokenRequest
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Agent == "" {
		jsonError(w, "agent is required", http.StatusBadRequest)
		return
	}

	tok, claims, err := s.tokens.Mint(req.Agent, nil, "")
	if err != nil {
		log.Printf("error minting token for %q: %v", req.Agent, err)
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.audit.LogAllowed(agentName, "mint-token", req.Agent, clientIP(r))
	jsonOK(w, map[string]interface{}{
		"token":      tok,
		"agent":      claims.Agent,
		"issued_at":  claims.IssuedAt.Format(time.RFC3339),
		"expires_at": claims.ExpiresAt.Format(time.RFC3339),
		"ttl":        s.tokens.TTL().String(),
	})
}
