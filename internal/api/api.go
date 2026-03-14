// Package api implements the Phoenix REST API server.
package api

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/audit"
	"github.com/phoenixsec/phoenix/internal/ca"
	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/crypto"
	"github.com/phoenixsec/phoenix/internal/nonce"
	"github.com/phoenixsec/phoenix/internal/policy"
	"github.com/phoenixsec/phoenix/internal/ref"
	"github.com/phoenixsec/phoenix/internal/session"
	"github.com/phoenixsec/phoenix/internal/store"
	"github.com/phoenixsec/phoenix/internal/token"
)

// MaxRequestBodyBytes limits the size of request bodies to prevent DoS.
const MaxRequestBodyBytes = 1 << 20 // 1 MB

// Rate limiting constants for authentication attempts.
const (
	rateLimitMaxFailures = 5
	rateLimitBaseDelay   = 1 * time.Second
	rateLimitMaxDelay    = 60 * time.Second
	rateLimitCleanupAge  = 10 * time.Minute
)

type rateLimitEntry struct {
	failures  int
	blockedAt time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	entries map[string]*rateLimitEntry
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{entries: make(map[string]*rateLimitEntry)}
}

func (rl *rateLimiter) check(ip string) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e, ok := rl.entries[ip]
	if !ok || e.failures < rateLimitMaxFailures {
		return nil
	}
	exp := e.failures - rateLimitMaxFailures
	if exp > 6 { // cap at 2^6 = 64s, prevents overflow
		exp = 6
	}
	delay := rateLimitBaseDelay * (1 << exp)
	if delay > rateLimitMaxDelay {
		delay = rateLimitMaxDelay
	}
	if time.Since(e.blockedAt) < delay {
		return fmt.Errorf("too many authentication failures, retry later")
	}
	return nil
}

func (rl *rateLimiter) recordFailure(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e, ok := rl.entries[ip]
	if !ok {
		e = &rateLimitEntry{}
		rl.entries[ip] = e
	}
	e.failures++
	e.blockedAt = time.Now()
}

func (rl *rateLimiter) recordSuccess(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.entries, ip)
}

func (rl *rateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-rateLimitCleanupAge)
	for ip, e := range rl.entries {
		if e.blockedAt.Before(cutoff) {
			delete(rl.entries, ip)
		}
	}
}

// Server is the Phoenix HTTP API server.
type Server struct {
	backend       store.SecretBackend
	fileBackend   *store.FileBackend // non-nil only for file backend (rotation needs it)
	acl           *acl.ACL
	audit         *audit.Logger
	auditPath     string
	masterKeyPath string         // path to master.key file (needed for KEK rotation)
	ca            *ca.CA         // nil when mTLS is disabled
	policy        *policy.Engine // nil when no attestation policy configured
	bearerEnabled bool           // whether bearer token auth is allowed
	nonces        *nonce.Store   // nil when nonce challenge is not configured
	tokens        *token.Issuer  // nil when short-lived tokens are not configured
	startTime     time.Time      // server start time for uptime reporting
	authRL        *rateLimiter
	sessions      *session.Store            // nil when sessions are not configured
	sessionRoles  map[string]config.RoleConfig // nil when sessions are not configured
	mux           *http.ServeMux
}

// NewServer creates a new API server with all dependencies.
// Bearer auth is enabled by default.
func NewServer(b store.SecretBackend, a *acl.ACL, al *audit.Logger, auditPath string) *Server {
	srv := &Server{
		backend:       b,
		acl:           a,
		audit:         al,
		auditPath:     auditPath,
		bearerEnabled: true,
		startTime:     time.Now(),
		authRL:        newRateLimiter(),
		mux:           http.NewServeMux(),
	}
	// Keep a reference to FileBackend for file-specific operations (rotation).
	if fb, ok := b.(*store.FileBackend); ok {
		srv.fileBackend = fb
	}
	srv.routes()
	go func() {
		ticker := time.NewTicker(rateLimitCleanupAge)
		defer ticker.Stop()
		for range ticker.C {
			srv.authRL.cleanup()
		}
	}()
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

// SetSessionStore configures the session identity store.
func (s *Server) SetSessionStore(ss *session.Store) {
	s.sessions = ss
}

// SetSessionRoles configures the role definitions for session minting.
func (s *Server) SetSessionRoles(roles map[string]config.RoleConfig) {
	s.sessionRoles = roles
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
	s.mux.HandleFunc("POST /v1/proxy", s.handleProxy)
	s.mux.HandleFunc("POST /v1/keypair", s.handleGenerateKeyPair)
	s.mux.HandleFunc("GET /v1/agents/", s.handleAgentSubresource)
	s.mux.HandleFunc("GET /v1/policy/check", s.handlePolicyCheck)
	s.mux.HandleFunc("POST /v1/session/mint", s.handleSessionMint)
	s.mux.HandleFunc("POST /v1/session/renew", s.handleSessionRenew)
}

// authInfo contains authentication result and attestation evidence.
type authInfo struct {
	Agent           string
	UsedMTLS        bool
	UsedBearer      bool
	IsLocal         bool                   // true when client IP is loopback
	CertFingerprint string                 // "sha256:<hex>" or empty
	TokenIssuedAt   *time.Time             // set when authenticated via short-lived token
	Process         *policy.ProcessContext // set when token carries process attestation claims

	// Session identity (set when authenticated via session token)
	UsedSession       bool
	SessionID         string
	SessionRole       string
	SessionNamespaces []string
	SessionActions    []string
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
//
// Auth priority: session token > mTLS > short-lived token > bearer.
// Session tokens are checked first so that a renewal request carrying both
// a phxs_ token and a client certificate authenticates via the session.
// When a session is authenticated and a verified client cert is also present,
// the cert evidence (UsedMTLS, CertFingerprint) is layered onto the authInfo
// so that role attestation checks can inspect the current TLS state.
func (s *Server) authenticateInfo(r *http.Request) (*authInfo, error) {
	ip := clientIP(r)
	local := session.IsLoopback(ip)

	tok := extractToken(r)

	// --- Session token authentication (phxs_ prefix) ---
	// Checked first: session tokens are scoped credentials that agents use
	// for all operations after bootstrap. If present, session auth is
	// authoritative for identity; mTLS evidence is layered on as attestation.
	if s.sessions != nil && tok != "" && strings.HasPrefix(tok, session.TokenPrefix) {
		sess, err := s.sessions.Validate(tok)
		if err != nil {
			return nil, fmt.Errorf("session auth failed: %w", err)
		}
		info := &authInfo{
			Agent:             sess.Agent,
			IsLocal:           local,
			UsedSession:       true,
			SessionID:         sess.ID,
			SessionRole:       sess.Role,
			SessionNamespaces: sess.Namespaces,
			SessionActions:    sess.Actions,
		}
		// Layer on mTLS attestation evidence from the current TLS connection.
		// The session token is the auth method; the cert is attestation context.
		if s.ca != nil && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			if _, verifyErr := s.ca.VerifyClientCert(r.TLS.PeerCertificates); verifyErr == nil {
				info.UsedMTLS = true
				info.CertFingerprint = certFingerprint(r.TLS.PeerCertificates[0].Raw)
			}
		}
		return info, nil
	}

	// --- mTLS authentication ---
	// Rate limiting is NOT applied to mTLS — it uses cryptographic auth, not secrets.
	if s.ca != nil && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		agentName, err := s.ca.VerifyClientCert(r.TLS.PeerCertificates)
		if err == nil {
			s.authRL.recordSuccess(ip) // clear any prior bearer failures from this IP
			fp := certFingerprint(r.TLS.PeerCertificates[0].Raw)
			return &authInfo{
				Agent:           agentName,
				UsedMTLS:        true,
				IsLocal:         local,
				CertFingerprint: fp,
			}, nil
		}
		// mTLS verification failed — log but fall through to bearer
		log.Printf("mTLS auth failed for %s: %v", clientIP(r), err)
	}

	// --- Short-lived token authentication ---
	if s.tokens != nil && tok != "" {
		claims, err := s.tokens.Validate(tok)
		if err == nil {
			iat := claims.IssuedAt
			info := &authInfo{
				Agent:         claims.Agent,
				IsLocal:       local,
				TokenIssuedAt: &iat,
			}
			// Propagate process attestation claims from the token
			if claims.ProcessUID != nil || claims.BinaryHash != "" {
				pc := &policy.ProcessContext{
					BinaryHash: claims.BinaryHash,
				}
				if claims.ProcessUID != nil {
					pc.UID = *claims.ProcessUID
				}
				info.Process = pc
			}
			return info, nil
		}
		// Not a valid short-lived token — fall through to bearer
	}

	// --- Bearer token authentication ---
	if err := s.authRL.check(ip); err != nil {
		return nil, err
	}
	if !s.bearerEnabled {
		return nil, fmt.Errorf("no valid authentication credentials provided")
	}
	if tok == "" {
		return nil, fmt.Errorf("no authentication credentials provided")
	}
	agent, err := s.acl.Authenticate(tok)
	if err != nil {
		s.authRL.recordFailure(ip)
		return nil, err
	}
	s.authRL.recordSuccess(ip)
	return &authInfo{
		Agent:      agent,
		UsedBearer: true,
		IsLocal:    local,
	}, nil
}

// certFingerprint computes "sha256:<hex>" from raw DER certificate bytes.
func certFingerprint(raw []byte) string {
	hash := sha256.Sum256(raw)
	return fmt.Sprintf("sha256:%X", hash[:])
}

// attest checks attestation policy for the given secret path.
// Returns nil if no policy is configured or if the request passes.
// nonceValidated indicates whether a nonce was submitted and validated for this request.
func (s *Server) attest(r *http.Request, path string, info *authInfo, nonceValidated bool) error {
	return s.attestFull(r, path, info, nonceValidated, false, false)
}

func (s *Server) attestFull(r *http.Request, path string, info *authInfo, nonceValidated, signatureVerified, sealKeyValidated bool) error {
	if s.policy == nil {
		return nil
	}
	ctx := &policy.RequestContext{
		UsedMTLS:          info.UsedMTLS,
		UsedBearer:        info.UsedBearer,
		SourceIP:          clientIP(r),
		CertFingerprint:   info.CertFingerprint,
		Tool:              r.Header.Get("X-Phoenix-Tool"),
		Process:           info.Process,
		NonceValidated:    nonceValidated,
		SignatureVerified: signatureVerified,
		TokenIssuedAt:     info.TokenIssuedAt,
		SealKeyPresented:  sealKeyValidated,
		SessionID:         info.SessionID,
		SessionRole:       info.SessionRole,
	}
	return s.policy.Evaluate(path, ctx)
}

// buildCanonicalPayload constructs the deterministic JSON payload used
// for signed resolve verification. Fields are sorted alphabetically.
func buildCanonicalPayload(nonce, timestamp string, refs []string) []byte {
	sortedRefs := make([]string, len(refs))
	copy(sortedRefs, refs)
	sort.Strings(sortedRefs)

	canonical := map[string]interface{}{
		"nonce":     nonce,
		"refs":      sortedRefs,
		"timestamp": timestamp,
	}
	data, _ := json.Marshal(canonical)
	return data
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

// jsonDenied sends a structured denial response with a machine-readable code.
func jsonDenied(w http.ResponseWriter, errMsg, code, detail, remediation string, httpCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpCode)
	resp := map[string]string{
		"error":  errMsg,
		"code":   code,
		"detail": detail,
	}
	if remediation != "" {
		resp["remediation"] = remediation
	}
	json.NewEncoder(w).Encode(resp)
}

// auditAllowed logs an allowed action, including session ID when a session was used.
func (s *Server) auditAllowed(info *authInfo, action, path, ip string) {
	if info != nil && info.UsedSession {
		s.logAudit(s.audit.LogSessionAllowed(info.Agent, action, path, ip, info.SessionID))
	} else {
		agent := ""
		if info != nil {
			agent = info.Agent
		}
		s.logAudit(s.audit.LogAllowed(agent, action, path, ip))
	}
}

// auditDenied logs a denied action, including session ID when a session was used.
func (s *Server) auditDenied(info *authInfo, action, path, ip, reason string) {
	if info != nil && info.UsedSession {
		s.logAudit(s.audit.LogSessionDenied(info.Agent, action, path, ip, reason, info.SessionID))
	} else {
		agent := ""
		if info != nil {
			agent = info.Agent
		}
		s.logAudit(s.audit.LogDenied(agent, action, path, ip, reason))
	}
}

// checkSessionScope verifies the request path is within session namespace scope.
// Returns true if access is allowed, false if denied (and writes the error response).
func (s *Server) checkSessionScope(w http.ResponseWriter, info *authInfo, path, ip string) bool {
	if !info.UsedSession {
		return true
	}
	if !session.PathInScope(path, info.SessionNamespaces) {
		s.logAudit(s.audit.LogSessionDenied(info.Agent, "scope_check", path, ip, "session_scope", info.SessionID))
		jsonDenied(w, "access_denied", "SCOPE_EXCEEDED",
			fmt.Sprintf("path %q is outside session scope for role %q", path, info.SessionRole),
			"request a session with a role that includes this namespace",
			http.StatusForbidden)
		return false
	}
	return true
}

// checkSessionAction verifies the requested action is allowed by the session role.
// Returns true if access is allowed, false if denied (and writes the error response).
func (s *Server) checkSessionAction(w http.ResponseWriter, info *authInfo, action, path, ip string) bool {
	if !info.UsedSession {
		return true
	}
	for _, a := range info.SessionActions {
		if a == action || a == "admin" {
			return true
		}
	}
	s.logAudit(s.audit.LogSessionDenied(info.Agent, action, path, ip, "session_action", info.SessionID))
	jsonDenied(w, "access_denied", "ACTION_DENIED",
		fmt.Sprintf("action %q is not permitted by session role %q", action, info.SessionRole),
		"request a session with a role that includes this action",
		http.StatusForbidden)
	return false
}

// checkSessionSealKey verifies the request seal key matches the session binding.
// Returns true if check passes, false if denied.
func (s *Server) checkSessionSealKey(w http.ResponseWriter, r *http.Request, info *authInfo) bool {
	if !info.UsedSession || info.SessionID == "" {
		return true
	}
	sess := s.sessions.Get(info.SessionID)
	if sess == nil || sess.SealKeyFingerprint == "" {
		return true
	}
	header := r.Header.Get("X-Phoenix-Seal-Key")
	if header == "" {
		// Seal key is bound but not presented -- deny
		jsonDenied(w, "access_denied", "SEAL_KEY_MISMATCH",
			"session has a bound seal key but no X-Phoenix-Seal-Key header was provided",
			"include the seal key that was used when minting this session",
			http.StatusBadRequest)
		return false
	}
	pubKey, err := crypto.DecodeSealKey(header)
	if err != nil {
		jsonError(w, "malformed seal key header: "+err.Error(), http.StatusBadRequest)
		return false
	}
	fp := session.SealKeyFingerprint(pubKey[:])
	if fp != sess.SealKeyFingerprint {
		jsonDenied(w, "access_denied", "SEAL_KEY_MISMATCH",
			"request seal key does not match session binding",
			"use the same seal key that was provided at session mint",
			http.StatusForbidden)
		return false
	}
	return true
}

// jsonOK sends a JSON success response.
func jsonOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// logAudit logs audit write failures. Audit errors must not be silently lost.
func (s *Server) logAudit(err error) {
	if err != nil {
		log.Printf("WARNING: audit log write failed: %v", err)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]interface{}{
		"status":  "ok",
		"secrets": s.backend.Count(),
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

	// Session scope enforcement (before ACL)
	if path != "" && !strings.HasSuffix(path, "/") {
		if !s.checkSessionScope(w, info, path, ip) {
			return
		}
	}

	// Session seal key binding check
	if !s.checkSessionSealKey(w, r, info) {
		return
	}

	// Validate seal header early so attestation gets the correct state
	// for both list mode and single-secret reads.
	sealKey, sealErr := s.validateSealHeader(r, info)
	if sealErr != nil {
		jsonError(w, sealErr.Error(), http.StatusBadRequest)
		return
	}
	sealKeyValidated := sealKey != nil

	// List mode: path is empty or ends with /
	if path == "" || strings.HasSuffix(path, "/") {
		// Session action enforcement: list
		if !s.checkSessionAction(w, info, "list", path, ip) {
			return
		}
		allPaths, err := s.backend.List(path)
		if err != nil {
			log.Printf("error listing secrets with prefix %q: %v", path, err)
			jsonError(w, "internal error", http.StatusInternalServerError)
			return
		}
		var visible []string
		for _, p := range allPaths {
			// Session scope filter: hide paths outside session namespace
			if info.UsedSession && !session.PathInScope(p, info.SessionNamespaces) {
				continue
			}
			if s.acl.Authorize(agentName, p, acl.ActionList) != nil {
				continue
			}
			// Attestation check: hide paths the caller can't attest for
			if s.attestFull(r, p, info, false, false, sealKeyValidated) != nil {
				continue
			}
			visible = append(visible, p)
		}
		s.auditAllowed(info, "list", path, ip)
		jsonOK(w, map[string]interface{}{"paths": visible})
		return
	}

	// Session action enforcement: read_value
	if !s.checkSessionAction(w, info, "read_value", path, ip) {
		return
	}

	// Single secret read — requires read_value permission
	if err := s.acl.Authorize(agentName, path, acl.ActionReadValue); err != nil {
		s.auditDenied(info, "read_value", path, ip, "acl")
		jsonError(w, "access denied: read_value permission required (use phoenix exec for context-free secret injection)", http.StatusForbidden)
		return
	}

	// Attestation policy check (with validated seal key state)
	if err := s.attestFull(r, path, info, false, false, sealKeyValidated); err != nil {
		s.auditDenied(info, "read_value", path, ip, "attestation")
		jsonError(w, "attestation required: "+err.Error(), http.StatusForbidden)
		return
	}

	secret, err := s.backend.Get(path)
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

	s.auditAllowed(info, "read_value", path, ip)
	if sealKey != nil {
		env, err := crypto.SealValue(path, "", secret.Value, sealKey)
		if err != nil {
			log.Printf("error sealing secret %q: %v", path, err)
			jsonError(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		jsonOK(w, map[string]interface{}{
			"path":         path,
			"metadata":     secret.Metadata,
			"sealed_value": env,
		})
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	jsonOK(w, secret)
}

// setSecretRequest is the JSON body for creating/updating secrets.
type setSecretRequest struct {
	Value       string   `json:"value"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

func (s *Server) handleSetSecret(w http.ResponseWriter, r *http.Request) {
	info, err := s.authenticateInfo(r)
	if err != nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	agentName := info.Agent

	path := secretPath(r)
	ip := clientIP(r)

	// Session scope and action enforcement
	if !s.checkSessionScope(w, info, path, ip) {
		return
	}
	if !s.checkSessionAction(w, info, "write", path, ip) {
		return
	}

	if err := s.acl.Authorize(agentName, path, acl.ActionWrite); err != nil {
		s.auditDenied(info, "write", path, ip, "acl")
		jsonError(w, "access denied", http.StatusForbidden)
		return
	}

	// Attestation policy check
	if err := s.attest(r, path, info, false); err != nil {
		s.auditDenied(info, "write", path, ip, "attestation")
		jsonError(w, "attestation required: "+err.Error(), http.StatusForbidden)
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

	if s.backend.ReadOnly() {
		jsonError(w, "backend is read-only", http.StatusMethodNotAllowed)
		return
	}

	if err := s.backend.Set(path, req.Value, agentName, req.Description, req.Tags); err != nil {
		if err == store.ErrInvalidPath {
			jsonError(w, "invalid secret path", http.StatusBadRequest)
			return
		}
		log.Printf("error setting secret %q: %v", path, err)
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.auditAllowed(info, "write", path, ip)
	jsonOK(w, map[string]string{"status": "ok", "path": path})
}

func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	info, err := s.authenticateInfo(r)
	if err != nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	agentName := info.Agent

	path := secretPath(r)
	ip := clientIP(r)

	// Session scope and action enforcement
	if !s.checkSessionScope(w, info, path, ip) {
		return
	}
	if !s.checkSessionAction(w, info, "delete", path, ip) {
		return
	}

	if err := s.acl.Authorize(agentName, path, acl.ActionDelete); err != nil {
		s.auditDenied(info, "delete", path, ip, "acl")
		jsonError(w, "access denied", http.StatusForbidden)
		return
	}

	// Attestation policy check
	if err := s.attest(r, path, info, false); err != nil {
		s.auditDenied(info, "delete", path, ip, "attestation")
		jsonError(w, "attestation required: "+err.Error(), http.StatusForbidden)
		return
	}

	if s.backend.ReadOnly() {
		jsonError(w, "backend is read-only", http.StatusMethodNotAllowed)
		return
	}

	if err := s.backend.Delete(path); err != nil {
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

	s.auditAllowed(info, "delete", path, ip)
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

	if err := acl.ValidatePermissions(req.Permissions); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	force := r.URL.Query().Get("force") == "true"

	if force {
		// Try update first; if agent doesn't exist, fall through to add
		err := s.acl.UpdateAgent(req.Name, req.Token, req.Permissions)
		if err == nil {
			s.logAudit(s.audit.LogAllowed(agentName, "update-agent", req.Name, clientIP(r)))
			jsonOK(w, map[string]string{"status": "ok", "agent": req.Name, "action": "updated"})
			return
		}
		if !errors.Is(err, acl.ErrAgentNotFound) {
			log.Printf("error updating agent %q: %v", req.Name, err)
			jsonError(w, "internal error", http.StatusInternalServerError)
			return
		}
		// Agent doesn't exist — fall through to AddAgent below
	}

	if err := s.acl.AddAgent(req.Name, req.Token, req.Permissions); err != nil {
		if errors.Is(err, acl.ErrAgentExists) {
			jsonError(w, "agent already exists (use ?force=true to overwrite)", http.StatusConflict)
			return
		}
		log.Printf("error creating agent %q: %v", req.Name, err)
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.logAudit(s.audit.LogAllowed(agentName, "create-agent", req.Name, clientIP(r)))
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

	s.logAudit(s.audit.LogAllowed(agentName, "issue-cert", req.AgentName, clientIP(r)))
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

	if s.fileBackend == nil {
		jsonError(w, "master key rotation is not supported for this backend", http.StatusNotImplemented)
		return
	}

	if s.masterKeyPath == "" {
		jsonError(w, "master key path not configured", http.StatusInternalServerError)
		return
	}

	// Verify provider is FileKeyProvider before we start
	provider, ok := s.fileBackend.Provider().(*crypto.FileKeyProvider)
	if !ok {
		log.Printf("rotation not supported: provider is %T, not FileKeyProvider", s.fileBackend.Provider())
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
	rotated, err := s.fileBackend.Store().RotateMasterKey(func() error {
		pendingKey := provider.PendingMasterKey()
		if pendingKey == nil {
			return fmt.Errorf("no pending key after rotation")
		}
		if provider.Passphrase() != "" {
			return crypto.SaveProtectedMasterKey(s.masterKeyPath, pendingKey, provider.Passphrase())
		}
		return crypto.SaveMasterKeyAtomic(s.masterKeyPath, pendingKey)
	})
	if err != nil {
		log.Printf("error rotating master key: %v", err)
		jsonError(w, "rotation failed", http.StatusInternalServerError)
		return
	}

	s.logAudit(s.audit.LogAllowed(agentName, "rotate-master", fmt.Sprintf("%d namespaces", rotated), ip))
	log.Printf("master key rotated by %s: %d namespaces re-wrapped", agentName, rotated)

	jsonOK(w, map[string]interface{}{
		"status":  "ok",
		"rotated": rotated,
		"backup":  prevPath,
	})
}

// resolveRequest is the JSON body for batch reference resolution.
type resolveRequest struct {
	Refs      []string `json:"refs"`
	Nonce     string   `json:"nonce,omitempty"`     // optional nonce from /v1/challenge
	Timestamp string   `json:"timestamp,omitempty"` // RFC3339 timestamp for signed resolve
	Signature string   `json:"signature,omitempty"` // base64 detached ECDSA signature
}

// signedResolveMaxSkew is the maximum allowed clock skew for signed resolve timestamps.
const signedResolveMaxSkew = 60 * time.Second

func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	info, err := s.authenticateInfo(r)
	if err != nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	agentName := info.Agent

	ip := clientIP(r)

	dryRun := r.URL.Query().Get("dry_run") == "true"

	// Validate seal key header early (before processing refs)
	sealKey, sealErr := s.validateSealHeader(r, info)
	if sealErr != nil {
		jsonError(w, sealErr.Error(), http.StatusBadRequest)
		return
	}

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

	// Validate nonce if provided
	nonceValidated := false
	if req.Nonce != "" {
		if s.nonces == nil {
			jsonError(w, "nonce challenge not enabled", http.StatusBadRequest)
			return
		}
		if err := s.nonces.Validate(req.Nonce); err != nil {
			jsonError(w, "nonce validation failed: "+err.Error(), http.StatusForbidden)
			return
		}
		nonceValidated = true
	}

	// Verify signed resolve payload if provided
	signatureVerified := false
	if req.Signature != "" {
		// Require nonce and timestamp alongside signature
		if req.Nonce == "" || req.Timestamp == "" {
			jsonError(w, "signed resolve requires nonce and timestamp", http.StatusBadRequest)
			return
		}

		// Parse and validate timestamp freshness
		ts, tsErr := time.Parse(time.RFC3339, req.Timestamp)
		if tsErr != nil {
			jsonError(w, "invalid timestamp format (expected RFC3339)", http.StatusBadRequest)
			return
		}
		if time.Since(ts).Abs() > signedResolveMaxSkew {
			jsonError(w, "timestamp outside allowed skew window", http.StatusForbidden)
			return
		}

		// Build canonical payload for verification
		canonical := buildCanonicalPayload(req.Nonce, req.Timestamp, req.Refs)

		// Decode signature
		sigBytes, decErr := base64.StdEncoding.DecodeString(req.Signature)
		if decErr != nil {
			jsonError(w, "invalid signature encoding", http.StatusBadRequest)
			return
		}

		// Verify against mTLS client cert public key
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			jsonError(w, "signed resolve requires mTLS client certificate", http.StatusForbidden)
			return
		}
		pubKey, ok := r.TLS.PeerCertificates[0].PublicKey.(*ecdsa.PublicKey)
		if !ok {
			jsonError(w, "client certificate must use ECDSA key for signed resolve", http.StatusBadRequest)
			return
		}

		hash := sha256.Sum256(canonical)
		if !ecdsa.VerifyASN1(pubKey, hash[:], sigBytes) {
			jsonError(w, "signature verification failed", http.StatusForbidden)
			return
		}
		signatureVerified = true
	}

	values := make(map[string]string)
	sealedValues := make(map[string]*crypto.SealedEnvelope)
	errors := make(map[string]string)

	// Session seal key binding check (once, before processing refs)
	if !s.checkSessionSealKey(w, r, info) {
		return
	}

	for _, refStr := range req.Refs {
		path, err := ref.Parse(refStr)
		if err != nil {
			s.auditDenied(info, "resolve", refStr, ip, "malformed_ref")
			errors[refStr] = err.Error()
			continue
		}

		// Session scope enforcement (per-ref)
		if info.UsedSession && !session.PathInScope(path, info.SessionNamespaces) {
			s.auditDenied(info, "resolve", path, ip, "session_scope")
			errors[refStr] = "path outside session scope"
			continue
		}

		// Session action enforcement (per-ref)
		if info.UsedSession {
			allowed := false
			for _, a := range info.SessionActions {
				if a == "read_value" || a == "admin" {
					allowed = true
					break
				}
			}
			if !allowed {
				s.auditDenied(info, "resolve", path, ip, "session_action")
				errors[refStr] = "action read_value not permitted by session role"
				continue
			}
		}

		if err := s.acl.Authorize(agentName, path, acl.ActionReadValue); err != nil {
			s.auditDenied(info, "resolve", path, ip, "acl")
			errors[refStr] = "access denied: read_value permission required"
			continue
		}

		// Attestation policy check (per-ref)
		if err := s.attestFull(r, path, info, nonceValidated, signatureVerified, sealKey != nil); err != nil {
			s.auditDenied(info, "resolve", path, ip, "attestation")
			errors[refStr] = "attestation required"
			continue
		}

		if dryRun {
			// Dry-run: verify path exists without returning the secret value.
			if _, err := s.backend.Get(path); err != nil {
				if err == store.ErrSecretNotFound {
					s.auditDenied(info, "dry-resolve", path, ip, "not_found")
					errors[refStr] = "secret not found"
				} else if err == store.ErrInvalidPath {
					s.auditDenied(info, "dry-resolve", path, ip, "invalid_path")
					errors[refStr] = "invalid path"
				} else {
					s.auditDenied(info, "dry-resolve", path, ip, "internal_error")
					log.Printf("error dry-resolving %q for %s: %v", path, agentName, err)
					errors[refStr] = "internal error"
				}
				continue
			}
			s.auditAllowed(info, "dry-resolve", path, ip)
			values[refStr] = "ok"
			continue
		}

		secret, err := s.backend.Get(path)
		if err != nil {
			if err == store.ErrSecretNotFound {
				s.auditDenied(info, "resolve", path, ip, "not_found")
				errors[refStr] = "secret not found"
			} else if err == store.ErrInvalidPath {
				s.auditDenied(info, "resolve", path, ip, "invalid_path")
				errors[refStr] = "invalid path"
			} else {
				s.auditDenied(info, "resolve", path, ip, "internal_error")
				log.Printf("error resolving %q for %s: %v", path, agentName, err)
				errors[refStr] = "internal error"
			}
			continue
		}

		s.auditAllowed(info, "resolve", path, ip)

		if sealKey != nil {
			env, err := crypto.SealValue(path, refStr, secret.Value, sealKey)
			if err != nil {
				log.Printf("error sealing resolved secret %q: %v", path, err)
				errors[refStr] = "internal error"
				continue
			}
			sealedValues[refStr] = env
		} else {
			values[refStr] = secret.Value
		}
	}

	resp := map[string]interface{}{}
	if sealKey != nil && !dryRun {
		resp["sealed_values"] = sealedValues
	} else {
		resp["values"] = values
	}
	if len(errors) > 0 {
		resp["errors"] = errors
	}
	if !dryRun {
		w.Header().Set("Cache-Control", "no-store")
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

	s.logAudit(s.audit.LogAllowed(agentName, "revoke-cert", req.SerialNumber, clientIP(r)))
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
		"secrets": s.backend.Count(),
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
			if rule.RequireSealed {
				checks = append(checks, "sealed-required")
			}
			if rule.AllowUnseal {
				checks = append(checks, "unseal-allowed")
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
	Agent      string `json:"agent"`
	ProcessUID *int   `json:"process_uid,omitempty"`
	BinaryHash string `json:"binary_hash,omitempty"`
}

// handlePolicyCheck returns whether a specific policy check passes for a path.
// Query params: path (required), check (required, e.g. "allow_unseal").
func (s *Server) handlePolicyCheck(w http.ResponseWriter, r *http.Request) {
	_, err := s.authenticate(r)
	if err != nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	path := r.URL.Query().Get("path")
	check := r.URL.Query().Get("check")
	if path == "" || check == "" {
		jsonError(w, "path and check query parameters required", http.StatusBadRequest)
		return
	}

	if check != "allow_unseal" {
		jsonError(w, "unsupported check: "+check, http.StatusBadRequest)
		return
	}

	allowed := false
	if s.policy != nil {
		rule, _ := s.policy.RuleFor(path)
		if rule != nil {
			allowed = rule.AllowUnseal
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"path":    path,
		"check":   check,
		"allowed": allowed,
	})
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

	tok, claims, err := s.tokens.Mint(req.Agent, req.ProcessUID, req.BinaryHash)
	if err != nil {
		log.Printf("error minting token for %q: %v", req.Agent, err)
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.logAudit(s.audit.LogAllowed(agentName, "mint-token", req.Agent, clientIP(r)))
	jsonOK(w, map[string]interface{}{
		"token":      tok,
		"agent":      claims.Agent,
		"issued_at":  claims.IssuedAt.Format(time.RFC3339),
		"expires_at": claims.ExpiresAt.Format(time.RFC3339),
		"ttl":        s.tokens.TTL().String(),
	})
}

// validateSealHeader checks the X-Phoenix-Seal-Key header against the agent's
// registered public seal key. Returns the decoded 32-byte public key if valid,
// or nil if no header is present. Returns an error if the header is present but
// invalid or mismatched.
//
// For session-authenticated requests, the ACL-registered seal key check is
// skipped. Session seal key binding is handled separately by checkSessionSealKey,
// which validates the header against the fingerprint bound at session mint time.
func (s *Server) validateSealHeader(r *http.Request, info *authInfo) (*[32]byte, error) {
	header := r.Header.Get("X-Phoenix-Seal-Key")
	if header == "" {
		return nil, nil
	}

	pubKey, err := crypto.DecodeSealKey(header)
	if err != nil {
		return nil, fmt.Errorf("malformed seal key header: %w", err)
	}

	// Session-authenticated requests: seal key was already validated against
	// the session's bound fingerprint by checkSessionSealKey. Skip ACL check.
	if info.UsedSession {
		return pubKey, nil
	}

	registered, err := s.acl.GetAgentSealKey(info.Agent)
	if err != nil {
		return nil, fmt.Errorf("agent lookup failed: %w", err)
	}
	if registered == "" {
		return nil, fmt.Errorf("agent has no registered seal key")
	}
	registeredKey, err := crypto.DecodeSealKey(registered)
	if err != nil {
		return nil, fmt.Errorf("registered seal key is malformed: %w", err)
	}
	if *registeredKey != *pubKey {
		return nil, fmt.Errorf("seal key does not match registered key")
	}

	return pubKey, nil
}

// generateKeyPairRequest is the JSON body for keypair generation.
type generateKeyPairRequest struct {
	AgentName string `json:"agent_name"`
}

func (s *Server) handleGenerateKeyPair(w http.ResponseWriter, r *http.Request) {
	agentName, err := s.authenticate(r)
	if err != nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err := s.acl.Authorize(agentName, "keypair", acl.ActionAdmin); err != nil {
		jsonError(w, "access denied: admin required", http.StatusForbidden)
		return
	}

	var req generateKeyPairRequest
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.AgentName == "" {
		jsonError(w, "agent_name is required", http.StatusBadRequest)
		return
	}

	// Verify agent exists
	_, err = s.acl.GetAgent(req.AgentName)
	if err != nil {
		jsonError(w, "agent not found", http.StatusNotFound)
		return
	}

	// Check if agent already has a seal key
	existing, _ := s.acl.GetAgentSealKey(req.AgentName)
	force := r.URL.Query().Get("force") == "true"
	if existing != "" && !force {
		jsonError(w, "agent already has a seal key (use ?force=true to rotate)", http.StatusConflict)
		return
	}

	kp, err := crypto.GenerateSealKeyPair()
	if err != nil {
		log.Printf("error generating seal keypair: %v", err)
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	pubEncoded := crypto.EncodeSealKey(&kp.PublicKey)
	privEncoded := crypto.EncodeSealKey(&kp.PrivateKey)

	if err := s.acl.SetAgentSealKey(req.AgentName, pubEncoded); err != nil {
		log.Printf("error storing seal key for %q: %v", req.AgentName, err)
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	ip := clientIP(r)
	auditAction := "generate-keypair"
	if existing != "" {
		auditAction = "rotate-keypair"
	}
	s.logAudit(s.audit.LogAllowed(agentName, auditAction, req.AgentName, ip))

	w.Header().Set("Cache-Control", "no-store")
	jsonOK(w, map[string]string{
		"agent_name":       req.AgentName,
		"seal_public_key":  pubEncoded,
		"seal_private_key": privEncoded,
	})
}

// handleAgentSubresource routes GET /v1/agents/{name}/seal-key
func (s *Server) handleAgentSubresource(w http.ResponseWriter, r *http.Request) {
	// Parse: /v1/agents/{name}/seal-key
	path := strings.TrimPrefix(r.URL.Path, "/v1/agents/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 || parts[1] != "seal-key" {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	agentTarget := parts[0]
	if agentTarget == "" {
		jsonError(w, "agent name is required", http.StatusBadRequest)
		return
	}

	s.handleGetSealKey(w, r, agentTarget)
}

func (s *Server) handleGetSealKey(w http.ResponseWriter, r *http.Request, agentTarget string) {
	agentName, err := s.authenticate(r)
	if err != nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err := s.acl.Authorize(agentName, "keypair", acl.ActionAdmin); err != nil {
		jsonError(w, "access denied: admin required", http.StatusForbidden)
		return
	}

	pubKey, err := s.acl.GetAgentSealKey(agentTarget)
	if err != nil {
		jsonError(w, "agent not found", http.StatusNotFound)
		return
	}

	jsonOK(w, map[string]string{
		"agent_name":      agentTarget,
		"seal_public_key": pubKey,
	})
}

// handleProxy is a stub for the future orchestrator proxy endpoint.
// The orchestrator will accept templated HTTP requests containing phoenix://
// references, resolve them server-side, execute the outbound request, and
// return the response — keeping secret values entirely within the server.
//
// Agents using the proxy only need "list" permission to discover and reference
// secrets. The server performs privileged internal resolution, so agents never
// need "read_value" and secrets never enter agent context.
//
// Expected future request schema:
//
//	{
//	  "method": "POST",
//	  "url": "https://api.example.com/v1/deploy",
//	  "headers": {"Authorization": "Bearer phoenix://myapp/api-key"},
//	  "body": "{\"token\": \"phoenix://myapp/deploy-token\"}"
//	}
func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	_, err := s.authenticateInfo(r)
	if err != nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	jsonError(w, "proxy endpoint not yet implemented", http.StatusNotImplemented)
}

// sessionMintRequest is the JSON body for minting a session token.
type sessionMintRequest struct {
	Role         string `json:"role"`
	SealPublicKey string `json:"seal_public_key,omitempty"` // base64-encoded 32-byte X25519 key
}

func (s *Server) handleSessionMint(w http.ResponseWriter, r *http.Request) {
	if s.sessions == nil || s.sessionRoles == nil {
		jsonError(w, "session identity not enabled", http.StatusNotImplemented)
		return
	}

	// Authenticate the bootstrap request using existing auth channels
	info, err := s.authenticateInfo(r)
	if err != nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ip := clientIP(r)

	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
	var req sessionMintRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Role == "" {
		jsonError(w, "role is required", http.StatusBadRequest)
		return
	}

	// Look up role
	role, ok := s.sessionRoles[req.Role]
	if !ok {
		jsonDenied(w, "access_denied", "ROLE_NOT_FOUND",
			fmt.Sprintf("role %q does not exist", req.Role),
			"check available roles in server config",
			http.StatusNotFound)
		s.logAudit(s.audit.LogDenied(info.Agent, "session.mint", req.Role, ip, "role_not_found"))
		return
	}

	// Determine bootstrap method from auth info
	bootstrapMethod := s.bootstrapMethod(info)

	// Check bootstrap trust
	if !s.bootstrapAllowed(role.BootstrapTrust, bootstrapMethod, info.IsLocal) {
		jsonDenied(w, "access_denied", "BOOTSTRAP_FAILED",
			fmt.Sprintf("auth method %q is not in role's bootstrap_trust list", bootstrapMethod),
			fmt.Sprintf("role %q accepts: %v", req.Role, role.BootstrapTrust),
			http.StatusForbidden)
		s.logAudit(s.audit.LogDenied(info.Agent, "session.mint", req.Role, ip, "bootstrap_failed"))
		return
	}

	// Check role attestation requirements
	if len(role.Attestation) > 0 {
		if reason := s.checkRoleAttestation(role.Attestation, info, ip); reason != "" {
			jsonDenied(w, "access_denied", "ATTESTATION_FAILED",
				reason,
				fmt.Sprintf("role %q requires attestation: %v", req.Role, role.Attestation),
				http.StatusForbidden)
			s.logAudit(s.audit.LogDenied(info.Agent, "session.mint", req.Role, ip, "attestation_failed"))
			return
		}
	}

	// Validate seal key if required
	var sealPubKey []byte
	if role.RequireSealKey {
		if req.SealPublicKey == "" {
			jsonDenied(w, "bad_request", "SEAL_KEY_REQUIRED",
				fmt.Sprintf("role %q requires a seal public key", req.Role),
				"include seal_public_key in the mint request",
				http.StatusBadRequest)
			return
		}
	}
	if req.SealPublicKey != "" {
		decoded, err := crypto.DecodeSealKey(req.SealPublicKey)
		if err != nil {
			jsonError(w, "invalid seal_public_key: "+err.Error(), http.StatusBadRequest)
			return
		}
		sealPubKey = decoded[:]
	}

	// Compute effective TTL
	ttl := s.sessionTTL(role.MaxTTL)

	namespaces := role.Namespaces
	actions := role.Actions // nil -> store defaults to ["list", "read_value"]

	// Mint session
	tokenStr, sess, err := s.sessions.Create(req.Role, info.Agent, sealPubKey, namespaces, actions, bootstrapMethod, ip, ttl)
	if err != nil {
		log.Printf("session mint error: %v", err)
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Audit log
	s.logAudit(s.audit.LogAllowed(info.Agent, "session.mint.approved", req.Role, ip))

	w.Header().Set("Cache-Control", "no-store")
	jsonOK(w, map[string]interface{}{
		"session_id":           sess.ID,
		"session_token":        tokenStr,
		"role":                 sess.Role,
		"expires_at":           sess.ExpiresAt.Format(time.RFC3339),
		"namespaces":           sess.Namespaces,
		"seal_key_fingerprint": sess.SealKeyFingerprint,
	})
}

func (s *Server) handleSessionRenew(w http.ResponseWriter, r *http.Request) {
	if s.sessions == nil || s.sessionRoles == nil {
		jsonError(w, "session identity not enabled", http.StatusNotImplemented)
		return
	}

	info, err := s.authenticateInfo(r)
	if err != nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if !info.UsedSession {
		jsonDenied(w, "bad_request", "SESSION_REQUIRED",
			"only session tokens can be renewed",
			"authenticate with a session token (phxs_ prefix)",
			http.StatusBadRequest)
		return
	}

	ip := clientIP(r)

	// Re-check that the role still exists in config
	role, ok := s.sessionRoles[info.SessionRole]
	if !ok {
		jsonDenied(w, "access_denied", "ROLE_NOT_FOUND",
			fmt.Sprintf("role %q no longer exists in server config", info.SessionRole),
			"contact your administrator",
			http.StatusForbidden)
		s.logAudit(s.audit.LogSessionDenied(info.Agent, "session.renew", info.SessionRole, ip, "role_not_found", info.SessionID))
		return
	}

	// Re-check bootstrap trust: look up the original bootstrap method from the session
	sess := s.sessions.Get(info.SessionID)
	if sess == nil {
		jsonDenied(w, "access_denied", "SESSION_EXPIRED",
			"session no longer exists",
			"mint a new session",
			http.StatusUnauthorized)
		return
	}

	if !s.bootstrapAllowed(role.BootstrapTrust, sess.BootstrapMethod, session.IsLoopback(ip)) {
		jsonDenied(w, "access_denied", "BOOTSTRAP_FAILED",
			fmt.Sprintf("original bootstrap method %q is no longer trusted for role %q", sess.BootstrapMethod, info.SessionRole),
			"mint a new session with a currently trusted auth method",
			http.StatusForbidden)
		s.logAudit(s.audit.LogSessionDenied(info.Agent, "session.renew", info.SessionRole, ip, "bootstrap_failed", info.SessionID))
		return
	}

	// Re-check role attestation requirements against the CURRENT request.
	// authenticateInfo() layers mTLS evidence onto session authInfo when a
	// verified client cert is present on the TLS connection, so info already
	// carries the real current-request attestation state.
	if len(role.Attestation) > 0 {
		if reason := s.checkRoleAttestation(role.Attestation, info, ip); reason != "" {
			jsonDenied(w, "access_denied", "ATTESTATION_FAILED",
				reason,
				fmt.Sprintf("role %q requires attestation: %v", info.SessionRole, role.Attestation),
				http.StatusForbidden)
			s.logAudit(s.audit.LogSessionDenied(info.Agent, "session.renew", info.SessionRole, ip, "attestation_failed", info.SessionID))
			return
		}
	}

	ttl := s.sessionTTL(role.MaxTTL)

	tokenStr, renewedSess, err := s.sessions.Renew(info.SessionID, ttl)
	if err != nil {
		switch err {
		case session.ErrSessionRevoked:
			jsonDenied(w, "access_denied", "SESSION_REVOKED",
				"session has been revoked",
				"mint a new session",
				http.StatusForbidden)
		case session.ErrTokenExpired:
			jsonDenied(w, "access_denied", "SESSION_EXPIRED",
				"session has expired",
				"mint a new session",
				http.StatusUnauthorized)
		default:
			log.Printf("session renew error: %v", err)
			jsonError(w, "internal error", http.StatusInternalServerError)
		}
		return
	}

	s.logAudit(s.audit.LogSessionAllowed(info.Agent, "session.renewed", info.SessionRole, ip, info.SessionID))

	w.Header().Set("Cache-Control", "no-store")
	jsonOK(w, map[string]interface{}{
		"session_id":    renewedSess.ID,
		"session_token": tokenStr,
		"role":          renewedSess.Role,
		"expires_at":    renewedSess.ExpiresAt.Format(time.RFC3339),
		"renewed":       true,
	})
}

// checkRoleAttestation verifies that the request satisfies the role's attestation
// requirements. Returns a non-empty reason string if any check fails.
func (s *Server) checkRoleAttestation(attestation []string, info *authInfo, ip string) string {
	for _, req := range attestation {
		switch req {
		case "require_mtls":
			if !info.UsedMTLS {
				return "role requires mTLS authentication"
			}
		case "source_ip":
			// source_ip attestation on a role means the caller must be local
			if !info.IsLocal {
				return "role requires local (loopback) access"
			}
		case "cert_fingerprint":
			if info.CertFingerprint == "" {
				return "role requires client certificate fingerprint"
			}
		case "require_sealed":
			// Seal key is checked separately at mint time
		}
	}
	return ""
}

// bootstrapMethod returns the primary auth method string from authInfo.
func (s *Server) bootstrapMethod(info *authInfo) string {
	if info.UsedMTLS {
		return "mtls"
	}
	if info.UsedBearer {
		return "bearer"
	}
	if info.TokenIssuedAt != nil {
		return "token"
	}
	return "unknown"
}

// bootstrapAllowed checks if the auth method satisfies the role's bootstrap trust.
// "local" is additive -- a bearer+local request matches both "bearer" and "local".
func (s *Server) bootstrapAllowed(trustMethods []string, method string, isLocal bool) bool {
	for _, allowed := range trustMethods {
		if allowed == method {
			return true
		}
		if allowed == "local" && isLocal {
			return true
		}
	}
	return false
}

// sessionTTL computes the effective TTL for a session, respecting the role's max_ttl.
func (s *Server) sessionTTL(maxTTL string) time.Duration {
	if maxTTL == "" {
		return 0 // use store default
	}
	d, err := time.ParseDuration(maxTTL)
	if err != nil {
		return 0 // validated at config load, shouldn't happen
	}
	return d
}
