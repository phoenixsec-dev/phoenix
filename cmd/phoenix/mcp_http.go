// MCP Streamable HTTP transport for Phoenix.
//
// Implements the MCP 2025-03-26 Streamable HTTP specification:
// a single /mcp endpoint accepting POST (JSON-RPC requests) and
// DELETE (session termination). GET is reserved for future SSE streaming.
//
// Usage:
//
//	phoenix mcp-server --http :8080 --mcp-token <token>
//
// Or via environment:
//
//	PHOENIX_MCP_TOKEN=<token> phoenix mcp-server --http :8080
package main

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type mcpSession struct {
	id      string
	created time.Time
}

type mcpHTTPServer struct {
	mu       sync.RWMutex
	sessions map[string]*mcpSession
	token    string // required Bearer token for MCP client auth
	logger   *log.Logger
	maxAge   time.Duration
}

func (s *mcpHTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.handlePost(w, r)
	case http.MethodDelete:
		s.handleDelete(w, r)
	case http.MethodGet:
		// Reserved for future SSE streaming support.
		http.Error(w, "SSE streaming not yet supported", http.StatusMethodNotAllowed)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *mcpHTTPServer) handlePost(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"Unauthorized"}}`))
		return
	}

	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
		return
	}

	var req mcpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		mcpSendError(enc, nil, -32700, "Parse error")
		w.Write(buf.Bytes())
		return
	}

	// Session management: initialize creates a session, all other
	// non-notification requests require a valid session.
	if req.Method == "initialize" {
		sess := s.createSession()
		w.Header().Set("Mcp-Session-Id", sess.id)
		s.logger.Printf("session created: %s", sess.id)
	} else if req.ID != nil {
		sessionID := r.Header.Get("Mcp-Session-Id")
		if !s.validSession(sessionID) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"Invalid or missing session"}}`))
			return
		}
		w.Header().Set("Mcp-Session-Id", sessionID)
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	mcpHandleRequest(req, enc, s.logger)

	if buf.Len() > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.Write(buf.Bytes())
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *mcpHTTPServer) handleDelete(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	sessionID := r.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		http.Error(w, "Missing Mcp-Session-Id", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	_, existed := s.sessions[sessionID]
	delete(s.sessions, sessionID)
	s.mu.Unlock()

	if !existed {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	s.logger.Printf("session deleted: %s", sessionID)
	w.WriteHeader(http.StatusOK)
}

func (s *mcpHTTPServer) checkAuth(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	provided := strings.TrimPrefix(auth, "Bearer ")
	return subtle.ConstantTimeCompare([]byte(provided), []byte(s.token)) == 1
}

func (s *mcpHTTPServer) createSession() *mcpSession {
	b := make([]byte, 16)
	cryptorand.Read(b)
	sess := &mcpSession{
		id:      hex.EncodeToString(b),
		created: time.Now(),
	}
	s.mu.Lock()
	s.sessions[sess.id] = sess
	s.mu.Unlock()
	return sess
}

func (s *mcpHTTPServer) validSession(id string) bool {
	if id == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[id]
	if !ok {
		return false
	}
	if s.maxAge > 0 && time.Since(sess.created) > s.maxAge {
		delete(s.sessions, id)
		return false
	}

	// Lazy cleanup: remove other expired sessions while we hold the lock.
	if s.maxAge > 0 {
		for sid, se := range s.sessions {
			if time.Since(se.created) > s.maxAge {
				delete(s.sessions, sid)
			}
		}
	}
	return true
}

// cmdMCPHTTP starts the MCP server in Streamable HTTP mode.
func cmdMCPHTTP(addr string, mcpToken string) error {
	if err := requireAuth(); err != nil {
		return err
	}
	if mcpToken == "" {
		return fmt.Errorf("MCP HTTP mode requires --mcp-token or PHOENIX_MCP_TOKEN")
	}

	logger := log.New(os.Stderr, "phoenix-mcp-http: ", log.LstdFlags)

	srv := &mcpHTTPServer{
		sessions: make(map[string]*mcpSession),
		token:    mcpToken,
		logger:   logger,
		maxAge:   time.Hour,
	}

	mux := http.NewServeMux()
	mux.Handle("/mcp", srv)

	logger.Printf("listening on %s", addr)
	return http.ListenAndServe(addr, mux)
}
