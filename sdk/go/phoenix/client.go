// Package phoenix provides a thin HTTP client for the Phoenix secrets
// management API. It supports health checks, single resolve, and batch
// resolve. No admin operations.
//
// Under 200 lines — if this grows beyond that, it's doing too much.
package phoenix

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Error represents a Phoenix API error.
type Error struct {
	Message     string
	Status      int
	Code        string // structured denial code (e.g., SCOPE_EXCEEDED, ACTION_DENIED)
	Remediation string // hint for resolving the error
}

func (e *Error) Error() string {
	if e.Code != "" {
		msg := fmt.Sprintf("phoenix: HTTP %d [%s]: %s", e.Status, e.Code, e.Message)
		if e.Remediation != "" {
			msg += "\n  hint: " + e.Remediation
		}
		return msg
	}
	if e.Status > 0 {
		return fmt.Sprintf("phoenix: HTTP %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("phoenix: %s", e.Message)
}

// ResolveResult contains the result of a batch resolve call.
type ResolveResult struct {
	Values map[string]string `json:"values"`
	Errors map[string]string `json:"errors,omitempty"`
}

// SealedEnvelope is the wire format for a sealed secret value.
type SealedEnvelope struct {
	Version      int    `json:"version"`
	Algorithm    string `json:"algorithm"`
	Path         string `json:"path"`
	Ref          string `json:"ref"`
	EphemeralKey string `json:"ephemeral_key"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
}

// Client is a thin HTTP client for the Phoenix API.
type Client struct {
	Server     string
	Token      string
	HTTPClient *http.Client
	Role       string     // session role (set after MintSession)
	sealPubKey string     // base64-encoded public key for sealed requests
	sealPriv   *[32]byte  // private key for decrypting sealed responses
	sessionExp time.Time  // token expiry for auto-renewal
}

// New creates a new Phoenix client. Server and token default to
// PHOENIX_SERVER and PHOENIX_TOKEN environment variables.
func New(server, token string) *Client {
	if server == "" {
		server = os.Getenv("PHOENIX_SERVER")
	}
	if server == "" {
		server = "http://127.0.0.1:9090"
	}
	server = strings.TrimRight(server, "/")

	if token == "" {
		token = os.Getenv("PHOENIX_TOKEN")
	}

	c := &Client{
		Server: server,
		Token:  token,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}

	return c
}

// NewWithRole creates a client and mints a scoped session for the given role.
// The bootstrap token (from token param or PHOENIX_TOKEN env) is used only for
// the mint request and then replaced with the scoped session token.
// Returns an error if minting fails (fail-closed: no fallback to bootstrap token).
func NewWithRole(server, token, role string) (*Client, error) {
	c := New(server, token)
	if role == "" {
		role = os.Getenv("PHOENIX_ROLE")
	}
	if role == "" {
		return c, nil
	}
	if err := c.MintSession(role); err != nil {
		return nil, fmt.Errorf("session mint for role %q: %w", role, err)
	}
	return c, nil
}

// SetSealKey loads a seal private key from a file, enabling sealed mode.
// When set, Resolve and ResolveBatch auto-decrypt sealed responses.
func (c *Client) SetSealKey(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading seal key: %w", err)
	}
	privKey, err := decodeSealKey(strings.TrimSpace(string(data)))
	if err != nil {
		return err
	}
	c.sealPriv = privKey
	c.sealPubKey = encodeSealKey(deriveSealPublicKey(privKey))
	return nil
}

// Health checks server health. Returns the parsed JSON response.
func (c *Client) Health() (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := c.doRequest("GET", "/v1/health", nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Resolve resolves a single phoenix:// reference to its secret value.
func (c *Client) Resolve(ref string) (string, error) {
	result, err := c.ResolveBatch([]string{ref})
	if err != nil {
		return "", err
	}
	if errMsg, ok := result.Errors[ref]; ok {
		return "", &Error{Message: errMsg}
	}
	val, ok := result.Values[ref]
	if !ok {
		return "", &Error{Message: fmt.Sprintf("no value returned for %s", ref)}
	}
	return val, nil
}

// ResolveBatch resolves multiple phoenix:// references in one API call.
// When sealed mode is enabled (via SetSealKey), responses are automatically
// decrypted — callers see plaintext values transparently.
func (c *Client) ResolveBatch(refs []string) (*ResolveResult, error) {
	if len(refs) == 0 {
		return nil, &Error{Message: "refs must not be empty"}
	}

	body := map[string]interface{}{"refs": refs}

	if c.sealPriv != nil {
		// Sealed mode: parse sealed_values and decrypt locally,
		// falling back to plaintext values if server doesn't seal.
		var raw struct {
			SealedValues map[string]json.RawMessage `json:"sealed_values"`
			Values       map[string]string          `json:"values"`
			Errors       map[string]string          `json:"errors,omitempty"`
		}
		if err := c.doRequest("POST", "/v1/resolve", body, &raw); err != nil {
			return nil, err
		}
		if len(raw.SealedValues) > 0 {
			result := &ResolveResult{
				Values: make(map[string]string, len(raw.SealedValues)),
				Errors: raw.Errors,
			}
			for ref, envJSON := range raw.SealedValues {
				var env SealedEnvelope
				if err := json.Unmarshal(envJSON, &env); err != nil {
					return nil, &Error{Message: fmt.Sprintf("parsing sealed envelope for %s: %v", ref, err)}
				}
				if env.Ref != ref {
					return nil, &Error{Message: fmt.Sprintf("sealed envelope ref mismatch: map key %q, envelope %q", ref, env.Ref)}
				}
				val, err := openSealedEnvelope(&env, c.sealPriv)
				if err != nil {
					return nil, &Error{Message: fmt.Sprintf("decrypting %s: %v", ref, err)}
				}
				result.Values[ref] = val
			}
			return result, nil
		}
		// Fallback: server returned plaintext values
		return &ResolveResult{Values: raw.Values, Errors: raw.Errors}, nil
	}

	var result ResolveResult
	if err := c.doRequest("POST", "/v1/resolve", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// MintSession mints a session token for the given role using the current
// token as bootstrap auth. On success, replaces c.Token with the session token.
func (c *Client) MintSession(role string) error {
	mintBody := map[string]string{"role": role}
	if c.sealPubKey != "" {
		mintBody["seal_public_key"] = c.sealPubKey
	}

	var result struct {
		SessionToken string `json:"session_token"`
		ExpiresAt    string `json:"expires_at"`
		Role         string `json:"role"`
	}
	if err := c.doRequest("POST", "/v1/session/mint", mintBody, &result); err != nil {
		return err
	}

	c.Token = result.SessionToken
	c.Role = result.Role
	if exp, err := time.Parse(time.RFC3339, result.ExpiresAt); err == nil {
		c.sessionExp = exp
	}
	return nil
}

// RenewSession renews the current session token.
// Only works if the client holds a session token (from MintSession).
func (c *Client) RenewSession() error {
	var result struct {
		SessionToken string `json:"session_token"`
		ExpiresAt    string `json:"expires_at"`
	}
	if err := c.doRequest("POST", "/v1/session/renew", map[string]string{}, &result); err != nil {
		return err
	}
	c.Token = result.SessionToken
	if exp, err := time.Parse(time.RFC3339, result.ExpiresAt); err == nil {
		c.sessionExp = exp
	}
	return nil
}

// SessionInfo contains details about an active session.
type SessionInfo struct {
	SessionID       string   `json:"session_id"`
	Role            string   `json:"role"`
	Agent           string   `json:"agent"`
	Namespaces      []string `json:"namespaces"`
	Actions         []string `json:"actions"`
	BootstrapMethod string   `json:"bootstrap_method"`
	SourceIP        string   `json:"source_ip"`
	CreatedAt       string   `json:"created_at"`
	ExpiresAt       string   `json:"expires_at"`
	Revoked         bool     `json:"revoked"`
}

// ListSessions returns sessions visible to the caller.
func (c *Client) ListSessions() ([]SessionInfo, error) {
	var result struct {
		Sessions []SessionInfo `json:"sessions"`
	}
	if err := c.doRequest("GET", "/v1/sessions", nil, &result); err != nil {
		return nil, err
	}
	return result.Sessions, nil
}

// RevokeSession revokes a session by ID.
func (c *Client) RevokeSession(sessionID string) error {
	return c.doRequest("POST", "/v1/sessions/"+sessionID+"/revoke", map[string]string{}, nil)
}

// IsApprovalRequired returns true if the error indicates approval is needed.
func (e *Error) IsApprovalRequired() bool { return e.Code == "APPROVAL_REQUIRED" }

// IsSessionExpired returns true if the error indicates the session has expired.
func (e *Error) IsSessionExpired() bool { return e.Code == "SESSION_EXPIRED" }

// IsScopeExceeded returns true if the error indicates the request is outside session scope.
func (e *Error) IsScopeExceeded() bool { return e.Code == "SCOPE_EXCEEDED" }

// IsActionDenied returns true if the error indicates the action is not permitted.
func (e *Error) IsActionDenied() bool { return e.Code == "ACTION_DENIED" }

// IsSessionRevoked returns true if the error indicates the session was revoked.
func (e *Error) IsSessionRevoked() bool { return e.Code == "SESSION_REVOKED" }

func (c *Client) doRequest(method, path string, body interface{}, out interface{}) error {
	// Auto-renew session if nearing expiry (within 5 min)
	if c.Role != "" && !c.sessionExp.IsZero() && time.Until(c.sessionExp) < 5*time.Minute {
		_ = c.RenewSession() // best-effort
	}

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return &Error{Message: fmt.Sprintf("marshaling request: %v", err)}
		}
		bodyReader = strings.NewReader(string(data))
	}

	req, err := http.NewRequest(method, c.Server+path, bodyReader)
	if err != nil {
		return &Error{Message: fmt.Sprintf("building request: %v", err)}
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.sealPubKey != "" {
		req.Header.Set("X-Phoenix-Seal-Key", c.sealPubKey)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return &Error{Message: fmt.Sprintf("server unreachable: %v", err)}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return &Error{Message: fmt.Sprintf("reading response: %v", err), Status: resp.StatusCode}
	}

	if resp.StatusCode != http.StatusOK {
		var structured struct {
			Error       string `json:"error"`
			Code        string `json:"code"`
			Detail      string `json:"detail"`
			Remediation string `json:"remediation"`
		}
		if json.Unmarshal(respBody, &structured) == nil && structured.Code != "" {
			return &Error{
				Message:     structured.Detail,
				Status:      resp.StatusCode,
				Code:        structured.Code,
				Remediation: structured.Remediation,
			}
		}
		if json.Unmarshal(respBody, &structured) == nil && structured.Error != "" {
			return &Error{Message: structured.Error, Status: resp.StatusCode}
		}
		return &Error{Message: fmt.Sprintf("HTTP %d", resp.StatusCode), Status: resp.StatusCode}
	}

	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return &Error{Message: fmt.Sprintf("decoding response: %v", err)}
		}
	}
	return nil
}
