// MCP (Model Context Protocol) server for Phoenix.
//
// Runs as a stdio JSON-RPC server, bridging MCP tool calls to the Phoenix HTTP API.
// Agents interact with secrets through phoenix:// references without handling raw values
// in their prompts or configs.
//
// Usage:
//
//	phoenix mcp-server
//
// Configure in Claude Code / Claude Desktop:
//
//	{
//	  "mcpServers": {
//	    "phoenix": {
//	      "command": "phoenix",
//	      "args": ["mcp-server"],
//	      "env": {
//	        "PHOENIX_SERVER": "https://phoenix:9090",
//	        "PHOENIX_TOKEN": "..."
//	      }
//	    }
//	  }
//	}
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/phoenixsec/phoenix/internal/crypto"
	"github.com/phoenixsec/phoenix/internal/version"
)

// mcpSealPrivKey holds the loaded seal private key for MCP sealed mode.
// Set during cmdMCP startup if PHOENIX_SEAL_KEY is configured.
var mcpSealPrivKey *[32]byte

// JSON-RPC wire types.

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *mcpError       `json:"error,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCP result types.

type mcpInitializeResult struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ServerInfo      mcpServerInfo          `json:"serverInfo"`
}

type mcpServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type mcpTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

type mcpListToolsResult struct {
	Tools []mcpTool `json:"tools"`
}

type mcpContentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type mcpCallToolResult struct {
	Content []mcpContentItem `json:"content"`
	IsError bool             `json:"isError"`
}

type mcpCallToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// Tool definitions with JSON Schema input schemas.

var mcpBaseTools = []mcpTool{
	{
		Name:        "phoenix_resolve",
		Description: "Resolve one or more phoenix:// secret references to their values. References are opaque URIs like phoenix://namespace/secret-name. Returns the resolved values for each reference.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"refs": {
					"type": "array",
					"items": {"type": "string"},
					"description": "List of phoenix:// references to resolve"
				}
			},
			"required": ["refs"]
		}`),
	},
	{
		Name:        "phoenix_get",
		Description: "Get a single secret value by its path (e.g. 'namespace/secret-name').",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"path": {
					"type": "string",
					"description": "Secret path (e.g. 'myapp/api-key')"
				}
			},
			"required": ["path"]
		}`),
	},
	{
		Name:        "phoenix_list",
		Description: "List available secret paths. Optionally filter by a namespace prefix. Returns paths only, not secret values.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"prefix": {
					"type": "string",
					"description": "Optional namespace prefix to filter by (e.g. 'myapp/'). Omit to list all accessible secrets."
				}
			}
		}`),
	},
}

var mcpSessionTools = []mcpTool{
	{
		Name:        "phoenix_session_list",
		Description: "List active Phoenix sessions. Returns session IDs, roles, agents, and expiry times. Agents see their own sessions; admins see all.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {}
		}`),
	},
	{
		Name:        "phoenix_session_revoke",
		Description: "Revoke a Phoenix session by its ID. The session token becomes invalid immediately.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"session_id": {
					"type": "string",
					"description": "Session ID to revoke (e.g. 'ses_...')"
				}
			},
			"required": ["session_id"]
		}`),
	},
}

var mcpUnsealTool = mcpTool{
	Name:        "phoenix_unseal",
	Description: "Decrypt a sealed secret value. The decrypted value will be visible in this conversation. Only works when allow_unseal policy is set for the secret's path.",
	InputSchema: json.RawMessage(`{
		"type": "object",
		"properties": {
			"sealed": {
				"type": "string",
				"description": "Sealed token (PHOENIX_SEALED:...)"
			}
		},
		"required": ["sealed"]
	}`),
}

// mcpGetTools returns the tool list, including optional tools based on config.
func mcpGetTools() []mcpTool {
	tools := make([]mcpTool, len(mcpBaseTools))
	copy(tools, mcpBaseTools)
	tools = append(tools, mcpSessionTools...)
	if mcpSealPrivKey != nil {
		tools = append(tools, mcpUnsealTool)
	}
	return tools
}

// mcpHandleRequest processes a single JSON-RPC request and writes the
// response to enc. Notifications (no id) are silently ignored.
func mcpHandleRequest(req mcpRequest, enc *json.Encoder, logger *log.Logger) {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	// Notifications have no id — do not respond.
	if req.ID == nil {
		return
	}

	switch req.Method {
	case "initialize":
		mcpSendResult(enc, req.ID, mcpInitializeResult{
			ProtocolVersion: "2024-11-05",
			Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
			ServerInfo:      mcpServerInfo{Name: "phoenix", Version: version.Version},
		})

	case "tools/list":
		mcpSendResult(enc, req.ID, mcpListToolsResult{Tools: mcpGetTools()})

	case "tools/call":
		var params mcpCallToolParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			mcpSendError(enc, req.ID, -32602, "Invalid params")
			return
		}
		text, isErr := mcpDispatchTool(params.Name, params.Arguments, logger)
		mcpSendResult(enc, req.ID, mcpCallToolResult{
			Content: []mcpContentItem{{Type: "text", Text: text}},
			IsError: isErr,
		})

	default:
		mcpSendError(enc, req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

// cmdMCP runs the MCP stdio server.
func cmdMCP(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}

	// Load seal key if configured (supports role-bound session keys).
	sealKey, err := loadSealKeyForRequest()
	if err != nil {
		return fmt.Errorf("loading seal key: %w", err)
	}
	mcpSealPrivKey = sealKey

	// All logging goes to stderr — stdout is the MCP protocol channel.
	logger := log.New(os.Stderr, "phoenix-mcp: ", 0)
	if mcpSealPrivKey != nil {
		logger.Println("sealed mode enabled")
	}

	// Start background session renewal if using a session token
	if os.Getenv("PHOENIX_ROLE") != "" && strings.HasPrefix(token, "phxs_") {
		go sessionRenewalLoop(logger)
	}

	logger.Println("server starting (stdio)")

	dec := json.NewDecoder(os.Stdin)
	enc := json.NewEncoder(os.Stdout)

	for {
		var req mcpRequest
		if err := dec.Decode(&req); err != nil {
			if err == io.EOF {
				logger.Println("stdin closed, shutting down")
				return nil
			}
			mcpSendError(enc, nil, -32700, "Parse error")
			continue
		}
		mcpHandleRequest(req, enc, logger)
	}
}

// mcpDispatchTool routes a tool call to the appropriate handler.
// logger may be nil (e.g. in tests); tool handlers must handle this.
func mcpDispatchTool(name string, args json.RawMessage, logger *log.Logger) (string, bool) {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	switch name {
	case "phoenix_resolve":
		return mcpToolResolve(args, logger)
	case "phoenix_get":
		return mcpToolGet(args, logger)
	case "phoenix_list":
		return mcpToolList(args, logger)
	case "phoenix_unseal":
		return mcpToolUnseal(args, logger)
	case "phoenix_session_list":
		return mcpToolSessionList(args, logger)
	case "phoenix_session_revoke":
		return mcpToolSessionRevoke(args, logger)
	default:
		return fmt.Sprintf("Unknown tool: %s", name), true
	}
}

// mcpToolResolve handles the phoenix_resolve tool.
func mcpToolResolve(args json.RawMessage, logger *log.Logger) (string, bool) {
	var params struct {
		Refs []string `json:"refs"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return fmt.Sprintf("Invalid arguments: %v", err), true
	}
	if len(params.Refs) == 0 {
		return "No references provided", true
	}

	body, err := json.Marshal(map[string]interface{}{"refs": params.Refs})
	if err != nil {
		return fmt.Sprintf("Internal error: %v", err), true
	}

	hdrs := map[string]string{"X-Phoenix-Tool": "phoenix_resolve"}
	if mcpSealPrivKey != nil {
		for k, v := range sealHeaders(mcpSealPrivKey) {
			hdrs[k] = v
		}
	}

	resp, err := apiRequestWithHeaders("POST", "/v1/resolve", strings.NewReader(string(body)), hdrs)
	if err != nil {
		return fmt.Sprintf("Request failed: %v", err), true
	}
	defer resp.Body.Close()

	if resp.StatusCode == 202 {
		respBody, _ := io.ReadAll(resp.Body)
		return mcpFormatApprovalRequired(respBody), false
	}

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return mcpFormatDenial(respBody, resp.StatusCode), true
	}

	// Sealed mode: return opaque PHOENIX_SEALED: tokens
	if mcpSealPrivKey != nil {
		var result struct {
			SealedValues map[string]interface{} `json:"sealed_values"`
			Errors       map[string]string      `json:"errors"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Sprintf("Failed to decode response: %v", err), true
		}

		if len(result.SealedValues) == 0 && len(result.Errors) > 0 {
			var msgs []string
			for ref, errMsg := range result.Errors {
				msgs = append(msgs, fmt.Sprintf("%s: %s", ref, errMsg))
			}
			return strings.Join(msgs, "\n"), true
		}

		var lines []string
		hasErrors := len(result.Errors) > 0
		for _, ref := range params.Refs {
			if raw, ok := result.SealedValues[ref]; ok {
				if envMap, ok := raw.(map[string]interface{}); ok {
					if envRef, _ := envMap["ref"].(string); envRef != ref {
						lines = append(lines, fmt.Sprintf("%s: ERROR: sealed envelope ref mismatch (envelope has %q)", ref, envRef))
						hasErrors = true
						continue
					}
				}
				envJSON, _ := json.Marshal(raw)
				sealToken := "PHOENIX_SEALED:" + base64.StdEncoding.EncodeToString(envJSON)
				lines = append(lines, fmt.Sprintf("%s = %s", ref, sealToken))
			} else if errMsg, ok := result.Errors[ref]; ok {
				lines = append(lines, fmt.Sprintf("%s: ERROR: %s", ref, errMsg))
			} else {
				lines = append(lines, fmt.Sprintf("%s: ERROR: no value returned by server", ref))
				hasErrors = true
			}
		}

		logger.Printf("resolved %d/%d refs (sealed)", len(result.SealedValues), len(params.Refs))
		return strings.Join(lines, "\n"), hasErrors
	}

	// Plaintext mode
	var result struct {
		Values map[string]string `json:"values"`
		Errors map[string]string `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Sprintf("Failed to decode response: %v", err), true
	}

	if len(result.Values) == 0 && len(result.Errors) > 0 {
		var msgs []string
		for ref, errMsg := range result.Errors {
			msgs = append(msgs, fmt.Sprintf("%s: %s", ref, errMsg))
		}
		return strings.Join(msgs, "\n"), true
	}

	var lines []string
	for _, ref := range params.Refs {
		if val, ok := result.Values[ref]; ok {
			lines = append(lines, fmt.Sprintf("%s = %s", ref, val))
		} else if errMsg, ok := result.Errors[ref]; ok {
			lines = append(lines, fmt.Sprintf("%s: ERROR: %s", ref, errMsg))
		}
	}

	logger.Printf("resolved %d/%d refs", len(result.Values), len(params.Refs))
	hasErrors := len(result.Errors) > 0
	return strings.Join(lines, "\n"), hasErrors
}

// mcpToolGet handles the phoenix_get tool.
func mcpToolGet(args json.RawMessage, logger *log.Logger) (string, bool) {
	var params struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return fmt.Sprintf("Invalid arguments: %v", err), true
	}
	if params.Path == "" {
		return "Path is required", true
	}

	hdrs := map[string]string{"X-Phoenix-Tool": "phoenix_get"}
	if mcpSealPrivKey != nil {
		for k, v := range sealHeaders(mcpSealPrivKey) {
			hdrs[k] = v
		}
	}

	resp, err := apiRequestWithHeaders("GET", "/v1/secrets/"+params.Path, nil, hdrs)
	if err != nil {
		return fmt.Sprintf("Request failed: %v", err), true
	}
	defer resp.Body.Close()

	if resp.StatusCode == 202 {
		body, _ := io.ReadAll(resp.Body)
		return mcpFormatApprovalRequired(body), false
	}

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Sprintf("%s: %s", params.Path, mcpFormatDenial(body, resp.StatusCode)), true
	}

	// Sealed mode: return opaque PHOENIX_SEALED: token
	if mcpSealPrivKey != nil {
		var sealed struct {
			SealedValue interface{} `json:"sealed_value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&sealed); err != nil {
			return fmt.Sprintf("Failed to decode response: %v", err), true
		}
		if sealed.SealedValue == nil {
			return fmt.Sprintf("%s: expected sealed_value in response", params.Path), true
		}
		if envMap, ok := sealed.SealedValue.(map[string]interface{}); ok {
			if envPath, _ := envMap["path"].(string); envPath != params.Path {
				return fmt.Sprintf("%s: sealed envelope path mismatch (envelope has %q)", params.Path, envPath), true
			}
		}
		envJSON, _ := json.Marshal(sealed.SealedValue)
		token := "PHOENIX_SEALED:" + base64.StdEncoding.EncodeToString(envJSON)
		logger.Printf("get %s (sealed)", params.Path)
		return token, false
	}

	var result struct {
		Path  string `json:"path"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Sprintf("Failed to decode response: %v", err), true
	}

	logger.Printf("get %s", params.Path)
	return result.Value, false
}

// mcpToolList handles the phoenix_list tool.
func mcpToolList(args json.RawMessage, logger *log.Logger) (string, bool) {
	var params struct {
		Prefix string `json:"prefix"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return fmt.Sprintf("Invalid arguments: %v", err), true
	}

	path := "/v1/secrets/"
	if params.Prefix != "" {
		p := params.Prefix
		if !strings.HasSuffix(p, "/") {
			p += "/"
		}
		path = "/v1/secrets/" + p
	}

	resp, err := apiRequestWithHeaders("GET", path, nil,
		map[string]string{"X-Phoenix-Tool": "phoenix_list"})
	if err != nil {
		return fmt.Sprintf("Request failed: %v", err), true
	}
	defer resp.Body.Close()

	if resp.StatusCode == 202 {
		respBody, _ := io.ReadAll(resp.Body)
		return mcpFormatApprovalRequired(respBody), false
	}

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return mcpFormatDenial(respBody, resp.StatusCode), true
	}

	var result struct {
		Paths []string `json:"paths"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Sprintf("Failed to decode response: %v", err), true
	}

	if len(result.Paths) == 0 {
		return "No secrets found", false
	}

	logger.Printf("listed %d secrets", len(result.Paths))
	return strings.Join(result.Paths, "\n"), false
}

// mcpToolUnseal decrypts a sealed secret token locally.
func mcpToolUnseal(args json.RawMessage, logger *log.Logger) (string, bool) {
	if mcpSealPrivKey == nil {
		return "Sealed mode is not enabled (PHOENIX_SEAL_KEY not set)", true
	}

	var params struct {
		Sealed string `json:"sealed"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return fmt.Sprintf("Invalid arguments: %v", err), true
	}

	const prefix = "PHOENIX_SEALED:"
	if !strings.HasPrefix(params.Sealed, prefix) {
		return "Invalid sealed token: must start with PHOENIX_SEALED:", true
	}

	envJSON, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(params.Sealed, prefix))
	if err != nil {
		return fmt.Sprintf("Invalid sealed token: bad base64: %v", err), true
	}

	var env crypto.SealedEnvelope
	if err := json.Unmarshal(envJSON, &env); err != nil {
		return fmt.Sprintf("Invalid sealed envelope: %v", err), true
	}

	// Check allow_unseal via server policy (authoritative source)
	allowed, err := mcpCheckAllowUnseal(env.Path)
	if err != nil {
		return fmt.Sprintf("Policy check failed: %v", err), true
	}
	if !allowed {
		return "Unseal denied: allow_unseal is not set for this path", true
	}

	payload, err := crypto.OpenSealedEnvelope(&env, mcpSealPrivKey)
	if err != nil {
		return fmt.Sprintf("Decryption failed: %v", err), true
	}

	logger.Printf("unseal %s (value now visible in conversation)", env.Path)
	return payload.Value, false
}

// mcpCheckAllowUnseal queries the server's authoritative policy for allow_unseal.
func mcpCheckAllowUnseal(path string) (bool, error) {
	resp, err := apiRequest("GET", "/v1/policy/check?path="+path+"&check=allow_unseal", nil)
	if err != nil {
		return false, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var result struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("decoding response: %w", err)
	}
	return result.Allowed, nil
}

// sessionRenewalLoop runs in the background during MCP server mode,
// periodically renewing the session token before it expires.
func sessionRenewalLoop(logger *log.Logger) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		renewSessionIfNeeded()
		if logger != nil {
			logger.Println("session renewal check complete")
		}
	}
}

// mcpFormatDenial parses a structured denial response body and returns
// a formatted error string for the agent.
func mcpFormatDenial(body []byte, statusCode int) string {
	var denial struct {
		Error       string `json:"error"`
		Code        string `json:"code"`
		Detail      string `json:"detail"`
		Remediation string `json:"remediation"`
	}
	if json.Unmarshal(body, &denial) == nil && denial.Code != "" {
		msg := fmt.Sprintf("[%s] %s", denial.Code, denial.Detail)
		if denial.Remediation != "" {
			msg += "\nhint: " + denial.Remediation
		}
		return msg
	}
	if json.Unmarshal(body, &denial) == nil && denial.Error != "" {
		return denial.Error
	}
	return fmt.Sprintf("HTTP %d", statusCode)
}

// mcpFormatApprovalRequired parses a 202 approval-required response
// and returns a message suitable for an agent to present to the human.
func mcpFormatApprovalRequired(body []byte) string {
	var pending struct {
		Status     string `json:"status"`
		ApproveCmd string `json:"approve_command"`
		ExpiresAt  string `json:"expires_at"`
	}
	if json.Unmarshal(body, &pending) == nil && pending.Status == "approval_required" {
		msg := "[APPROVAL_REQUIRED] This operation requires human approval."
		if pending.ApproveCmd != "" {
			msg += "\nRun: " + pending.ApproveCmd
		}
		if pending.ExpiresAt != "" {
			msg += "\nExpires: " + pending.ExpiresAt
		}
		return msg
	}
	return "[APPROVAL_REQUIRED] This operation requires human approval."
}

// mcpToolSessionList handles the phoenix_session_list tool.
func mcpToolSessionList(args json.RawMessage, logger *log.Logger) (string, bool) {
	resp, err := apiRequest("GET", "/v1/sessions", nil)
	if err != nil {
		return fmt.Sprintf("Request failed: %v", err), true
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return mcpFormatDenial(body, resp.StatusCode), true
	}

	var result struct {
		Sessions []struct {
			SessionID string `json:"session_id"`
			Role      string `json:"role"`
			Agent     string `json:"agent"`
			CreatedAt string `json:"created_at"`
			ExpiresAt string `json:"expires_at"`
			SourceIP  string `json:"source_ip"`
		} `json:"sessions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Sprintf("Failed to decode response: %v", err), true
	}

	if len(result.Sessions) == 0 {
		return "No active sessions.", false
	}

	var lines []string
	for _, s := range result.Sessions {
		lines = append(lines, fmt.Sprintf("%s  role=%s  agent=%s  expires=%s  ip=%s",
			s.SessionID, s.Role, s.Agent, s.ExpiresAt, s.SourceIP))
	}
	logger.Printf("listed %d sessions", len(result.Sessions))
	return strings.Join(lines, "\n"), false
}

// mcpToolSessionRevoke handles the phoenix_session_revoke tool.
func mcpToolSessionRevoke(args json.RawMessage, logger *log.Logger) (string, bool) {
	var params struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return fmt.Sprintf("Invalid arguments: %v", err), true
	}
	if params.SessionID == "" {
		return "session_id is required", true
	}

	resp, err := apiRequest("POST", "/v1/sessions/"+params.SessionID+"/revoke", strings.NewReader("{}"))
	if err != nil {
		return fmt.Sprintf("Request failed: %v", err), true
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return mcpFormatDenial(body, resp.StatusCode), true
	}

	logger.Printf("revoked session %s", params.SessionID)
	return fmt.Sprintf("Session %s revoked.", params.SessionID), false
}

// mcpSendResult sends a successful JSON-RPC response.
func mcpSendResult(enc *json.Encoder, id json.RawMessage, result interface{}) {
	if err := enc.Encode(mcpResponse{JSONRPC: "2.0", ID: id, Result: result}); err != nil {
		log.New(os.Stderr, "phoenix-mcp: ", 0).Printf("encode error: %v", err)
	}
}

// mcpSendError sends a JSON-RPC error response.
func mcpSendError(enc *json.Encoder, id json.RawMessage, code int, msg string) {
	if err := enc.Encode(mcpResponse{JSONRPC: "2.0", ID: id, Error: &mcpError{Code: code, Message: msg}}); err != nil {
		log.New(os.Stderr, "phoenix-mcp: ", 0).Printf("encode error: %v", err)
	}
}
