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
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"git.home/vector/phoenix/internal/version"
)

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

var mcpTools = []mcpTool{
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

// cmdMCP runs the MCP stdio server.
func cmdMCP(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}

	// All logging goes to stderr — stdout is the MCP protocol channel.
	logger := log.New(os.Stderr, "phoenix-mcp: ", 0)
	logger.Println("server starting")

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

		// Notifications have no id — do not respond.
		if req.ID == nil {
			continue
		}

		switch req.Method {
		case "initialize":
			mcpSendResult(enc, req.ID, mcpInitializeResult{
				ProtocolVersion: "2024-11-05",
				Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
				ServerInfo:      mcpServerInfo{Name: "phoenix", Version: version.Version},
			})

		case "tools/list":
			mcpSendResult(enc, req.ID, mcpListToolsResult{Tools: mcpTools})

		case "tools/call":
			var params mcpCallToolParams
			if err := json.Unmarshal(req.Params, &params); err != nil {
				mcpSendError(enc, req.ID, -32602, "Invalid params")
				continue
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

	resp, err := apiRequestWithHeaders("POST", "/v1/resolve", strings.NewReader(string(body)),
		map[string]string{"X-Phoenix-Tool": "phoenix_resolve"})
	if err != nil {
		return fmt.Sprintf("Request failed: %v", err), true
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Sprintf("Server error: HTTP %d", resp.StatusCode), true
	}

	var result struct {
		Values map[string]string `json:"values"`
		Errors map[string]string `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Sprintf("Failed to decode response: %v", err), true
	}

	// If all refs failed, report errors.
	if len(result.Values) == 0 && len(result.Errors) > 0 {
		var msgs []string
		for ref, errMsg := range result.Errors {
			msgs = append(msgs, fmt.Sprintf("%s: %s", ref, errMsg))
		}
		return strings.Join(msgs, "\n"), true
	}

	// Build output: values first, then any partial errors.
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

	resp, err := apiRequestWithHeaders("GET", "/v1/secrets/"+params.Path, nil,
		map[string]string{"X-Phoenix-Tool": "phoenix_get"})
	if err != nil {
		return fmt.Sprintf("Request failed: %v", err), true
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		var errResp struct {
			Error string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Error != "" {
			return fmt.Sprintf("%s: %s", params.Path, errResp.Error), true
		}
		return fmt.Sprintf("%s: HTTP %d", params.Path, resp.StatusCode), true
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

	if resp.StatusCode != 200 {
		var errResp struct {
			Error string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Error != "" {
			return errResp.Error, true
		}
		return fmt.Sprintf("HTTP %d", resp.StatusCode), true
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
