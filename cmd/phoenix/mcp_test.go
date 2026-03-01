package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"git.home/vector/phoenix/internal/version"
)

// mcpExchange sends JSON-RPC messages to the MCP server loop and collects responses.
// It replaces os.Stdin/os.Stdout to pipe messages through the server, and
// sets up a mock Phoenix HTTP server for tool calls.
func mcpExchange(t *testing.T, handler http.HandlerFunc, messages ...string) []mcpResponse {
	t.Helper()

	// Set up mock Phoenix server.
	ts := httptest.NewServer(handler)
	defer ts.Close()

	oldURL := serverURL
	oldToken := token
	oldClient := httpClient
	serverURL = ts.URL
	token = "test-token"
	httpClient = ts.Client()
	defer func() {
		serverURL = oldURL
		token = oldToken
		httpClient = oldClient
	}()

	// Build input from messages.
	input := strings.Join(messages, "\n") + "\n"

	// Run the MCP server with piped stdin/stdout.
	inReader := strings.NewReader(input)
	var outBuf bytes.Buffer

	dec := json.NewDecoder(inReader)
	enc := json.NewEncoder(&outBuf)

	// Simulate the server loop inline (we can't call cmdMCP because it
	// reads os.Stdin, so we replicate the loop logic with our own reader).
	for {
		var req mcpRequest
		if err := dec.Decode(&req); err != nil {
			if err == io.EOF {
				break
			}
			mcpSendError(enc, nil, -32700, "Parse error")
			continue
		}

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
			text, isErr := mcpDispatchTool(params.Name, params.Arguments, nil)
			mcpSendResult(enc, req.ID, mcpCallToolResult{
				Content: []mcpContentItem{{Type: "text", Text: text}},
				IsError: isErr,
			})
		default:
			mcpSendError(enc, req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
		}
	}

	// Parse responses.
	var responses []mcpResponse
	respDec := json.NewDecoder(&outBuf)
	for {
		var resp mcpResponse
		if err := respDec.Decode(&resp); err != nil {
			break
		}
		responses = append(responses, resp)
	}

	return responses
}

func jsonMsg(id interface{}, method string, params interface{}) string {
	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
	}
	if id != nil {
		msg["id"] = id
	}
	if params != nil {
		msg["params"] = params
	}
	b, _ := json.Marshal(msg)
	return string(b)
}

func TestMCPInitialize(t *testing.T) {
	responses := mcpExchange(t, nil,
		jsonMsg(1, "initialize", map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "test", "version": "1.0"},
		}),
	)

	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	resp := responses[0]
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	// Check the result contains server info.
	b, _ := json.Marshal(resp.Result)
	var result mcpInitializeResult
	if err := json.Unmarshal(b, &result); err != nil {
		t.Fatalf("failed to decode result: %v", err)
	}
	if result.ProtocolVersion != "2024-11-05" {
		t.Errorf("protocol version = %q, want %q", result.ProtocolVersion, "2024-11-05")
	}
	if result.ServerInfo.Name != "phoenix" {
		t.Errorf("server name = %q, want %q", result.ServerInfo.Name, "phoenix")
	}
	if result.ServerInfo.Version != version.Version {
		t.Errorf("server version = %q, want %q", result.ServerInfo.Version, version.Version)
	}
}

func TestMCPToolsList(t *testing.T) {
	responses := mcpExchange(t, nil,
		jsonMsg(1, "tools/list", nil),
	)

	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	b, _ := json.Marshal(responses[0].Result)
	var result mcpListToolsResult
	if err := json.Unmarshal(b, &result); err != nil {
		t.Fatalf("failed to decode result: %v", err)
	}

	if len(result.Tools) != 3 {
		t.Fatalf("expected 3 tools, got %d", len(result.Tools))
	}

	names := map[string]bool{}
	for _, tool := range result.Tools {
		names[tool.Name] = true
		if len(tool.InputSchema) == 0 {
			t.Errorf("tool %q has empty inputSchema", tool.Name)
		}
	}

	for _, expected := range []string{"phoenix_resolve", "phoenix_get", "phoenix_list"} {
		if !names[expected] {
			t.Errorf("missing tool %q", expected)
		}
	}
}

func TestMCPNotificationNoResponse(t *testing.T) {
	responses := mcpExchange(t, nil,
		// Notification — no id field.
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		// Then a real request to prove the server is still running.
		jsonMsg(1, "tools/list", nil),
	)

	// Should only get 1 response (for tools/list), not for the notification.
	if len(responses) != 1 {
		t.Fatalf("expected 1 response (notification should produce none), got %d", len(responses))
	}
}

func TestMCPUnknownMethod(t *testing.T) {
	responses := mcpExchange(t, nil,
		jsonMsg(1, "resources/list", nil),
	)

	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	if responses[0].Error == nil {
		t.Fatal("expected error response for unknown method")
	}
	if responses[0].Error.Code != -32601 {
		t.Errorf("error code = %d, want -32601", responses[0].Error.Code)
	}
}

func TestMCPUnknownTool(t *testing.T) {
	responses := mcpExchange(t, nil,
		jsonMsg(1, "tools/call", map[string]interface{}{
			"name":      "nonexistent_tool",
			"arguments": map[string]interface{}{},
		}),
	)

	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	b, _ := json.Marshal(responses[0].Result)
	var result mcpCallToolResult
	json.Unmarshal(b, &result)

	if !result.IsError {
		t.Error("expected isError=true for unknown tool")
	}
	if !strings.Contains(result.Content[0].Text, "Unknown tool") {
		t.Errorf("expected 'Unknown tool' in error text, got %q", result.Content[0].Text)
	}
}

func TestMCPToolResolve(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/resolve" {
			http.Error(w, "not found", 404)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", 401)
			return
		}
		var req struct {
			Refs []string `json:"refs"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		values := map[string]string{}
		for _, ref := range req.Refs {
			values[ref] = "resolved-value-for-" + ref
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"values": values})
	})

	responses := mcpExchange(t, handler,
		jsonMsg(1, "tools/call", map[string]interface{}{
			"name": "phoenix_resolve",
			"arguments": map[string]interface{}{
				"refs": []string{"phoenix://myapp/api-key"},
			},
		}),
	)

	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	b, _ := json.Marshal(responses[0].Result)
	var result mcpCallToolResult
	json.Unmarshal(b, &result)

	if result.IsError {
		t.Errorf("unexpected error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "resolved-value-for-phoenix://myapp/api-key") {
		t.Errorf("unexpected result text: %s", result.Content[0].Text)
	}
}

func TestMCPToolResolvePartialError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"values": map[string]string{"phoenix://myapp/key1": "val1"},
			"errors": map[string]string{"phoenix://myapp/key2": "access denied"},
		})
	})

	responses := mcpExchange(t, handler,
		jsonMsg(1, "tools/call", map[string]interface{}{
			"name": "phoenix_resolve",
			"arguments": map[string]interface{}{
				"refs": []string{"phoenix://myapp/key1", "phoenix://myapp/key2"},
			},
		}),
	)

	b, _ := json.Marshal(responses[0].Result)
	var result mcpCallToolResult
	json.Unmarshal(b, &result)

	if !result.IsError {
		t.Error("expected isError=true for partial failure")
	}
	text := result.Content[0].Text
	if !strings.Contains(text, "val1") {
		t.Errorf("expected successful value in output, got: %s", text)
	}
	if !strings.Contains(text, "access denied") {
		t.Errorf("expected error message in output, got: %s", text)
	}
}

func TestMCPToolGet(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/secrets/myapp/db-password" {
			http.Error(w, `{"error":"not found"}`, 404)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"path":  "myapp/db-password",
			"value": "s3cret",
		})
	})

	responses := mcpExchange(t, handler,
		jsonMsg(1, "tools/call", map[string]interface{}{
			"name": "phoenix_get",
			"arguments": map[string]interface{}{
				"path": "myapp/db-password",
			},
		}),
	)

	b, _ := json.Marshal(responses[0].Result)
	var result mcpCallToolResult
	json.Unmarshal(b, &result)

	if result.IsError {
		t.Errorf("unexpected error: %s", result.Content[0].Text)
	}
	if result.Content[0].Text != "s3cret" {
		t.Errorf("expected 's3cret', got %q", result.Content[0].Text)
	}
}

func TestMCPToolGetNotFound(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(map[string]string{"error": "secret not found"})
	})

	responses := mcpExchange(t, handler,
		jsonMsg(1, "tools/call", map[string]interface{}{
			"name": "phoenix_get",
			"arguments": map[string]interface{}{
				"path": "myapp/nonexistent",
			},
		}),
	)

	b, _ := json.Marshal(responses[0].Result)
	var result mcpCallToolResult
	json.Unmarshal(b, &result)

	if !result.IsError {
		t.Error("expected isError=true for not found")
	}
	if !strings.Contains(result.Content[0].Text, "secret not found") {
		t.Errorf("expected 'secret not found' in error, got %q", result.Content[0].Text)
	}
}

func TestMCPToolList(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/secrets/myapp/" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"paths": []string{"myapp/key1", "myapp/key2", "myapp/key3"},
		})
	})

	responses := mcpExchange(t, handler,
		jsonMsg(1, "tools/call", map[string]interface{}{
			"name": "phoenix_list",
			"arguments": map[string]interface{}{
				"prefix": "myapp/",
			},
		}),
	)

	b, _ := json.Marshal(responses[0].Result)
	var result mcpCallToolResult
	json.Unmarshal(b, &result)

	if result.IsError {
		t.Errorf("unexpected error: %s", result.Content[0].Text)
	}

	lines := strings.Split(result.Content[0].Text, "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 paths, got %d: %v", len(lines), lines)
	}
}

func TestMCPToolListAll(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/secrets/" {
			t.Errorf("expected path /v1/secrets/, got %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"paths": []string{"a/key1", "b/key2"},
		})
	})

	responses := mcpExchange(t, handler,
		jsonMsg(1, "tools/call", map[string]interface{}{
			"name":      "phoenix_list",
			"arguments": map[string]interface{}{},
		}),
	)

	b, _ := json.Marshal(responses[0].Result)
	var result mcpCallToolResult
	json.Unmarshal(b, &result)

	if result.IsError {
		t.Errorf("unexpected error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "a/key1") {
		t.Errorf("expected paths in output, got: %s", result.Content[0].Text)
	}
}

func TestMCPToolResolveEmpty(t *testing.T) {
	responses := mcpExchange(t, nil,
		jsonMsg(1, "tools/call", map[string]interface{}{
			"name": "phoenix_resolve",
			"arguments": map[string]interface{}{
				"refs": []string{},
			},
		}),
	)

	b, _ := json.Marshal(responses[0].Result)
	var result mcpCallToolResult
	json.Unmarshal(b, &result)

	if !result.IsError {
		t.Error("expected isError=true for empty refs")
	}
}

func TestMCPToolGetEmptyPath(t *testing.T) {
	responses := mcpExchange(t, nil,
		jsonMsg(1, "tools/call", map[string]interface{}{
			"name": "phoenix_get",
			"arguments": map[string]interface{}{
				"path": "",
			},
		}),
	)

	b, _ := json.Marshal(responses[0].Result)
	var result mcpCallToolResult
	json.Unmarshal(b, &result)

	if !result.IsError {
		t.Error("expected isError=true for empty path")
	}
}

func TestMCPMultipleRequests(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/secrets/":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"paths": []string{"ns/key1"},
			})
		case "/v1/secrets/ns/key1":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"path": "ns/key1", "value": "val1",
			})
		default:
			http.Error(w, "not found", 404)
		}
	})

	responses := mcpExchange(t, handler,
		jsonMsg(1, "initialize", map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "test", "version": "1.0"},
		}),
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		jsonMsg(2, "tools/list", nil),
		jsonMsg(3, "tools/call", map[string]interface{}{
			"name":      "phoenix_list",
			"arguments": map[string]interface{}{},
		}),
		jsonMsg(4, "tools/call", map[string]interface{}{
			"name":      "phoenix_get",
			"arguments": map[string]interface{}{"path": "ns/key1"},
		}),
	)

	// 4 responses: initialize, tools/list, list tool, get tool
	// (notification produces no response)
	if len(responses) != 4 {
		t.Fatalf("expected 4 responses, got %d", len(responses))
	}

	// Verify IDs match
	for i, expectedID := range []int{1, 2, 3, 4} {
		var id int
		json.Unmarshal(responses[i].ID, &id)
		if id != expectedID {
			t.Errorf("response %d: id = %d, want %d", i, id, expectedID)
		}
	}
}

func TestMCPParseErrorReturnsNullID(t *testing.T) {
	// JSON-RPC 2.0 spec: parse errors must return "id": null.
	// We test the serialization directly because json.Decoder does not
	// reliably recover after a parse error on a stream, which means
	// the mcpExchange loop-simulation can't test recovery.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	mcpSendError(enc, nil, -32700, "Parse error")

	var resp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   *mcpError       `json:"error"`
	}
	if err := json.NewDecoder(&buf).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.Error == nil {
		t.Fatal("expected error in response")
	}
	if resp.Error.Code != -32700 {
		t.Errorf("error code = %d, want -32700", resp.Error.Code)
	}
	// ID must be present as JSON null, not omitted
	if string(resp.ID) != "null" {
		t.Errorf("id = %s, want null", string(resp.ID))
	}

	// Verify raw JSON contains "id":null explicitly
	var buf2 bytes.Buffer
	enc2 := json.NewEncoder(&buf2)
	mcpSendError(enc2, nil, -32700, "Parse error")
	raw := buf2.String()
	if !strings.Contains(raw, `"id":null`) {
		t.Errorf("raw JSON should contain \"id\":null, got: %s", raw)
	}
}

func TestMCPToolResolveSendsToolHeader(t *testing.T) {
	var capturedHeader string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeader = r.Header.Get("X-Phoenix-Tool")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"values": map[string]string{"phoenix://test/key": "val"},
		})
	})

	mcpExchange(t, handler,
		jsonMsg(1, "tools/call", map[string]interface{}{
			"name": "phoenix_resolve",
			"arguments": map[string]interface{}{
				"refs": []string{"phoenix://test/key"},
			},
		}),
	)

	if capturedHeader != "phoenix_resolve" {
		t.Errorf("X-Phoenix-Tool = %q, want %q", capturedHeader, "phoenix_resolve")
	}
}

func TestMCPToolGetSendsToolHeader(t *testing.T) {
	var capturedHeader string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeader = r.Header.Get("X-Phoenix-Tool")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"path": "test/key", "value": "val",
		})
	})

	mcpExchange(t, handler,
		jsonMsg(1, "tools/call", map[string]interface{}{
			"name":      "phoenix_get",
			"arguments": map[string]interface{}{"path": "test/key"},
		}),
	)

	if capturedHeader != "phoenix_get" {
		t.Errorf("X-Phoenix-Tool = %q, want %q", capturedHeader, "phoenix_get")
	}
}

func TestMCPToolListSendsToolHeader(t *testing.T) {
	var capturedHeader string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeader = r.Header.Get("X-Phoenix-Tool")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"paths": []string{"test/key"},
		})
	})

	mcpExchange(t, handler,
		jsonMsg(1, "tools/call", map[string]interface{}{
			"name":      "phoenix_list",
			"arguments": map[string]interface{}{},
		}),
	)

	if capturedHeader != "phoenix_list" {
		t.Errorf("X-Phoenix-Tool = %q, want %q", capturedHeader, "phoenix_list")
	}
}

// TestMCPE2ERealStdinStdout exercises cmdMCP with actual stdin/stdout replacement,
// verifying the full server lifecycle: startup, protocol exchange, and clean shutdown.
func TestMCPE2ERealStdinStdout(t *testing.T) {
	// Set up mock Phoenix server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/secrets/":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"paths": []string{"e2e/secret1"},
			})
		default:
			http.Error(w, "not found", 404)
		}
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	oldURL := serverURL
	oldToken := token
	oldClient := httpClient
	serverURL = ts.URL
	token = "e2e-test-token"
	httpClient = ts.Client()
	defer func() {
		serverURL = oldURL
		token = oldToken
		httpClient = oldClient
	}()

	// Build input: initialize, notification, tools/list, tool call, then EOF
	messages := []string{
		jsonMsg(1, "initialize", map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "e2e-test", "version": "1.0"},
		}),
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		jsonMsg(2, "tools/list", nil),
		jsonMsg(3, "tools/call", map[string]interface{}{
			"name":      "phoenix_list",
			"arguments": map[string]interface{}{},
		}),
	}
	input := strings.Join(messages, "\n") + "\n"

	// Replace stdin/stdout
	origStdin := os.Stdin
	origStdout := os.Stdout
	defer func() {
		os.Stdin = origStdin
		os.Stdout = origStdout
	}()

	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating stdin pipe: %v", err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating stdout pipe: %v", err)
	}

	os.Stdin = inR
	os.Stdout = outW

	// Write input and close to signal EOF
	go func() {
		inW.Write([]byte(input))
		inW.Close()
	}()

	// Run cmdMCP in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- cmdMCP(nil)
		outW.Close()
	}()

	// Read all output
	var outBuf bytes.Buffer
	io.Copy(&outBuf, outR)

	if err := <-errCh; err != nil {
		t.Fatalf("cmdMCP returned error: %v", err)
	}

	// Parse responses
	var responses []mcpResponse
	dec := json.NewDecoder(&outBuf)
	for {
		var resp mcpResponse
		if err := dec.Decode(&resp); err != nil {
			break
		}
		responses = append(responses, resp)
	}

	// Expect 3 responses: initialize, tools/list, tools/call (notification has no response)
	if len(responses) != 3 {
		t.Fatalf("expected 3 responses, got %d", len(responses))
	}

	// Verify initialize response
	var id int
	json.Unmarshal(responses[0].ID, &id)
	if id != 1 {
		t.Errorf("first response id = %d, want 1", id)
	}
	if responses[0].Error != nil {
		t.Errorf("initialize should not error: %v", responses[0].Error)
	}

	// Verify tools/list response
	json.Unmarshal(responses[1].ID, &id)
	if id != 2 {
		t.Errorf("second response id = %d, want 2", id)
	}

	// Verify tool call response contains our secret path
	json.Unmarshal(responses[2].ID, &id)
	if id != 3 {
		t.Errorf("third response id = %d, want 3", id)
	}
	b, _ := json.Marshal(responses[2].Result)
	var toolResult mcpCallToolResult
	json.Unmarshal(b, &toolResult)
	if toolResult.IsError {
		t.Errorf("tool call should succeed, got error: %s", toolResult.Content[0].Text)
	}
	if !strings.Contains(toolResult.Content[0].Text, "e2e/secret1") {
		t.Errorf("expected 'e2e/secret1' in output, got: %s", toolResult.Content[0].Text)
	}
}
