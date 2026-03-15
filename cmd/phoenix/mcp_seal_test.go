package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/phoenixsec/phoenix/internal/crypto"
)

// withSealKey sets up mcpSealPrivKey for the test and restores it after.
func withSealKey(t *testing.T, privKey *[32]byte) {
	t.Helper()
	old := mcpSealPrivKey
	mcpSealPrivKey = privKey
	t.Cleanup(func() { mcpSealPrivKey = old })
}

// policyCheckHandler returns a handler that serves /v1/policy/check responses.
// allowPaths maps path → allowed. Paths not in the map return allowed=false.
func policyCheckHandler(allowPaths map[string]bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/policy/check" {
			path := r.URL.Query().Get("path")
			allowed := allowPaths[path]
			json.NewEncoder(w).Encode(map[string]interface{}{
				"path":    path,
				"check":   r.URL.Query().Get("check"),
				"allowed": allowed,
			})
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// --- Tool list tests ---

func TestMCPToolsListWithSealKey(t *testing.T) {
	kp, _ := crypto.GenerateSealKeyPair()
	withSealKey(t, &kp.PrivateKey)

	responses := mcpExchange(t, nil,
		jsonMsg(1, "tools/list", nil),
	)

	b, _ := json.Marshal(responses[0].Result)
	var result mcpListToolsResult
	json.Unmarshal(b, &result)

	if len(result.Tools) != 6 {
		t.Fatalf("expected 6 tools (incl. unseal + session), got %d", len(result.Tools))
	}

	names := map[string]bool{}
	for _, tool := range result.Tools {
		names[tool.Name] = true
	}
	if !names["phoenix_unseal"] {
		t.Error("expected phoenix_unseal in tool list when seal key is set")
	}
}

func TestMCPToolsListWithoutSealKey(t *testing.T) {
	withSealKey(t, nil)

	responses := mcpExchange(t, nil,
		jsonMsg(1, "tools/list", nil),
	)

	b, _ := json.Marshal(responses[0].Result)
	var result mcpListToolsResult
	json.Unmarshal(b, &result)

	if len(result.Tools) != 5 {
		t.Fatalf("expected 5 tools (no unseal), got %d", len(result.Tools))
	}

	for _, tool := range result.Tools {
		if tool.Name == "phoenix_unseal" {
			t.Error("phoenix_unseal should not appear without seal key")
		}
	}
}

// --- Sealed resolve test ---

func TestMCPToolResolveSealedOutput(t *testing.T) {
	kp, _ := crypto.GenerateSealKeyPair()
	withSealKey(t, &kp.PrivateKey)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sealKey := r.Header.Get("X-Phoenix-Seal-Key")
		if sealKey == "" {
			t.Error("expected X-Phoenix-Seal-Key header in sealed mode")
		}
		pubKey, _ := crypto.DecodeSealKey(sealKey)
		env, _ := crypto.SealValue("myapp/api-key", "phoenix://myapp/api-key", "secret123", pubKey)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sealed_values": map[string]interface{}{
				"phoenix://myapp/api-key": env,
			},
		})
	})

	responses := mcpExchange(t, handler,
		jsonMsg(1, "tools/call", map[string]interface{}{
			"name": "phoenix_resolve",
			"arguments": map[string]interface{}{
				"refs": []string{"phoenix://myapp/api-key"},
			},
		}),
	)

	b, _ := json.Marshal(responses[0].Result)
	var result mcpCallToolResult
	json.Unmarshal(b, &result)

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].Text)
	}

	text := result.Content[0].Text
	if !strings.Contains(text, "PHOENIX_SEALED:") {
		t.Fatalf("expected PHOENIX_SEALED: token, got: %s", text)
	}
	if strings.Contains(text, "secret123") {
		t.Fatal("plaintext value should not appear in sealed output")
	}
}

// --- Sealed get test ---

func TestMCPToolGetSealedOutput(t *testing.T) {
	kp, _ := crypto.GenerateSealKeyPair()
	withSealKey(t, &kp.PrivateKey)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sealKey := r.Header.Get("X-Phoenix-Seal-Key")
		pubKey, _ := crypto.DecodeSealKey(sealKey)
		env, _ := crypto.SealValue("myapp/db-pass", "", "hunter2", pubKey)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sealed_value": env,
		})
	})

	responses := mcpExchange(t, handler,
		jsonMsg(1, "tools/call", map[string]interface{}{
			"name": "phoenix_get",
			"arguments": map[string]interface{}{
				"path": "myapp/db-pass",
			},
		}),
	)

	b, _ := json.Marshal(responses[0].Result)
	var result mcpCallToolResult
	json.Unmarshal(b, &result)

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].Text)
	}

	text := result.Content[0].Text
	if !strings.HasPrefix(text, "PHOENIX_SEALED:") {
		t.Fatalf("expected PHOENIX_SEALED: prefix, got: %s", text)
	}
	if strings.Contains(text, "hunter2") {
		t.Fatal("plaintext value should not appear in sealed output")
	}
}

// --- Unseal tests ---

func TestMCPToolUnsealWithAllowPolicy(t *testing.T) {
	kp, _ := crypto.GenerateSealKeyPair()
	withSealKey(t, &kp.PrivateKey)

	env, _ := crypto.SealValue("myapp/secret", "phoenix://myapp/secret", "the-value", &kp.PublicKey)
	envJSON, _ := json.Marshal(env)
	sealedToken := "PHOENIX_SEALED:" + base64.StdEncoding.EncodeToString(envJSON)

	handler := policyCheckHandler(map[string]bool{"myapp/secret": true})

	responses := mcpExchange(t, handler,
		jsonMsg(1, "tools/call", map[string]interface{}{
			"name": "phoenix_unseal",
			"arguments": map[string]interface{}{
				"sealed": sealedToken,
			},
		}),
	)

	b, _ := json.Marshal(responses[0].Result)
	var result mcpCallToolResult
	json.Unmarshal(b, &result)

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].Text)
	}
	if result.Content[0].Text != "the-value" {
		t.Fatalf("got %q, want %q", result.Content[0].Text, "the-value")
	}
}

func TestMCPToolUnsealDeniedByServer(t *testing.T) {
	kp, _ := crypto.GenerateSealKeyPair()
	withSealKey(t, &kp.PrivateKey)

	env, _ := crypto.SealValue("myapp/secret", "phoenix://myapp/secret", "the-value", &kp.PublicKey)
	envJSON, _ := json.Marshal(env)
	sealedToken := "PHOENIX_SEALED:" + base64.StdEncoding.EncodeToString(envJSON)

	// Server says allow_unseal=false for this path
	handler := policyCheckHandler(map[string]bool{})

	responses := mcpExchange(t, handler,
		jsonMsg(1, "tools/call", map[string]interface{}{
			"name": "phoenix_unseal",
			"arguments": map[string]interface{}{
				"sealed": sealedToken,
			},
		}),
	)

	b, _ := json.Marshal(responses[0].Result)
	var result mcpCallToolResult
	json.Unmarshal(b, &result)

	if !result.IsError {
		t.Fatal("expected error when server denies allow_unseal")
	}
	if !strings.Contains(result.Content[0].Text, "Unseal denied") {
		t.Fatalf("expected 'Unseal denied', got: %s", result.Content[0].Text)
	}
}

func TestMCPToolUnsealDeniedWrongPath(t *testing.T) {
	kp, _ := crypto.GenerateSealKeyPair()
	withSealKey(t, &kp.PrivateKey)

	env, _ := crypto.SealValue("myapp/secret", "phoenix://myapp/secret", "the-value", &kp.PublicKey)
	envJSON, _ := json.Marshal(env)
	sealedToken := "PHOENIX_SEALED:" + base64.StdEncoding.EncodeToString(envJSON)

	// Server allows "other/secret" but not "myapp/secret"
	handler := policyCheckHandler(map[string]bool{"other/secret": true})

	responses := mcpExchange(t, handler,
		jsonMsg(1, "tools/call", map[string]interface{}{
			"name": "phoenix_unseal",
			"arguments": map[string]interface{}{
				"sealed": sealedToken,
			},
		}),
	)

	b, _ := json.Marshal(responses[0].Result)
	var result mcpCallToolResult
	json.Unmarshal(b, &result)

	if !result.IsError {
		t.Fatal("expected error when path doesn't match allow_unseal")
	}
	if !strings.Contains(result.Content[0].Text, "Unseal denied") {
		t.Fatalf("expected 'Unseal denied', got: %s", result.Content[0].Text)
	}
}

func TestMCPToolUnsealTamperedEnvelope(t *testing.T) {
	kp, _ := crypto.GenerateSealKeyPair()
	withSealKey(t, &kp.PrivateKey)

	env, _ := crypto.SealValue("myapp/secret", "phoenix://myapp/secret", "the-value", &kp.PublicKey)
	envJSON, _ := json.Marshal(env)

	// Tamper with the ciphertext
	tampered := strings.Replace(string(envJSON), env.Ciphertext[:4], "XXXX", 1)
	sealedToken := "PHOENIX_SEALED:" + base64.StdEncoding.EncodeToString([]byte(tampered))

	handler := policyCheckHandler(map[string]bool{"myapp/secret": true})

	responses := mcpExchange(t, handler,
		jsonMsg(1, "tools/call", map[string]interface{}{
			"name": "phoenix_unseal",
			"arguments": map[string]interface{}{
				"sealed": sealedToken,
			},
		}),
	)

	b, _ := json.Marshal(responses[0].Result)
	var result mcpCallToolResult
	json.Unmarshal(b, &result)

	if !result.IsError {
		t.Fatal("expected error for tampered envelope")
	}
	if !strings.Contains(result.Content[0].Text, "Decryption failed") {
		t.Fatalf("expected 'Decryption failed', got: %s", result.Content[0].Text)
	}
}

func TestMCPToolUnsealInvalidToken(t *testing.T) {
	kp, _ := crypto.GenerateSealKeyPair()
	withSealKey(t, &kp.PrivateKey)

	responses := mcpExchange(t, nil,
		jsonMsg(1, "tools/call", map[string]interface{}{
			"name": "phoenix_unseal",
			"arguments": map[string]interface{}{
				"sealed": "not-a-sealed-token",
			},
		}),
	)

	b, _ := json.Marshal(responses[0].Result)
	var result mcpCallToolResult
	json.Unmarshal(b, &result)

	if !result.IsError {
		t.Fatal("expected error for invalid token")
	}
	if !strings.Contains(result.Content[0].Text, "must start with PHOENIX_SEALED:") {
		t.Fatalf("unexpected error: %s", result.Content[0].Text)
	}
}

func TestMCPToolUnsealNoSealKey(t *testing.T) {
	withSealKey(t, nil)

	responses := mcpExchange(t, nil,
		jsonMsg(1, "tools/call", map[string]interface{}{
			"name": "phoenix_unseal",
			"arguments": map[string]interface{}{
				"sealed": "PHOENIX_SEALED:dGVzdA==",
			},
		}),
	)

	b, _ := json.Marshal(responses[0].Result)
	var result mcpCallToolResult
	json.Unmarshal(b, &result)

	if !result.IsError {
		t.Fatal("expected error when seal key is not loaded")
	}
	if !strings.Contains(result.Content[0].Text, "not enabled") {
		t.Fatalf("unexpected error: %s", result.Content[0].Text)
	}
}

// --- Sealed resolve missing ref ---

func TestMCPToolResolveSealedMissingRef(t *testing.T) {
	kp, _ := crypto.GenerateSealKeyPair()
	withSealKey(t, &kp.PrivateKey)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return empty sealed_values — ref is missing
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sealed_values": map[string]interface{}{},
		})
	})

	responses := mcpExchange(t, handler,
		jsonMsg(1, "tools/call", map[string]interface{}{
			"name": "phoenix_resolve",
			"arguments": map[string]interface{}{
				"refs": []string{"phoenix://myapp/missing"},
			},
		}),
	)

	b, _ := json.Marshal(responses[0].Result)
	var result mcpCallToolResult
	json.Unmarshal(b, &result)

	if !result.IsError {
		t.Fatal("expected error for missing ref")
	}
	if !strings.Contains(result.Content[0].Text, "no value returned") {
		t.Fatalf("expected 'no value returned', got: %s", result.Content[0].Text)
	}
}

// --- Backward compatibility ---

func TestMCPToolResolvePlaintextWithoutSealKey(t *testing.T) {
	withSealKey(t, nil)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Phoenix-Seal-Key") != "" {
			t.Error("should not send seal header without key")
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"values": map[string]string{"phoenix://myapp/key": "plain-val"},
		})
	})

	responses := mcpExchange(t, handler,
		jsonMsg(1, "tools/call", map[string]interface{}{
			"name": "phoenix_resolve",
			"arguments": map[string]interface{}{
				"refs": []string{"phoenix://myapp/key"},
			},
		}),
	)

	b, _ := json.Marshal(responses[0].Result)
	var result mcpCallToolResult
	json.Unmarshal(b, &result)

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "plain-val") {
		t.Fatalf("expected plaintext value, got: %s", result.Content[0].Text)
	}
	if strings.Contains(result.Content[0].Text, "PHOENIX_SEALED:") {
		t.Fatal("should not produce sealed tokens without seal key")
	}
}

func TestMCPToolGetPlaintextWithoutSealKey(t *testing.T) {
	withSealKey(t, nil)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Phoenix-Seal-Key") != "" {
			t.Error("should not send seal header without key")
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"path": "myapp/key", "value": "plain-val",
		})
	})

	responses := mcpExchange(t, handler,
		jsonMsg(1, "tools/call", map[string]interface{}{
			"name": "phoenix_get",
			"arguments": map[string]interface{}{
				"path": "myapp/key",
			},
		}),
	)

	b, _ := json.Marshal(responses[0].Result)
	var result mcpCallToolResult
	json.Unmarshal(b, &result)

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].Text)
	}
	if result.Content[0].Text != "plain-val" {
		t.Fatalf("got %q, want %q", result.Content[0].Text, "plain-val")
	}
}
