package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phoenixsec/phoenix/internal/crypto"
)

// --- Helper tests ---

func TestLoadSealKeyNoEnv(t *testing.T) {
	t.Setenv("PHOENIX_SEAL_KEY", "")
	key, err := loadSealKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != nil {
		t.Fatal("expected nil key when PHOENIX_SEAL_KEY is unset")
	}
}

func TestLoadSealKeyFromFile(t *testing.T) {
	kp, err := crypto.GenerateSealKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "test.seal.key")
	if err := os.WriteFile(keyPath, []byte(crypto.EncodeSealKey(&kp.PrivateKey)), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PHOENIX_SEAL_KEY", keyPath)

	key, err := loadSealKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	if *key != kp.PrivateKey {
		t.Fatal("loaded key does not match written key")
	}
}

func TestSealHeadersNilKey(t *testing.T) {
	hdrs := sealHeaders(nil)
	if hdrs != nil {
		t.Fatal("expected nil headers for nil key")
	}
}

func TestSealHeadersWithKey(t *testing.T) {
	kp, _ := crypto.GenerateSealKeyPair()
	hdrs := sealHeaders(&kp.PrivateKey)
	if hdrs == nil {
		t.Fatal("expected non-nil headers")
	}
	val, ok := hdrs["X-Phoenix-Seal-Key"]
	if !ok {
		t.Fatal("missing X-Phoenix-Seal-Key header")
	}
	expected := crypto.EncodeSealKey(&kp.PublicKey)
	if val != expected {
		t.Fatalf("header = %q, want %q", val, expected)
	}
}

func TestDecryptSealedValueRoundTrip(t *testing.T) {
	kp, _ := crypto.GenerateSealKeyPair()
	env, err := crypto.SealValue("ns/secret", "phoenix://ns/secret", "hunter2", &kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	val, err := decryptSealedValue(env, &kp.PrivateKey)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if val != "hunter2" {
		t.Fatalf("got %q, want %q", val, "hunter2")
	}
}

func TestDecryptSealedValueWrongKey(t *testing.T) {
	kp1, _ := crypto.GenerateSealKeyPair()
	kp2, _ := crypto.GenerateSealKeyPair()
	env, _ := crypto.SealValue("ns/secret", "phoenix://ns/secret", "hunter2", &kp1.PublicKey)
	_, err := decryptSealedValue(env, &kp2.PrivateKey)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

// --- cmdGet sealed tests ---

func TestCmdGetSealed(t *testing.T) {
	kp, _ := crypto.GenerateSealKeyPair()

	keyPath := filepath.Join(t.TempDir(), "test.seal.key")
	os.WriteFile(keyPath, []byte(crypto.EncodeSealKey(&kp.PrivateKey)), 0600)
	t.Setenv("PHOENIX_SEAL_KEY", keyPath)

	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		sealKey := r.Header.Get("X-Phoenix-Seal-Key")
		if sealKey == "" {
			t.Error("missing X-Phoenix-Seal-Key header")
		}
		pubKey, _ := crypto.DecodeSealKey(sealKey)
		env, _ := crypto.SealValue("ns/secret", "", "sealed-secret-42", pubKey)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sealed_value": env,
		})
	}, func() {
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := cmdGet([]string{"ns/secret"})

		w.Close()
		os.Stdout = oldStdout
		buf := make([]byte, 1024)
		n, _ := r.Read(buf)
		output := string(buf[:n])

		if err != nil {
			t.Fatalf("cmdGet failed: %v", err)
		}
		if output != "sealed-secret-42" {
			t.Fatalf("got %q, want %q", output, "sealed-secret-42")
		}
	})
}

func TestCmdGetPlaintextFallback(t *testing.T) {
	t.Setenv("PHOENIX_SEAL_KEY", "")

	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Phoenix-Seal-Key") != "" {
			t.Error("should not send seal header without key")
		}
		json.NewEncoder(w).Encode(map[string]string{"value": "plaintext-val"})
	}, func() {
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := cmdGet([]string{"ns/secret"})

		w.Close()
		os.Stdout = oldStdout
		buf := make([]byte, 1024)
		n, _ := r.Read(buf)
		output := string(buf[:n])

		if err != nil {
			t.Fatalf("cmdGet failed: %v", err)
		}
		if output != "plaintext-val" {
			t.Fatalf("got %q, want %q", output, "plaintext-val")
		}
	})
}

func TestCmdGetSealedMissingSealedValue(t *testing.T) {
	kp, _ := crypto.GenerateSealKeyPair()

	keyPath := filepath.Join(t.TempDir(), "test.seal.key")
	os.WriteFile(keyPath, []byte(crypto.EncodeSealKey(&kp.PrivateKey)), 0600)
	t.Setenv("PHOENIX_SEAL_KEY", keyPath)

	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"value": "plaintext"})
	}, func() {
		err := cmdGet([]string{"ns/secret"})
		if err == nil {
			t.Fatal("expected error when sealed_value is missing")
		}
		if !strings.Contains(err.Error(), "sealed_value") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// --- cmdResolve sealed tests ---

func TestCmdResolveSealedSingleRef(t *testing.T) {
	kp, _ := crypto.GenerateSealKeyPair()

	keyPath := filepath.Join(t.TempDir(), "test.seal.key")
	os.WriteFile(keyPath, []byte(crypto.EncodeSealKey(&kp.PrivateKey)), 0600)
	t.Setenv("PHOENIX_SEAL_KEY", keyPath)

	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		sealKey := r.Header.Get("X-Phoenix-Seal-Key")
		pubKey, _ := crypto.DecodeSealKey(sealKey)
		env, _ := crypto.SealValue("ns/db-pass", "phoenix://ns/db-pass", "p@ssw0rd", pubKey)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sealed_values": map[string]interface{}{
				"phoenix://ns/db-pass": env,
			},
		})
	}, func() {
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := cmdResolve([]string{"phoenix://ns/db-pass"})

		w.Close()
		os.Stdout = oldStdout
		buf := make([]byte, 1024)
		n, _ := r.Read(buf)
		output := string(buf[:n])

		if err != nil {
			t.Fatalf("cmdResolve failed: %v", err)
		}
		if output != "p@ssw0rd" {
			t.Fatalf("got %q, want %q", output, "p@ssw0rd")
		}
	})
}

func TestCmdResolveSealedMissingRef(t *testing.T) {
	kp, _ := crypto.GenerateSealKeyPair()

	keyPath := filepath.Join(t.TempDir(), "test.seal.key")
	os.WriteFile(keyPath, []byte(crypto.EncodeSealKey(&kp.PrivateKey)), 0600)
	t.Setenv("PHOENIX_SEAL_KEY", keyPath)

	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sealed_values": map[string]interface{}{},
		})
	}, func() {
		err := cmdResolve([]string{"phoenix://ns/missing"})
		if err == nil {
			t.Fatal("expected error for missing ref in sealed response")
		}
		if !strings.Contains(err.Error(), "no value returned") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestCmdResolveSealedPartialErrors(t *testing.T) {
	kp, _ := crypto.GenerateSealKeyPair()

	keyPath := filepath.Join(t.TempDir(), "test.seal.key")
	os.WriteFile(keyPath, []byte(crypto.EncodeSealKey(&kp.PrivateKey)), 0600)
	t.Setenv("PHOENIX_SEAL_KEY", keyPath)

	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		sealKey := r.Header.Get("X-Phoenix-Seal-Key")
		pubKey, _ := crypto.DecodeSealKey(sealKey)
		env, _ := crypto.SealValue("ns/good", "phoenix://ns/good", "val1", pubKey)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sealed_values": map[string]interface{}{
				"phoenix://ns/good": env,
			},
			"errors": map[string]string{
				"phoenix://ns/bad": "not found",
			},
		})
	}, func() {
		err := cmdResolve([]string{"phoenix://ns/good", "phoenix://ns/bad"})
		if err == nil {
			t.Fatal("expected error for partial failure")
		}
		if !strings.Contains(err.Error(), "some references failed") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// --- cmdKeypairGenerate tests ---

func TestCmdKeypairGenerateWritesKeyFile(t *testing.T) {
	kp, _ := crypto.GenerateSealKeyPair()

	outPath := filepath.Join(t.TempDir(), "test-agent.seal.key")

	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || !strings.HasPrefix(r.URL.Path, "/v1/keypair") {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]string{
			"agent_name":       "test-agent",
			"seal_public_key":  crypto.EncodeSealKey(&kp.PublicKey),
			"seal_private_key": crypto.EncodeSealKey(&kp.PrivateKey),
		})
	}, func() {
		oldStdout := os.Stdout
		_, w, _ := os.Pipe()
		os.Stdout = w

		err := cmdKeypairGenerate([]string{"test-agent", "-o", outPath})

		w.Close()
		os.Stdout = oldStdout

		if err != nil {
			t.Fatalf("cmdKeypairGenerate failed: %v", err)
		}

		data, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatalf("reading key file: %v", err)
		}
		if string(data) != crypto.EncodeSealKey(&kp.PrivateKey) {
			t.Fatal("key file content mismatch")
		}

		info, _ := os.Stat(outPath)
		if info.Mode().Perm() != 0600 {
			t.Fatalf("key file mode = %o, want 0600", info.Mode().Perm())
		}
	})
}

func TestCmdKeypairGenerateHardensExistingPerms(t *testing.T) {
	kp, _ := crypto.GenerateSealKeyPair()

	outPath := filepath.Join(t.TempDir(), "test-agent.seal.key")
	// Pre-create with insecure permissions
	os.WriteFile(outPath, []byte("old-key"), 0644)

	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"agent_name":       "test-agent",
			"seal_public_key":  crypto.EncodeSealKey(&kp.PublicKey),
			"seal_private_key": crypto.EncodeSealKey(&kp.PrivateKey),
		})
	}, func() {
		oldStdout := os.Stdout
		_, w, _ := os.Pipe()
		os.Stdout = w

		err := cmdKeypairGenerate([]string{"test-agent", "-o", outPath})

		w.Close()
		os.Stdout = oldStdout

		if err != nil {
			t.Fatalf("cmdKeypairGenerate failed: %v", err)
		}

		info, _ := os.Stat(outPath)
		if info.Mode().Perm() != 0600 {
			t.Fatalf("key file mode = %o, want 0600 (should harden existing file)", info.Mode().Perm())
		}
	})
}

func TestCmdKeypairGenerateForceFlag(t *testing.T) {
	kp, _ := crypto.GenerateSealKeyPair()
	var gotForce bool

	outPath := filepath.Join(t.TempDir(), "test.seal.key")

	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotForce = r.URL.Query().Get("force") == "true"
		json.NewEncoder(w).Encode(map[string]string{
			"agent_name":       "test-agent",
			"seal_public_key":  crypto.EncodeSealKey(&kp.PublicKey),
			"seal_private_key": crypto.EncodeSealKey(&kp.PrivateKey),
		})
	}, func() {
		oldStdout := os.Stdout
		_, w, _ := os.Pipe()
		os.Stdout = w

		err := cmdKeypairGenerate([]string{"test-agent", "--force", "-o", outPath})

		w.Close()
		os.Stdout = oldStdout

		if err != nil {
			t.Fatalf("cmdKeypairGenerate failed: %v", err)
		}
		if !gotForce {
			t.Fatal("expected force=true query parameter")
		}
	})
}

func TestCmdKeypairGenerateMissingName(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	token = "test-token"

	err := cmdKeypairGenerate([]string{})
	if err == nil {
		t.Fatal("expected usage error")
	}
	if !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCmdKeypairGenerateDefaultPath(t *testing.T) {
	kp, _ := crypto.GenerateSealKeyPair()

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"agent_name":       "myagent",
			"seal_public_key":  crypto.EncodeSealKey(&kp.PublicKey),
			"seal_private_key": crypto.EncodeSealKey(&kp.PrivateKey),
		})
	}, func() {
		oldStdout := os.Stdout
		_, w, _ := os.Pipe()
		os.Stdout = w

		err := cmdKeypairGenerate([]string{"myagent"})

		w.Close()
		os.Stdout = oldStdout

		if err != nil {
			t.Fatalf("cmdKeypairGenerate failed: %v", err)
		}

		expectedPath := filepath.Join(tmpHome, ".config", "phoenix", "keys", "myagent.seal.key")
		info, err := os.Stat(expectedPath)
		if err != nil {
			t.Fatalf("key file not found at default path %s: %v", expectedPath, err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("mode = %o, want 0600", info.Mode().Perm())
		}

		dirInfo, _ := os.Stat(filepath.Dir(expectedPath))
		if dirInfo.Mode().Perm() != 0700 {
			t.Fatalf("keys dir mode = %o, want 0700", dirInfo.Mode().Perm())
		}

		// Suppress unused import warning
		_ = fmt.Sprintf("PHOENIX_SEAL_KEY=%s", expectedPath)
	})
}

// --- cmdExec env stripping test ---

func TestCmdExecStripsSealKeyEnv(t *testing.T) {
	t.Setenv("PHOENIX_SEAL_KEY", "/some/key/path")
	t.Setenv("PHOENIX_TOKEN", "test-token")

	// Build env like cmdExec does
	var env []string
	for _, e := range os.Environ() {
		key := e[:strings.IndexByte(e, '=')]
		switch key {
		case "PHOENIX_TOKEN", "PHOENIX_CLIENT_CERT", "PHOENIX_CLIENT_KEY",
			"PHOENIX_CA_CERT", "PHOENIX_SERVER", "PHOENIX_POLICY",
			"PHOENIX_SEAL_KEY":
			continue
		}
		env = append(env, e)
	}

	for _, e := range env {
		key := e[:strings.IndexByte(e, '=')]
		if key == "PHOENIX_SEAL_KEY" {
			t.Fatal("PHOENIX_SEAL_KEY should be stripped from child env")
		}
		if key == "PHOENIX_TOKEN" {
			t.Fatal("PHOENIX_TOKEN should be stripped from child env")
		}
	}
}
