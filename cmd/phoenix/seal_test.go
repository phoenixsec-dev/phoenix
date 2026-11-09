package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
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

func TestLoadSealKeyForRequestUsesRoleSessionKey(t *testing.T) {
	kp, err := crypto.GenerateSealKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".phoenix"), 0700); err != nil {
		t.Fatal(err)
	}

	role := "deploy-role"
	keyPath := filepath.Join(home, ".phoenix", "session-seal-"+role+".key")
	if err := os.WriteFile(keyPath, []byte(crypto.EncodeSealKey(&kp.PrivateKey)), 0600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", home)
	t.Setenv("PHOENIX_ROLE", role)
	t.Setenv("PHOENIX_SEAL_KEY", "")

	key, err := loadSealKeyForRequest()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key from role session file")
	}
	if *key != kp.PrivateKey {
		t.Fatal("loaded key does not match role session key")
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

// echoSealPub is a mock POST /v1/keypair: it checks the CLI sent a valid
// public key and no private key, answers like the server, and returns the key.
func echoSealPub(t *testing.T, w http.ResponseWriter, r *http.Request) string {
	t.Helper()
	var body map[string]string
	json.NewDecoder(r.Body).Decode(&body)
	if _, err := crypto.DecodeSealKey(body["seal_public_key"]); err != nil {
		t.Errorf("bad seal_public_key sent: %v", err)
	}
	if len(body) != 2 {
		t.Errorf("request carries more than agent_name and seal_public_key: %v", body)
	}
	json.NewEncoder(w).Encode(map[string]string{"agent_name": body["agent_name"], "seal_public_key": body["seal_public_key"]})
	return body["seal_public_key"]
}

func TestCmdKeypairGenerateWritesKeyFile(t *testing.T) {
	var sentPub string

	outPath := filepath.Join(t.TempDir(), "test-agent.seal.key")

	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || !strings.HasPrefix(r.URL.Path, "/v1/keypair") {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		sentPub = echoSealPub(t, w, r)
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
		priv, err := crypto.DecodeSealKey(string(data))
		if err != nil {
			t.Fatalf("key file: %v", err)
		}
		if crypto.EncodeSealKey(crypto.DeriveSealPublicKey(priv)) != sentPub {
			t.Fatal("key file is not the private half of the registered public key")
		}

		info, _ := os.Stat(outPath)
		if info.Mode().Perm() != 0600 {
			t.Fatalf("key file mode = %o, want 0600", info.Mode().Perm())
		}
	})
}

// An older server ignores the public key and returns one it made itself.
// The CLI must refuse, and leave the existing key file alone.
func TestCmdKeypairGenerateOldServerRefused(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "a.seal.key")
	os.WriteFile(outPath, []byte("existing"), 0600)
	other, _ := crypto.GenerateSealKeyPair()
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"agent_name":       "a",
			"seal_public_key":  crypto.EncodeSealKey(&other.PublicKey),
			"seal_private_key": crypto.EncodeSealKey(&other.PrivateKey),
		})
	}, func() {
		err := cmdKeypairGenerate([]string{"a", "-o", outPath})
		if err == nil || !strings.Contains(err.Error(), "Update phoenix-server") {
			t.Fatalf("err = %v", err)
		}
		if data, _ := os.ReadFile(outPath); string(data) != "existing" {
			t.Fatalf("key file changed: %q", data)
		}
		if left, _ := filepath.Glob(outPath + ".*.tmp"); len(left) != 0 {
			t.Fatalf("temp key file left behind: %v", left)
		}
	})
}

// Review R1: a file or symlink already at "<output>.tmp" is never written
// through or reused; the key goes to a fresh, uniquely named file.
func TestCmdKeypairGenerateIgnoresPlantedTmp(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "a.seal.key")
	victim := filepath.Join(dir, "victim")
	os.WriteFile(victim, []byte("victim"), 0600)
	os.Symlink(victim, outPath+".tmp")
	var sentPub string
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		sentPub = echoSealPub(t, w, r)
	}, func() {
		captureStdout(t, func() {
			if err := cmdKeypairGenerate([]string{"a", "-o", outPath}); err != nil {
				t.Fatalf("cmdKeypairGenerate: %v", err)
			}
		})
	})
	if data, _ := os.ReadFile(victim); string(data) != "victim" {
		t.Fatalf("write followed the planted symlink: %q", data)
	}
	if fi, err := os.Lstat(outPath); err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0600 {
		t.Fatalf("key file is not a private regular file: %v %v", fi, err)
	}
	data, _ := os.ReadFile(outPath)
	priv, err := crypto.DecodeSealKey(string(data))
	if err != nil || crypto.EncodeSealKey(crypto.DeriveSealPublicKey(priv)) != sentPub {
		t.Fatalf("key file does not match the registered key: %v", err)
	}
}

// Review R1: when the server may have registered the key but the answer was
// lost, the new private key is kept and its path named, not deleted.
func TestCmdKeypairGenerateKeepsKeyOnLostResponse(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "a.seal.key")
	os.WriteFile(outPath, []byte("old"), 0600)
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		hj, _ := w.(http.Hijacker)
		conn, _, _ := hj.Hijack()
		conn.Close()
	}, func() {
		err := cmdKeypairGenerate([]string{"a", "--force", "-o", outPath})
		if err == nil {
			t.Fatal("expected an error for a lost response")
		}
		if data, _ := os.ReadFile(outPath); string(data) != "old" {
			t.Fatalf("existing key file changed: %q", data)
		}
		m := regexp.MustCompile(`kept at (\S+)`).FindStringSubmatch(err.Error())
		if m == nil {
			t.Fatalf("error does not name the kept key: %v", err)
		}
		data, rerr := os.ReadFile(m[1])
		if rerr != nil {
			t.Fatalf("kept key missing: %v", rerr)
		}
		if _, derr := crypto.DecodeSealKey(string(data)); derr != nil {
			t.Fatalf("kept key unreadable: %v", derr)
		}
	})
}

func TestCmdKeypairGenerateHardensExistingPerms(t *testing.T) {

	outPath := filepath.Join(t.TempDir(), "test-agent.seal.key")
	// Pre-create with insecure permissions
	os.WriteFile(outPath, []byte("old-key"), 0644)

	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		echoSealPub(t, w, r)
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
	var gotForce bool

	outPath := filepath.Join(t.TempDir(), "test.seal.key")

	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotForce = r.URL.Query().Get("force") == "true"
		echoSealPub(t, w, r)
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

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		echoSealPub(t, w, r)
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

func TestCmdKeypairGenerateRejectsDirectoryOutput(t *testing.T) {
	outDir := t.TempDir()

	err := cmdKeypairGenerate([]string{"test-agent", "-o", outDir})
	if err == nil {
		t.Fatal("expected usage error for directory output path")
	}
	if !strings.Contains(err.Error(), "output must be a file path") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCmdKeypairGenerateMissingOutputArg(t *testing.T) {
	err := cmdKeypairGenerate([]string{"test-agent", "-o"})
	if err == nil {
		t.Fatal("expected usage error when --output is missing a value")
	}
	if !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("unexpected error: %v", err)
	}
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
