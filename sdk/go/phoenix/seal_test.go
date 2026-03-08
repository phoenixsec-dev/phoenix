package phoenix

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// sealValue creates a sealed envelope for testing (mirrors internal/crypto.SealValue).
func sealValue(path, ref, value string, recipientPubKey *[32]byte) *SealedEnvelope {
	ephPub, ephPriv, _ := box.GenerateKey(rand.Reader)

	payload, _ := json.Marshal(map[string]string{
		"path":      path,
		"ref":       ref,
		"value":     value,
		"issued_at": time.Now().UTC().Format(time.RFC3339),
	})

	var nonce [24]byte
	rand.Read(nonce[:])

	ciphertext := box.Seal(nil, payload, &nonce, recipientPubKey, ephPriv)

	return &SealedEnvelope{
		Version:      1,
		Algorithm:    "x25519-xsalsa20-poly1305",
		Path:         path,
		Ref:          ref,
		EphemeralKey: base64.StdEncoding.EncodeToString(ephPub[:]),
		Nonce:        base64.StdEncoding.EncodeToString(nonce[:]),
		Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
	}
}

func TestSetSealKeyAndResolveSealed(t *testing.T) {
	// Generate a keypair
	pub, priv, _ := box.GenerateKey(rand.Reader)

	// Write private key to temp file
	keyPath := filepath.Join(t.TempDir(), "test.seal.key")
	os.WriteFile(keyPath, []byte(encodeSealKey(priv)), 0600)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sealKey := r.Header.Get("X-Phoenix-Seal-Key")
		if sealKey == "" {
			t.Error("expected X-Phoenix-Seal-Key header")
		}
		// Verify the public key matches
		expected := encodeSealKey(pub)
		if sealKey != expected {
			t.Errorf("seal key = %q, want %q", sealKey, expected)
		}

		env := sealValue("ns/key", "phoenix://ns/key", "sealed-secret", pub)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sealed_values": map[string]interface{}{
				"phoenix://ns/key": env,
			},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "test-token")
	if err := c.SetSealKey(keyPath); err != nil {
		t.Fatalf("SetSealKey: %v", err)
	}

	val, err := c.Resolve("phoenix://ns/key")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if val != "sealed-secret" {
		t.Fatalf("got %q, want %q", val, "sealed-secret")
	}
}

func TestResolveBatchSealed(t *testing.T) {
	pub, priv, _ := box.GenerateKey(rand.Reader)

	keyPath := filepath.Join(t.TempDir(), "test.seal.key")
	os.WriteFile(keyPath, []byte(encodeSealKey(priv)), 0600)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env1 := sealValue("ns/k1", "phoenix://ns/k1", "val1", pub)
		env2 := sealValue("ns/k2", "phoenix://ns/k2", "val2", pub)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sealed_values": map[string]interface{}{
				"phoenix://ns/k1": env1,
				"phoenix://ns/k2": env2,
			},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "tok")
	c.SetSealKey(keyPath)

	result, err := c.ResolveBatch([]string{"phoenix://ns/k1", "phoenix://ns/k2"})
	if err != nil {
		t.Fatalf("ResolveBatch: %v", err)
	}
	if result.Values["phoenix://ns/k1"] != "val1" {
		t.Fatalf("k1 = %q, want %q", result.Values["phoenix://ns/k1"], "val1")
	}
	if result.Values["phoenix://ns/k2"] != "val2" {
		t.Fatalf("k2 = %q, want %q", result.Values["phoenix://ns/k2"], "val2")
	}
}

func TestPlaintextBackwardCompat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Phoenix-Seal-Key") != "" {
			t.Error("should not send seal header without key")
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"values": map[string]string{"phoenix://ns/key": "plain-val"},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "tok")
	val, err := c.Resolve("phoenix://ns/key")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if val != "plain-val" {
		t.Fatalf("got %q, want %q", val, "plain-val")
	}
}

func TestSealedWrongKeyReject(t *testing.T) {
	pub1, _, _ := box.GenerateKey(rand.Reader)
	_, priv2, _ := box.GenerateKey(rand.Reader)

	keyPath := filepath.Join(t.TempDir(), "test.seal.key")
	os.WriteFile(keyPath, []byte(encodeSealKey(priv2)), 0600)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Seal with pub1 but client has priv2
		env := sealValue("ns/key", "phoenix://ns/key", "secret", pub1)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sealed_values": map[string]interface{}{
				"phoenix://ns/key": env,
			},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "tok")
	c.SetSealKey(keyPath)

	_, err := c.Resolve("phoenix://ns/key")
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestSetSealKeyBadFile(t *testing.T) {
	c := New("http://localhost:9999", "tok")
	err := c.SetSealKey("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestSetSealKeyBadContent(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "bad.key")
	os.WriteFile(keyPath, []byte("not-valid-base64!!!"), 0600)

	c := New("http://localhost:9999", "tok")
	err := c.SetSealKey(keyPath)
	if err == nil {
		t.Fatal("expected error for invalid key content")
	}
}

func TestResolveBatchRefSwapRejected(t *testing.T) {
	pub, priv, _ := box.GenerateKey(rand.Reader)

	keyPath := filepath.Join(t.TempDir(), "test.seal.key")
	os.WriteFile(keyPath, []byte(encodeSealKey(priv)), 0600)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Server swaps the map keys: envelope for A is filed under B and vice versa
		envA := sealValue("ns/a", "phoenix://ns/a", "A", pub)
		envB := sealValue("ns/b", "phoenix://ns/b", "B", pub)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sealed_values": map[string]interface{}{
				"phoenix://ns/a": envB, // swapped!
				"phoenix://ns/b": envA, // swapped!
			},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "tok")
	c.SetSealKey(keyPath)

	_, err := c.ResolveBatch([]string{"phoenix://ns/a", "phoenix://ns/b"})
	if err == nil {
		t.Fatal("expected error for ref-swap attack, got nil")
	}
}

func TestOpenSealedEnvelopeBadVersion(t *testing.T) {
	env := &SealedEnvelope{Version: 99, Algorithm: "x25519-xsalsa20-poly1305"}
	_, err := openSealedEnvelope(env, &[32]byte{})
	if err == nil {
		t.Fatal("expected error for bad version")
	}
}

func TestOpenSealedEnvelopeBadAlgorithm(t *testing.T) {
	env := &SealedEnvelope{Version: 1, Algorithm: "aes-gcm"}
	_, err := openSealedEnvelope(env, &[32]byte{})
	if err == nil {
		t.Fatal("expected error for bad algorithm")
	}
}
