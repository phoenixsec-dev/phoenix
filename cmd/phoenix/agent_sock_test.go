package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/phoenixsec/phoenix/internal/agent"
)

func TestCmdAgentSockAttestHappyPath(t *testing.T) {
	// Start a real attestation agent on a temp socket
	sockPath := filepath.Join(t.TempDir(), "test-agent.sock")
	ag := agent.New(sockPath)
	if err := ag.Start(); err != nil {
		t.Fatalf("starting agent: %v", err)
	}
	defer ag.Stop()

	// Run the CLI command against the socket
	err := cmdAgentSockAttest([]string{"--socket", sockPath})
	if err != nil {
		t.Fatalf("cmdAgentSockAttest: %v", err)
	}
}

func TestCmdAgentSockAttestWithAgentName(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test-agent.sock")
	ag := agent.New(sockPath)
	if err := ag.Start(); err != nil {
		t.Fatalf("starting agent: %v", err)
	}
	defer ag.Stop()

	err := cmdAgentSockAttest([]string{"--socket", sockPath, "--agent", "deployer"})
	if err != nil {
		t.Fatalf("cmdAgentSockAttest with agent name: %v", err)
	}
}

func TestCmdAgentSockAttestNoSocket(t *testing.T) {
	// Attempt to connect to a non-existent socket
	err := cmdAgentSockAttest([]string{"--socket", "/tmp/phoenix-nonexistent-test.sock"})
	if err == nil {
		t.Fatal("expected error when connecting to non-existent socket")
	}
}

func TestCmdAgentSockAttestBadSocket(t *testing.T) {
	// Create a regular file where a socket should be
	tmpDir := t.TempDir()
	badPath := filepath.Join(tmpDir, "not-a-socket")
	os.WriteFile(badPath, []byte("not a socket"), 0600)

	err := cmdAgentSockAttest([]string{"--socket", badPath})
	if err == nil {
		t.Fatal("expected error when connecting to non-socket file")
	}
}

func TestCmdAgentSockAttestProtocol(t *testing.T) {
	// Verify the wire protocol: connect, send request, get valid response
	sockPath := filepath.Join(t.TempDir(), "proto-test.sock")
	ag := agent.New(sockPath)
	if err := ag.Start(); err != nil {
		t.Fatalf("starting agent: %v", err)
	}
	defer ag.Stop()

	// Connect directly (like the CLI does)
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send request
	req := struct {
		Agent string `json:"agent"`
	}{Agent: "test-agent"}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("encode request: %v", err)
	}

	// Read response
	var resp agent.AttestResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if !resp.OK {
		t.Fatalf("attestation not OK: %s", resp.Error)
	}
	if resp.Peer == nil {
		t.Fatal("expected peer info in response")
	}
	if resp.Peer.PID <= 0 {
		t.Errorf("expected positive PID, got %d", resp.Peer.PID)
	}
	pid := int32(os.Getpid())
	if resp.Peer.PID != pid {
		t.Errorf("PID = %d, want %d (current process)", resp.Peer.PID, pid)
	}
	uid := int32(os.Getuid())
	if resp.Peer.UID != uid {
		t.Errorf("UID = %d, want %d (current user)", resp.Peer.UID, uid)
	}
}

// --- Token cache tests ---

func TestTokenCacheRoundTrip(t *testing.T) {
	// Override HOME to use temp dir for cache
	origHome := os.Getenv("HOME")
	tmpHome := t.TempDir()
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	// Initially empty
	tok := getCachedToken("myagent", 0)
	if tok != "" {
		t.Fatalf("expected empty cache, got %q", tok)
	}

	// Save a token
	cache := map[string]*tokenCacheEntry{
		"myagent": {
			Token:     "test-token-123",
			Agent:     "myagent",
			ExpiresAt: time.Now().Add(10 * time.Minute),
		},
	}
	if err := saveTokenCache(cache); err != nil {
		t.Fatalf("saveTokenCache: %v", err)
	}

	// Should be retrievable
	tok = getCachedToken("myagent", 0)
	if tok != "test-token-123" {
		t.Fatalf("cached token = %q, want test-token-123", tok)
	}
}

func TestTokenCacheExpired(t *testing.T) {
	origHome := os.Getenv("HOME")
	tmpHome := t.TempDir()
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	cache := map[string]*tokenCacheEntry{
		"expired-agent": {
			Token:     "old-token",
			Agent:     "expired-agent",
			ExpiresAt: time.Now().Add(-1 * time.Minute), // already expired
		},
	}
	saveTokenCache(cache)

	tok := getCachedToken("expired-agent", 0)
	if tok != "" {
		t.Fatalf("expected empty for expired token, got %q", tok)
	}
}

func TestTokenCacheTTLBuffer(t *testing.T) {
	origHome := os.Getenv("HOME")
	tmpHome := t.TempDir()
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	// Token expires in 20 seconds
	cache := map[string]*tokenCacheEntry{
		"buffered": {
			Token:     "near-expiry-token",
			Agent:     "buffered",
			ExpiresAt: time.Now().Add(20 * time.Second),
		},
	}
	saveTokenCache(cache)

	// Without buffer, still valid
	tok := getCachedToken("buffered", 0)
	if tok == "" {
		t.Fatal("expected valid token without buffer")
	}

	// With 30s buffer, considered expired
	tok = getCachedToken("buffered", 30*time.Second)
	if tok != "" {
		t.Fatalf("expected empty with 30s buffer, got %q", tok)
	}
}

func TestTokenCacheMissingAgent(t *testing.T) {
	origHome := os.Getenv("HOME")
	tmpHome := t.TempDir()
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	tok := getCachedToken("nonexistent", 0)
	if tok != "" {
		t.Fatalf("expected empty for missing agent, got %q", tok)
	}
}

func TestAttestViaSocket(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "attest-test.sock")
	ag := agent.New(sockPath)
	if err := ag.Start(); err != nil {
		t.Fatalf("starting agent: %v", err)
	}
	defer ag.Stop()

	uid, hash, err := attestViaSocket(sockPath, "test")
	if err != nil {
		t.Fatalf("attestViaSocket: %v", err)
	}

	if uid != os.Getuid() {
		t.Errorf("UID = %d, want %d", uid, os.Getuid())
	}
	// Binary hash may or may not be available depending on /proc
	_ = hash
}

func TestAttestViaSocketNoAgent(t *testing.T) {
	_, _, err := attestViaSocket("/tmp/phoenix-nonexistent-test.sock", "test")
	if err == nil {
		t.Fatal("expected error for non-existent socket")
	}
}
