package agent

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestHashFile(t *testing.T) {
	// Create a temp file with known content
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	if err := os.WriteFile(path, []byte("hello world"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	hash, err := HashFile(path)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}

	// SHA-256 of "hello world" = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
	expected := "sha256:B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9"
	if hash != expected {
		t.Fatalf("hash = %q, want %q", hash, expected)
	}
}

func TestHashFileNotFound(t *testing.T) {
	_, err := HashFile("/nonexistent/file")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestAgentStartStop(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	a := New(sockPath)
	if err := a.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer a.Stop()

	if a.SocketPath() != sockPath {
		t.Fatalf("SocketPath = %q, want %q", a.SocketPath(), sockPath)
	}

	// Socket file should exist
	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("socket file missing: %v", err)
	}

	// Stop should clean up
	a.Stop()
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Fatal("socket file should be removed after Stop")
	}
}

func TestAgentStopIdempotent(t *testing.T) {
	dir := t.TempDir()
	a := New(filepath.Join(dir, "test.sock"))
	a.Start()
	a.Stop()
	a.Stop() // should not panic
}

func TestAgentConnectAndAttest(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SO_PEERCRED only available on Linux")
	}

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	a := New(sockPath)
	if err := a.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer a.Stop()

	// Connect to the agent
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// Send attestation request
	req := AttestRequest{Agent: "test-agent"}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Read response
	var resp AttestResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if !resp.OK {
		t.Fatalf("attestation failed: %s", resp.Error)
	}
	if resp.Peer == nil {
		t.Fatal("expected peer info")
	}

	// PID should match our process
	if resp.Peer.PID != int32(os.Getpid()) {
		t.Fatalf("PID = %d, want %d", resp.Peer.PID, os.Getpid())
	}

	// UID should match
	if resp.Peer.UID != int32(os.Getuid()) {
		t.Fatalf("UID = %d, want %d", resp.Peer.UID, os.Getuid())
	}
}

func TestResolveBinaryCurrentProcess(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc only available on Linux")
	}

	path, hash := resolveBinary(int32(os.Getpid()))
	if path == "" {
		t.Fatal("expected non-empty binary path")
	}
	if hash == "" {
		t.Fatal("expected non-empty binary hash")
	}
	t.Logf("Binary: %s, Hash: %s", path, hash)
}

func TestPeerInfoJSON(t *testing.T) {
	info := &PeerInfo{
		PID:        1234,
		UID:        1000,
		GID:        1000,
		BinaryPath: "/usr/bin/test",
		BinaryHash: "sha256:abc123",
	}

	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded PeerInfo
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.PID != 1234 || decoded.UID != 1000 || decoded.BinaryHash != "sha256:abc123" {
		t.Fatalf("round-trip failed: %+v", decoded)
	}
}
