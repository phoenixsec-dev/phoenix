package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"git.home/vector/phoenix/internal/agent"
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
