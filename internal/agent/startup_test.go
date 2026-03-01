package agent

import (
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
)

// TestAgentConfigDrivenStartup verifies the pattern used by phoenix-server:
// create agent from config path, start it, verify it's functional, then stop.
func TestAgentConfigDrivenStartup(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "agent.sock")

	// This is what phoenix-server does:
	ag := New(sockPath)
	if err := ag.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Verify socket is listening
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		ag.Stop()
		t.Fatalf("Dial: %v", err)
	}

	// Send a request and verify response
	json.NewEncoder(conn).Encode(AttestRequest{Agent: "test"})
	var resp AttestResponse
	json.NewDecoder(conn).Decode(&resp)
	conn.Close()

	if !resp.OK {
		ag.Stop()
		t.Fatalf("attestation not OK: %s", resp.Error)
	}

	// Clean shutdown (what defer ag.Stop() does in the server)
	if err := ag.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// TestAgentStaleSocketRecovery verifies that starting an agent removes
// a stale socket file from a previous run.
func TestAgentStaleSocketRecovery(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "stale.sock")

	// Start and stop to create a "stale" socket scenario
	ag1 := New(sockPath)
	if err := ag1.Start(); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	// Stop without cleanup to simulate crash
	ag1.listener.Close()

	// Second agent should recover
	ag2 := New(sockPath)
	if err := ag2.Start(); err != nil {
		t.Fatalf("second Start with stale socket: %v", err)
	}
	defer ag2.Stop()

	// Should be functional
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial after recovery: %v", err)
	}
	json.NewEncoder(conn).Encode(AttestRequest{Agent: "recovered"})
	var resp AttestResponse
	json.NewDecoder(conn).Decode(&resp)
	conn.Close()

	if !resp.OK {
		t.Fatalf("attestation not OK after recovery: %s", resp.Error)
	}
}
