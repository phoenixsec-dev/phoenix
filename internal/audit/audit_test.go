package audit

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogAndQuery(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	logger, err := NewLogger(logPath)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer logger.Close()

	logger.LogAllowed("vector", "read", "openclaw/api-key", "192.168.0.117")
	logger.LogDenied("openclaw", "read", "proxmox/admin", "192.168.0.115", "acl")
	logger.LogAllowed("admin", "write", "monitoring/grafana", "192.168.0.110")

	// Query all
	entries, err := Query(logPath, QueryOptions{})
	if err != nil {
		t.Fatalf("Query all: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	// Query by agent
	entries, err = Query(logPath, QueryOptions{Agent: "vector"})
	if err != nil {
		t.Fatalf("Query by agent: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry for vector, got %d", len(entries))
	}
	if entries[0].Status != "allowed" {
		t.Fatalf("expected 'allowed', got %q", entries[0].Status)
	}

	// Query with limit
	entries, err = Query(logPath, QueryOptions{Limit: 2})
	if err != nil {
		t.Fatalf("Query with limit: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries with limit, got %d", len(entries))
	}
}

func TestLogFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := NewWriterLogger(&buf)

	logger.LogAllowed("vector", "read", "test/key", "10.0.0.1")

	line := strings.TrimSpace(buf.String())
	var entry Entry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatalf("unmarshal log line: %v", err)
	}

	if entry.Agent != "vector" {
		t.Fatalf("expected agent 'vector', got %q", entry.Agent)
	}
	if entry.Status != "allowed" {
		t.Fatalf("expected status 'allowed', got %q", entry.Status)
	}
	if entry.Timestamp.IsZero() {
		t.Fatal("timestamp should not be zero")
	}
}

func TestQuerySince(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	logger, _ := NewLogger(logPath)

	logger.LogAllowed("a", "read", "test/old", "1.2.3.4")
	time.Sleep(10 * time.Millisecond)
	since := time.Now().UTC()
	time.Sleep(10 * time.Millisecond)
	logger.LogAllowed("b", "read", "test/new", "1.2.3.4")
	logger.Close()

	entries, err := Query(logPath, QueryOptions{Since: &since})
	if err != nil {
		t.Fatalf("Query since: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry since cutoff, got %d", len(entries))
	}
	if entries[0].Agent != "b" {
		t.Fatalf("expected agent 'b', got %q", entries[0].Agent)
	}
}
