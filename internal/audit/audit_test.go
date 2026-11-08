package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
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

func TestLogFormatIncludesSealedField(t *testing.T) {
	var buf bytes.Buffer
	logger := NewWriterLogger(&buf)

	logger.LogAllowedSealed("vector", "read", "test/key", "10.0.0.1", true)

	line := strings.TrimSpace(buf.String())
	var entry Entry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatalf("unmarshal log line: %v", err)
	}
	if !entry.Sealed {
		t.Fatal("expected sealed field to be true")
	}
}

func TestLogFormatIncludesMetadataWhenPresent(t *testing.T) {
	var buf bytes.Buffer
	logger := NewWriterLogger(&buf)

	metadata := map[string]string{"openclaw.agent": "claw", "empty": ""}
	logger.LogAllowedWithMetadata("vector", "read", "test/key", "10.0.0.1", metadata)
	metadata["openclaw.agent"] = "mutated"

	line := strings.TrimSpace(buf.String())
	var entry Entry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatalf("unmarshal log line: %v", err)
	}
	if entry.Metadata["openclaw.agent"] != "claw" {
		t.Fatalf("metadata openclaw.agent = %q, want %q", entry.Metadata["openclaw.agent"], "claw")
	}
	if _, ok := entry.Metadata["empty"]; ok {
		t.Fatal("empty metadata value should be omitted")
	}
}

func TestQueryByPath(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	logger, _ := NewLogger(logPath)
	logger.LogAllowed("vector", "read", "openclaw/api-key", "1.2.3.4")
	logger.LogAllowed("vector", "read", "monitoring/grafana", "1.2.3.4")
	logger.LogDenied("openclaw", "read", "proxmox/admin", "1.2.3.4", "acl")
	logger.Close()

	entries, err := Query(logPath, QueryOptions{Path: "openclaw/api-key"})
	if err != nil {
		t.Fatalf("Query by path: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry for path, got %d", len(entries))
	}
	if entries[0].Agent != "vector" {
		t.Fatalf("expected agent 'vector', got %q", entries[0].Agent)
	}
}

func TestQueryCombinedFilters(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	logger, _ := NewLogger(logPath)
	logger.LogAllowed("vector", "read", "ns/key", "1.1.1.1")
	logger.LogAllowed("admin", "write", "ns/key", "1.1.1.1")
	logger.LogAllowed("vector", "read", "ns/other", "1.1.1.1")
	logger.Close()

	// Filter by agent AND path
	entries, err := Query(logPath, QueryOptions{Agent: "vector", Path: "ns/key"})
	if err != nil {
		t.Fatalf("Query combined: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
}

func TestLogDeniedReason(t *testing.T) {
	var buf bytes.Buffer
	logger := NewWriterLogger(&buf)

	logger.LogDenied("badagent", "read", "secret/key", "10.0.0.1", "acl denied")

	var entry Entry
	json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &entry)

	if entry.Status != "denied" {
		t.Fatalf("expected 'denied', got %q", entry.Status)
	}
	if entry.Reason != "acl denied" {
		t.Fatalf("expected reason 'acl denied', got %q", entry.Reason)
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

// A limited query returns the newest entries in order, with filters applied
// before the limit, without holding the whole log while it reads.
func TestQueryLimitKeepsNewestInOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		agent := "a"
		if i%3 == 0 {
			agent = "b"
		}
		l.LogAllowed(agent, "read", fmt.Sprintf("p/%d", i), "127.0.0.1")
	}
	l.Close()
	got, err := Query(path, QueryOptions{Limit: 7})
	if err != nil || len(got) != 7 {
		t.Fatalf("got %d entries, err %v", len(got), err)
	}
	for i, e := range got {
		if want := fmt.Sprintf("p/%d", 993+i); e.Path != want {
			t.Fatalf("entry %d = %s, want %s", i, e.Path, want)
		}
	}
	got, _ = Query(path, QueryOptions{Limit: 3, Agent: "b"})
	if len(got) != 3 || got[0].Path != "p/993" || got[2].Path != "p/999" {
		t.Fatalf("filtered = %+v", got)
	}
	if all, _ := Query(path, QueryOptions{}); len(all) != 1000 {
		t.Fatalf("no limit returned %d", len(all))
	}
}

// A limit near the int maximum must not overflow and panic: it just means "all".
func TestQueryHugeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	l.LogAllowed("a", "read", "p/0", "127.0.0.1")
	l.LogAllowed("a", "read", "p/1", "127.0.0.1")
	l.Close()
	maxInt := int(^uint(0) >> 1)
	for _, limit := range []int{maxInt/2 + 1, maxInt} {
		got, err := Query(path, QueryOptions{Limit: limit})
		if err != nil || len(got) != 2 {
			t.Fatalf("limit %d: %d entries, err %v", limit, len(got), err)
		}
	}
}
