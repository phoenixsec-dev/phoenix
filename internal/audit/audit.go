// Package audit provides append-only JSON Lines logging for Phoenix.
//
// Every secret access (read, write, delete) is logged with the agent identity,
// action, path, result, and client IP. Secret values are NEVER logged.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Entry is a single audit log record.
type Entry struct {
	Timestamp time.Time `json:"ts"`
	Agent     string    `json:"agent"`
	Action    string    `json:"action"`
	Path      string    `json:"path"`
	Status    string    `json:"status"` // "allowed" or "denied"
	IP        string    `json:"ip,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
}

// Logger writes audit entries to a file.
type Logger struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
}

// NewLogger creates a new audit logger writing to the given file path.
// The file is opened in append mode and created if it doesn't exist.
func NewLogger(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("opening audit log: %w", err)
	}

	return &Logger{
		file: f,
		enc:  json.NewEncoder(f),
	}, nil
}

// NewWriterLogger creates an audit logger backed by any io.Writer (useful for tests).
func NewWriterLogger(w io.Writer) *Logger {
	return &Logger{
		enc: json.NewEncoder(w),
	}
}

// Log records an audit entry.
func (l *Logger) Log(agent, action, path, status, ip, reason string) error {
	entry := Entry{
		Timestamp: time.Now().UTC(),
		Agent:     agent,
		Action:    action,
		Path:      path,
		Status:    status,
		IP:        ip,
		Reason:    reason,
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.enc.Encode(entry); err != nil {
		return err
	}
	if l.file != nil {
		return l.file.Sync()
	}
	return nil
}

// LogAllowed is a convenience for logging permitted actions.
func (l *Logger) LogAllowed(agent, action, path, ip string) error {
	return l.Log(agent, action, path, "allowed", ip, "")
}

// LogDenied is a convenience for logging denied actions.
func (l *Logger) LogDenied(agent, action, path, ip, reason string) error {
	return l.Log(agent, action, path, "denied", ip, reason)
}

// Close flushes and closes the audit log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Query reads audit entries from a file, filtered by optional criteria.
type QueryOptions struct {
	Since *time.Time
	Agent string
	Path  string
	Limit int
}

// Query reads and filters audit entries from a log file.
func Query(path string, opts QueryOptions) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening audit log for query: %w", err)
	}
	defer f.Close()

	var entries []Entry
	dec := json.NewDecoder(f)

	for dec.More() {
		var entry Entry
		if err := dec.Decode(&entry); err != nil {
			continue // skip malformed lines
		}

		if opts.Since != nil && entry.Timestamp.Before(*opts.Since) {
			continue
		}
		if opts.Agent != "" && entry.Agent != opts.Agent {
			continue
		}
		if opts.Path != "" && entry.Path != opts.Path {
			continue
		}

		entries = append(entries, entry)
	}

	// If limit is set, return only the last N entries
	if opts.Limit > 0 && len(entries) > opts.Limit {
		entries = entries[len(entries)-opts.Limit:]
	}

	return entries, nil
}
