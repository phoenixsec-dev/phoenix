// Package audit provides append-only JSON Lines logging for Phoenix.
//
// Every secret access (read, write, delete) is logged with the agent identity,
// action, path, result, and client IP. Secret values are NEVER logged.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

// Entry is a single audit log record.
type Entry struct {
	Timestamp time.Time         `json:"ts"`
	Agent     string            `json:"agent"`
	Action    string            `json:"action"`
	Path      string            `json:"path"`
	Status    string            `json:"status"` // "allowed" or "denied"
	IP        string            `json:"ip,omitempty"`
	Reason    string            `json:"reason,omitempty"`
	SessionID string            `json:"session_id,omitempty"`
	Sealed    bool              `json:"sealed"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// Logger writes audit entries to a file.
type Logger struct {
	mu   sync.Mutex
	w    io.Writer
	file *os.File // nil for NewWriterLogger

	// Rotation (rotate.go); maxBytes 0 = never rotate.
	path     string
	maxBytes int64
	size     int64 // bytes in the current file
	kick     chan struct{}
	wg       sync.WaitGroup
}

// NewLogger creates a new audit logger writing to the given file path.
// The file is opened in append mode and created if it doesn't exist.
// It never rotates the file; see NewRotatingLogger.
func NewLogger(path string) (*Logger, error) {
	return NewRotatingLogger(path, 0)
}

// NewRotatingLogger is NewLogger that moves the file to a dated archive
// once it passes maxBytes (0 = never). Archives are never deleted.
func NewRotatingLogger(path string, maxBytes int64) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("opening audit log: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("opening audit log: %w", err)
	}
	l := &Logger{w: f, file: f, path: path, maxBytes: maxBytes, size: st.Size()}
	if maxBytes > 0 {
		l.kick = make(chan struct{}, 1)
		l.wg.Add(1)
		go l.compressWorker(l.kick)
		l.kickCompress() // finish anything a crash left half compressed
	}
	return l, nil
}

// NewWriterLogger creates an audit logger backed by any io.Writer (useful for tests).
func NewWriterLogger(w io.Writer) *Logger {
	return &Logger{w: w}
}

// logWithMetadata writes a low-level audit entry with optional sanitized metadata.
func (l *Logger) logWithMetadata(agent, action, path, status, ip, reason, sessionID string, sealed bool, metadata map[string]string) error {
	entry := Entry{
		Agent:     agent,
		Action:    action,
		Path:      path,
		Status:    status,
		IP:        ip,
		Reason:    reason,
		SessionID: sessionID,
		Sealed:    sealed,
		Metadata:  cloneMetadata(metadata),
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Stamped under the lock so file order is time order, which lets a
	// since-query stop reading early.
	entry.Timestamp = time.Now().UTC()
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	n, err := l.w.Write(append(line, '\n'))
	l.size += int64(n)
	if err != nil {
		return err
	}
	if l.file == nil {
		return nil
	}
	if err := l.file.Sync(); err != nil {
		return err
	}
	if l.maxBytes > 0 && l.size >= l.maxBytes {
		if err := l.rotate(); err != nil {
			// The line is safely written; only the rotation failed. Try
			// again after another maxBytes instead of on every write.
			log.Printf("audit: WARNING: rotating %s: %v", l.path, err)
			l.size = 0
		}
	}
	return nil
}

func cloneMetadata(metadata map[string]string) map[string]string {
	if len(metadata) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(metadata))
	for k, v := range metadata {
		if k == "" || v == "" {
			continue
		}
		cloned[k] = v
	}
	if len(cloned) == 0 {
		return nil
	}
	return cloned
}

// LogAllowed is a convenience for logging permitted plaintext actions.
func (l *Logger) LogAllowed(agent, action, path, ip string) error {
	return l.LogAllowedWithMetadata(agent, action, path, ip, nil)
}

// LogAllowedWithMetadata logs a permitted plaintext action with optional sanitized metadata.
func (l *Logger) LogAllowedWithMetadata(agent, action, path, ip string, metadata map[string]string) error {
	return l.logWithMetadata(agent, action, path, "allowed", ip, "", "", false, metadata)
}

// LogAllowedSealed is a convenience for logging permitted actions with response
// seal state (true when the response was sealed).
func (l *Logger) LogAllowedSealed(agent, action, path, ip string, sealed bool) error {
	return l.LogAllowedSealedWithMetadata(agent, action, path, ip, sealed, nil)
}

// LogAllowedSealedWithMetadata logs a permitted action with response seal state
// and optional sanitized metadata.
func (l *Logger) LogAllowedSealedWithMetadata(agent, action, path, ip string, sealed bool, metadata map[string]string) error {
	return l.logWithMetadata(agent, action, path, "allowed", ip, "", "", sealed, metadata)
}

// LogDenied is a convenience for logging denied actions.
func (l *Logger) LogDenied(agent, action, path, ip, reason string) error {
	return l.LogDeniedWithMetadata(agent, action, path, ip, reason, nil)
}

// LogDeniedWithMetadata logs a denied action with optional sanitized metadata.
func (l *Logger) LogDeniedWithMetadata(agent, action, path, ip, reason string, metadata map[string]string) error {
	return l.logWithMetadata(agent, action, path, "denied", ip, reason, "", false, metadata)
}

// LogSessionAllowed logs a permitted action with session context.
func (l *Logger) LogSessionAllowed(agent, action, path, ip, sessionID string) error {
	return l.LogSessionAllowedWithMetadata(agent, action, path, ip, sessionID, nil)
}

// LogSessionAllowedWithMetadata logs a permitted action with session context
// and optional sanitized metadata.
func (l *Logger) LogSessionAllowedWithMetadata(agent, action, path, ip, sessionID string, metadata map[string]string) error {
	return l.logWithMetadata(agent, action, path, "allowed", ip, "", sessionID, false, metadata)
}

// LogSessionAllowedSealed logs a permitted action with session context and response
// seal state (true when the response was sealed).
func (l *Logger) LogSessionAllowedSealed(agent, action, path, ip, sessionID string, sealed bool) error {
	return l.LogSessionAllowedSealedWithMetadata(agent, action, path, ip, sessionID, sealed, nil)
}

// LogSessionAllowedSealedWithMetadata logs a permitted action with session context,
// response seal state, and optional sanitized metadata.
func (l *Logger) LogSessionAllowedSealedWithMetadata(agent, action, path, ip, sessionID string, sealed bool, metadata map[string]string) error {
	return l.logWithMetadata(agent, action, path, "allowed", ip, "", sessionID, sealed, metadata)
}

// LogSessionDenied logs a denied action with session context.
func (l *Logger) LogSessionDenied(agent, action, path, ip, reason, sessionID string) error {
	return l.LogSessionDeniedWithMetadata(agent, action, path, ip, reason, sessionID, nil)
}

// LogSessionDeniedWithMetadata logs a denied action with session context and
// optional sanitized metadata.
func (l *Logger) LogSessionDeniedWithMetadata(agent, action, path, ip, reason, sessionID string, metadata map[string]string) error {
	return l.logWithMetadata(agent, action, path, "denied", ip, reason, sessionID, false, metadata)
}

// Close closes the audit log file and waits for any archive compression.
func (l *Logger) Close() error {
	l.mu.Lock()
	var err error
	if l.file != nil {
		err = l.file.Close()
		l.file = nil
		l.w = closedWriter{}
	}
	if l.kick != nil {
		close(l.kick)
		l.kick = nil
	}
	l.mu.Unlock()
	l.wg.Wait()
	return err
}

// closedWriter makes a write after Close fail instead of panicking.
type closedWriter struct{}

func (closedWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }
