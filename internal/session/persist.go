package session

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/phoenixsec/phoenix/internal/fsutil"
)

// signingKeyLabel is the fixed HKDF label for the session signing key.
// Changing it invalidates every session token issued before the change.
const signingKeyLabel = "phoenix session signing key v1"

// fileVersion is the format version of the sessions file.
const fileVersion = 1

// Options configures OpenStore.
type Options struct {
	// TTL is the default session lifetime. Zero means DefaultTTL.
	TTL time.Duration
	// SigningKey signs session tokens. Use DeriveSigningKey so the key is the
	// same after a restart. Empty means a random key: every session token
	// dies when the server restarts.
	SigningKey []byte
	// Path is the sessions file. Empty keeps sessions in memory only, so they
	// are gone after a restart.
	Path string
	// RoleFingerprints maps each configured role to a hash of its settings
	// (config.RoleFingerprints). Saved with the sessions; at load, a session
	// whose role is missing here or whose hash changed is dropped.
	RoleFingerprints map[string]string
}

// DeriveSigningKey turns the master key into the session signing key with
// HKDF-SHA256 and a fixed label. The same master key always gives the same
// signing key, so session tokens keep working across restarts without a new
// secret file to protect. The signing key reveals nothing about the master key.
func DeriveSigningKey(masterKey []byte) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, errors.New("deriving session signing key: empty master key")
	}
	return hkdf.Key(sha256.New, masterKey, nil, signingKeyLabel, SigningKeyBytes)
}

// sessionsFile is the on-disk form of the sessions file. It holds session
// records only (who, which role, scope, expiry, revoked), never a token or
// the signing key, so a copy of the file cannot be used to authenticate.
type sessionsFile struct {
	Version  int               `json:"version"`
	Roles    map[string]string `json:"roles"` // role fingerprints when saved
	Sessions []*Session        `json:"sessions"`
}

// loadSessions reads the sessions file and returns the unexpired records
// whose role still exists with the same settings (fingerprint in roles).
// A missing file means no sessions. A file that is not a Phoenix sessions
// file (version 1 with a "sessions" list) is an error and is left untouched:
// it may be another Phoenix file configured at this path (secrets, a TLS
// key, the config), and moving or overwriting it would destroy it.
func loadSessions(path string, roles map[string]string) (map[string]*Session, error) {
	out := make(map[string]*Session)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading sessions file: %w", err)
	}

	var keys map[string]json.RawMessage
	var f sessionsFile
	if err := json.Unmarshal(data, &keys); err != nil || keys["sessions"] == nil ||
		json.Unmarshal(data, &f) != nil || f.Version != fileVersion {
		return nil, fmt.Errorf("%s is not a Phoenix role sessions file, and that path is reserved for one; "+
			"if it is another file, move it; if it is a damaged sessions file, delete it (that only ends sessions)", path)
	}

	now := time.Now()
	changed := 0
	for _, sess := range f.Sessions {
		if sess == nil || sess.ID == "" || now.After(sess.ExpiresAt) {
			continue
		}
		if cur, ok := roles[sess.Role]; !ok || f.Roles[sess.Role] != cur {
			changed++
			continue
		}
		out[sess.ID] = sess
	}
	if changed > 0 {
		log.Printf("  Sessions: ended %d whose role was removed or changed since the last start", changed)
	}
	return out, nil
}

// saveLocked writes every session record to the sessions file. The caller
// must hold s.mu. Does nothing for a memory-only store.
func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	s.unsaved = true
	f := sessionsFile{Version: fileVersion, Roles: s.roleFingerprints, Sessions: make([]*Session, 0, len(s.sessions))}
	for _, sess := range s.sessions {
		f.Sessions = append(f.Sessions, sess)
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding sessions file: %w", err)
	}
	if err := fsutil.WriteFileAtomic(s.path, data, 0600); err != nil {
		return fmt.Errorf("saving sessions file: %w", err)
	}
	s.unsaved = false
	return nil
}
