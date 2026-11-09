package session

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// openTestStore opens a store backed by a sessions file in dir, signing with
// a key derived from a fixed master key, the way the server does.
func openTestStore(t *testing.T, path string, key []byte) *Store {
	t.Helper()
	s, err := OpenStore(Options{TTL: time.Hour, SigningKey: key, Path: path})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(s.Stop)
	return s
}

func testSigningKey(t *testing.T) []byte {
	t.Helper()
	key, err := DeriveSigningKey(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// The bug: a restart used to make a new random key and forget every record.
func TestRestartKeepsLiveSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "role-sessions.json")
	key := testSigningKey(t)

	before := openTestStore(t, path, key)
	tok, sess, err := before.Create("dev", "agent1", nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
	if err != nil {
		t.Fatal(err)
	}
	before.Stop()

	after := openTestStore(t, path, key)
	got, err := after.Validate(tok)
	if err != nil {
		t.Fatalf("token from before the restart: %v", err)
	}
	if got.ID != sess.ID || got.Role != "dev" || got.Namespaces[0] != "dev/*" {
		t.Errorf("restored session = %+v", got)
	}
	if _, _, err := after.Renew(sess.ID, 0); err != nil {
		t.Errorf("renew after restart: %v", err)
	}
}

func TestRestartKeepsRevokedSessionRevoked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "role-sessions.json")
	key := testSigningKey(t)

	before := openTestStore(t, path, key)
	tok, sess, err := before.Create("dev", "agent1", nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := before.Revoke(sess.ID); err != nil {
		t.Fatal(err)
	}
	before.cleanup() // revoked but unexpired: must be kept
	before.Stop()

	after := openTestStore(t, path, key)
	if _, err := after.Validate(tok); err != ErrSessionRevoked {
		t.Fatalf("revoked token after restart: got %v, want ErrSessionRevoked", err)
	}
	if _, _, err := after.Renew(sess.ID, 0); err != ErrSessionRevoked {
		t.Fatalf("renew revoked after restart: got %v, want ErrSessionRevoked", err)
	}
}

// A new signing key (no master key, or a rotated one) still kills old tokens.
func TestRestartWithNewKeyRejectsOldTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "role-sessions.json")
	before := openTestStore(t, path, testSigningKey(t))
	tok, _, err := before.Create("dev", "agent1", nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
	if err != nil {
		t.Fatal(err)
	}
	before.Stop()

	after := openTestStore(t, path, nil)
	if _, err := after.Validate(tok); err != ErrSignatureInvalid {
		t.Fatalf("got %v, want ErrSignatureInvalid", err)
	}
}

func TestSessionsFileHoldsNoToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "role-sessions.json")
	s := openTestStore(t, path, testSigningKey(t))
	tok, _, err := s.Create("dev", "agent1", nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sig := tok[strings.LastIndexByte(tok, '.')+1:]
	if bytes.Contains(data, []byte(TokenPrefix)) || bytes.Contains(data, []byte(sig)) {
		t.Errorf("sessions file contains token material:\n%s", data)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("sessions file mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestExpiredSessionsNotLoaded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "role-sessions.json")
	key := testSigningKey(t)
	before := openTestStore(t, path, key)
	if _, _, err := before.Create("dev", "agent1", nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", time.Millisecond); err != nil {
		t.Fatal(err)
	}
	before.Stop()
	time.Sleep(5 * time.Millisecond)

	after := openTestStore(t, path, key)
	if n := len(after.sessions); n != 0 {
		t.Errorf("loaded %d expired sessions, want 0", n)
	}
}

func TestUnreadableSessionsFileMovedAside(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "role-sessions.json")
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	s := openTestStore(t, path, testSigningKey(t))
	if n := len(s.sessions); n != 0 {
		t.Errorf("sessions = %d, want 0", n)
	}
	aside, _ := filepath.Glob(path + ".corrupt-*")
	if len(aside) != 1 {
		t.Errorf("corrupt file not moved aside: %v", aside)
	}
}

func TestDeriveSigningKey(t *testing.T) {
	master := bytes.Repeat([]byte{7}, 32)
	a, err := DeriveSigningKey(master)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := DeriveSigningKey(master)
	other, _ := DeriveSigningKey(bytes.Repeat([]byte{8}, 32))
	if len(a) != SigningKeyBytes || !bytes.Equal(a, b) {
		t.Errorf("derivation not stable")
	}
	if bytes.Equal(a, master) || bytes.Equal(a, other) {
		t.Errorf("derived key equals master key or another master's key")
	}
	if _, err := DeriveSigningKey(nil); err == nil {
		t.Errorf("empty master key accepted")
	}
}
