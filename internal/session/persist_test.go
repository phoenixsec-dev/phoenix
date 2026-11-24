package session

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phoenixsec/phoenix/internal/fsutil"
)

// openTestStore opens a store backed by a sessions file in dir, signing with
// a key derived from a fixed master key, the way the server does.
func openTestStore(t *testing.T, path string, key []byte) *Store {
	t.Helper()
	return openTestStoreRoles(t, path, key, map[string]string{"dev": "v1"})
}

// openTestStoreRoles is openTestStore with the given role fingerprints.
func openTestStoreRoles(t *testing.T, path string, key []byte, roles map[string]string) *Store {
	t.Helper()
	s, err := OpenStore(Options{TTL: time.Hour, SigningKey: key, Path: path, RoleFingerprints: roles})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(s.Stop)
	bindTestFP(t, s)
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
	tok, sess, err := before.Create("dev", "agent1", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
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
	tok, sess, err := before.Create("dev", "agent1", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
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
	tok, _, err := before.Create("dev", "agent1", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
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
	tok, _, err := s.Create("dev", "agent1", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
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
	if _, _, err := before.Create("dev", "agent1", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", time.Millisecond); err != nil {
		t.Fatal(err)
	}
	before.Stop()
	time.Sleep(5 * time.Millisecond)

	after := openTestStore(t, path, key)
	if n := len(after.sessions); n != 0 {
		t.Errorf("loaded %d expired sessions, want 0", n)
	}
}

// Another file at the sessions path (a damaged sessions file, a TLS key,
// a secrets store) stops startup and is never moved or overwritten.
func TestForeignFileAtSessionsPathLeftAlone(t *testing.T) {
	for name, content := range map[string]string{
		"damaged":     "{not json",
		"pem key":     "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
		"store.json":  `{"version":1,"namespaces":{},"secrets":{}}`,
		"old version": `{"version":2,"sessions":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "role-sessions.json")
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			s, err := OpenStore(Options{TTL: time.Hour, SigningKey: testSigningKey(t), Path: path})
			if err == nil {
				s.Stop()
				t.Fatal("OpenStore accepted a file that is not a sessions file")
			}
			if b, _ := os.ReadFile(path); string(b) != content {
				t.Fatalf("file changed: %q", b)
			}
			if aside, _ := filepath.Glob(path + "*"); len(aside) != 1 {
				t.Fatalf("extra files next to it: %v", aside)
			}
		})
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

// A role change (or removal) must still end that role's sessions at
// restart, as it did when sessions lived in memory. Other roles keep theirs.
func TestRestartEndsSessionsOfChangedRoles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "role-sessions.json")
	key := testSigningKey(t)
	roles := map[string]string{"dev": "v1", "ops": "v1", "gone": "v1"}

	before := openTestStoreRoles(t, path, key, roles)
	mint := func(role string) string {
		tok, _, err := before.Create(role, "agent1", testFP, nil, []string{role + "/*"}, nil, "bearer", "127.0.0.1", 0)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	devTok, opsTok, goneTok := mint("dev"), mint("ops"), mint("gone")
	before.Stop()

	after := openTestStoreRoles(t, path, key, map[string]string{"dev": "v1", "ops": "v2"})
	if _, err := after.Validate(devTok); err != nil {
		t.Errorf("unchanged role: %v", err)
	}
	if _, err := after.Validate(opsTok); err != ErrSessionNotFound {
		t.Errorf("changed role: got %v, want ErrSessionNotFound", err)
	}
	if _, err := after.Validate(goneTok); err != ErrSessionNotFound {
		t.Errorf("removed role: got %v, want ErrSessionNotFound", err)
	}
}

// A role changed and then changed back must not bring old sessions back.
func TestRoleChangedBackDoesNotReviveSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "role-sessions.json")
	key := testSigningKey(t)
	first := openTestStoreRoles(t, path, key, map[string]string{"dev": "v1"})
	tok, _, err := first.Create("dev", "agent1", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
	if err != nil {
		t.Fatal(err)
	}
	first.Stop()
	openTestStoreRoles(t, path, key, map[string]string{"dev": "v2"}).Stop()

	back := openTestStoreRoles(t, path, key, map[string]string{"dev": "v1"})
	if _, err := back.Validate(tok); err != ErrSessionNotFound {
		t.Fatalf("got %v, want ErrSessionNotFound", err)
	}
}

// A revoke outlives a role change or removal: the token keeps saying revoked,
// so clients ask a person instead of quietly making a new session.
func TestRevokedSessionOfChangedRoleStaysRevoked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "role-sessions.json")
	key := testSigningKey(t)
	s := openTestStoreRoles(t, path, key, map[string]string{"dev": "v1", "gone": "v1"})
	toks := map[string]string{}
	for _, role := range []string{"dev", "gone"} {
		tok, sess, err := s.Create(role, "agent1", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Revoke(sess.ID); err != nil {
			t.Fatal(err)
		}
		toks[role] = tok
	}
	s.Stop()
	// Two restarts: the first one also rewrites the file.
	for i := 1; i <= 2; i++ {
		s = openTestStoreRoles(t, path, key, map[string]string{"dev": "v2"})
		for role, tok := range toks {
			if _, err := s.Validate(tok); err != ErrSessionRevoked {
				t.Errorf("restart %d, role %s: got %v, want ErrSessionRevoked", i, role, err)
			}
		}
		s.Stop()
	}
}

// Ended sessions that could not be saved are saved by the next cleanup.
func TestEndedSessionsSavedByCleanupAfterFailedSave(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "d")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "role-sessions.json")
	s := openTestStore(t, path, testSigningKey(t))
	if _, _, err := s.Create("dev", "agent1", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir, dir+".away"); err != nil {
		t.Fatal(err)
	}
	ended, err := s.ChangeCredential("agent1", func() error { s.credentialCurrent = func(_, _ string) bool { return false }; return nil })
	if err != nil || len(ended) != 1 || s.ActiveCount() != 0 {
		t.Fatalf("ChangeCredential: ended %d, %d active, err %v", len(ended), s.ActiveCount(), err)
	}
	if err := os.Rename(dir+".away", dir); err != nil {
		t.Fatal(err)
	}
	s.cleanup()
	if n := openTestStore(t, path, testSigningKey(t)).ActiveCount(); n != 0 {
		t.Errorf("%d sessions after restart, want 0", n)
	}
}

// A save whose directory sync failed may not survive a power cut: a revoke
// reports it, and cleanup tries again.
func TestDirSyncFailureCountsAsUnsaved(t *testing.T) {
	s := openTestStore(t, filepath.Join(t.TempDir(), "role-sessions.json"), testSigningKey(t))
	if reflect.ValueOf(s.writeFile).Pointer() != reflect.ValueOf(fsutil.WriteFileAtomicStrict).Pointer() {
		t.Error("sessions are not saved with fsutil.WriteFileAtomicStrict")
	}
	_, sess, err := s.Create("dev", "agent1", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
	if err != nil {
		t.Fatal(err)
	}
	s.writeFile = func(p string, data []byte, perm os.FileMode) error {
		return fsutil.WriteFileAtomicStrictOps(p, data, perm, fsutil.AtomicOps{SyncDir: func(string) error { return errors.New("no sync") }})
	}
	if err := s.Revoke(sess.ID); !errors.Is(err, fsutil.ErrDirSyncFailed) {
		t.Fatalf("Revoke: %v, want ErrDirSyncFailed", err)
	}
	s.cleanup()
	if !s.unsaved {
		t.Error("a failed retry must stay pending")
	}
	s.writeFile = fsutil.WriteFileAtomicStrict
	s.cleanup()
	if s.unsaved {
		t.Error("cleanup did not retry the save")
	}
}
