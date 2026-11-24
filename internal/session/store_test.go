package session

import (
	"crypto/rand"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testFP is the credential fingerprint test sessions are minted with.
const testFP = "sha256:test"

// bindTestFP makes testFP every agent's current credential.
func bindTestFP(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.BindCredentials(func(_, fp string) bool { return fp == testFP }); err != nil {
		t.Fatalf("BindCredentials: %v", err)
	}
}

func newTestStore(t *testing.T, ttl time.Duration) *Store {
	t.Helper()
	s, err := NewStore(ttl)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(s.Stop)
	bindTestFP(t, s)
	return s
}

func TestStoreCreateValidate(t *testing.T) {
	s := newTestStore(t, time.Hour)

	token, sess, err := s.Create("dev", "agent1", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if !strings.HasPrefix(token, TokenPrefix) {
		t.Errorf("token missing prefix")
	}
	if !strings.HasPrefix(sess.ID, "ses_") {
		t.Errorf("session ID missing ses_ prefix: %s", sess.ID)
	}
	if sess.Role != "dev" {
		t.Errorf("Role = %q, want %q", sess.Role, "dev")
	}
	if sess.Agent != "agent1" {
		t.Errorf("Agent = %q, want %q", sess.Agent, "agent1")
	}

	got, err := s.Validate(token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.ID != sess.ID {
		t.Errorf("session ID mismatch: %s vs %s", got.ID, sess.ID)
	}
}

func TestStoreCreateWithSealKey(t *testing.T) {
	s := newTestStore(t, time.Hour)

	sealKey := make([]byte, 32)
	if _, err := rand.Read(sealKey); err != nil {
		t.Fatal(err)
	}

	_, sess, err := s.Create("secure", "agent1", testFP, sealKey, []string{"prod/*"}, nil, "bearer", "192.0.2.10", 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	expectedFP := SealKeyFingerprint(sealKey)
	if sess.SealKeyFingerprint != expectedFP {
		t.Errorf("SealKeyFingerprint = %q, want %q", sess.SealKeyFingerprint, expectedFP)
	}
}

func TestStoreRevoke(t *testing.T) {
	s := newTestStore(t, time.Hour)

	token, sess, err := s.Create("dev", "agent1", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.Revoke(sess.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	_, err = s.Validate(token)
	if err != ErrSessionRevoked {
		t.Fatalf("expected ErrSessionRevoked, got %v", err)
	}

	// Double revoke is idempotent
	if err := s.Revoke(sess.ID); err != nil {
		t.Fatalf("double Revoke: %v", err)
	}
}

func TestStoreRevokeNotFound(t *testing.T) {
	s := newTestStore(t, time.Hour)

	err := s.Revoke("ses_nonexistent")
	if err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestStoreExpiredSession(t *testing.T) {
	s := newTestStore(t, 1*time.Millisecond)

	token, _, err := s.Create("dev", "agent1", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 1*time.Millisecond)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	_, err = s.Validate(token)
	if err != ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestStoreGet(t *testing.T) {
	s := newTestStore(t, time.Hour)

	_, sess, err := s.Create("dev", "agent1", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got := s.Get(sess.ID)
	if got == nil {
		t.Fatal("Get returned nil")
	}
	if got.ID != sess.ID {
		t.Errorf("ID mismatch: %s vs %s", got.ID, sess.ID)
	}

	if s.Get("ses_nonexistent") != nil {
		t.Error("Get returned non-nil for nonexistent session")
	}
}

func TestStoreList(t *testing.T) {
	s := newTestStore(t, time.Hour)

	for i := 0; i < 3; i++ {
		_, _, err := s.Create("dev", "agent1", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
		if err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
	}

	list := s.List()
	if len(list) != 3 {
		t.Fatalf("List() returned %d sessions, want 3", len(list))
	}

	if s.ActiveCount() != 3 {
		t.Fatalf("ActiveCount() = %d, want 3", s.ActiveCount())
	}
}

func TestStoreListExcludesRevoked(t *testing.T) {
	s := newTestStore(t, time.Hour)

	_, sess1, _ := s.Create("dev", "agent1", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
	s.Create("dev", "agent2", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)

	s.Revoke(sess1.ID)

	list := s.List()
	if len(list) != 1 {
		t.Fatalf("List() returned %d sessions, want 1", len(list))
	}
}

func TestStoreConcurrentAccess(t *testing.T) {
	s := newTestStore(t, time.Hour)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, _, err := s.Create("dev", "agent", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
			if err != nil {
				t.Errorf("Create: %v", err)
				return
			}
			_, err = s.Validate(token)
			if err != nil {
				t.Errorf("Validate: %v", err)
			}
		}()
	}
	wg.Wait()

	if s.ActiveCount() != 50 {
		t.Errorf("ActiveCount() = %d, want 50", s.ActiveCount())
	}
}

func TestStoreCleanup(t *testing.T) {
	s := newTestStore(t, time.Hour)

	// Create one that will be "expired" and one active
	_, _, err := s.Create("dev", "agent1", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Manually expire the first session
	s.mu.Lock()
	for _, sess := range s.sessions {
		sess.ExpiresAt = time.Now().Add(-time.Second)
		break
	}
	s.mu.Unlock()

	// Create an active one
	_, _, err = s.Create("dev", "agent2", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Run cleanup directly
	s.cleanup()

	s.mu.RLock()
	count := len(s.sessions)
	s.mu.RUnlock()

	if count != 1 {
		t.Errorf("after cleanup: %d sessions, want 1", count)
	}
}

// Revoked sessions stay until they expire so they keep answering
// SESSION_REVOKED (not SESSION_INVALID, which clients re-mint on).
func TestStoreCleanupKeepsRevokedUntilExpiry(t *testing.T) {
	s := newTestStore(t, time.Hour)
	tok, sess, err := s.Create("dev", "agent1", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Revoke(sess.ID); err != nil {
		t.Fatal(err)
	}
	s.cleanup()
	if _, err := s.Validate(tok); err != ErrSessionRevoked {
		t.Fatalf("after cleanup: got %v, want ErrSessionRevoked", err)
	}
}

func TestStoreDefaultActions(t *testing.T) {
	s := newTestStore(t, time.Hour)

	// nil actions -> defaults to ["list", "read_value"]
	_, sess, err := s.Create("dev", "agent1", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if !sess.ActionAllowed("list") {
		t.Error("expected list to be allowed")
	}
	if !sess.ActionAllowed("read_value") {
		t.Error("expected read_value to be allowed")
	}
	if sess.ActionAllowed("write") {
		t.Error("expected write to be denied")
	}
	if sess.ActionAllowed("delete") {
		t.Error("expected delete to be denied")
	}
}

func TestStoreExplicitActions(t *testing.T) {
	s := newTestStore(t, time.Hour)

	_, sess, err := s.Create("deployer", "agent1", testFP, nil, []string{"deploy/*"}, []string{"list", "read_value", "write"}, "bearer", "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if !sess.ActionAllowed("write") {
		t.Error("expected write to be allowed")
	}
	if sess.ActionAllowed("delete") {
		t.Error("expected delete to be denied")
	}
	if sess.ActionAllowed("admin") {
		t.Error("expected admin to be denied")
	}
}

func TestStoreAdminAction(t *testing.T) {
	s := newTestStore(t, time.Hour)

	_, sess, err := s.Create("admin", "agent1", testFP, nil, []string{"*"}, []string{"admin"}, "bearer", "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if !sess.ActionAllowed("write") {
		t.Error("admin should allow write")
	}
	if !sess.ActionAllowed("delete") {
		t.Error("admin should allow delete")
	}
	if !sess.ActionAllowed("list") {
		t.Error("admin should allow list")
	}
}

func TestStoreRenew(t *testing.T) {
	s := newTestStore(t, time.Hour)

	token, sess, err := s.Create("dev", "agent1", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	origExpiry := sess.ExpiresAt
	time.Sleep(5 * time.Millisecond)

	newToken, renewed, err := s.Renew(sess.ID, 2*time.Hour)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}

	if newToken == token {
		t.Error("expected new token to differ from original")
	}
	if renewed.ID != sess.ID {
		t.Errorf("session ID changed: %s -> %s", sess.ID, renewed.ID)
	}
	if !renewed.ExpiresAt.After(origExpiry) {
		t.Errorf("ExpiresAt not extended: %v -> %v", origExpiry, renewed.ExpiresAt)
	}

	// New token should validate
	got, err := s.Validate(newToken)
	if err != nil {
		t.Fatalf("Validate new token: %v", err)
	}
	if got.ID != sess.ID {
		t.Errorf("validated session ID mismatch")
	}
}

func TestStoreRenewExpired(t *testing.T) {
	s := newTestStore(t, time.Millisecond)

	_, sess, err := s.Create("dev", "agent1", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", time.Millisecond)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	_, _, err = s.Renew(sess.ID, time.Hour)
	if err != ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestStoreRenewRevoked(t *testing.T) {
	s := newTestStore(t, time.Hour)

	_, sess, err := s.Create("dev", "agent1", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.Revoke(sess.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	_, _, err = s.Renew(sess.ID, time.Hour)
	if err != ErrSessionRevoked {
		t.Fatalf("expected ErrSessionRevoked, got %v", err)
	}
}

func TestStoreRenewNotFound(t *testing.T) {
	s := newTestStore(t, time.Hour)

	_, _, err := s.Renew("ses_nonexistent", time.Hour)
	if err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestStoreDefaultTTL(t *testing.T) {
	s := newTestStore(t, 0)

	_, sess, err := s.Create("dev", "agent1", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	expectedDuration := DefaultTTL
	actualDuration := sess.ExpiresAt.Sub(sess.CreatedAt)
	// Allow 1 second of drift
	if actualDuration < expectedDuration-time.Second || actualDuration > expectedDuration+time.Second {
		t.Errorf("session duration = %v, want ~%v", actualDuration, expectedDuration)
	}
}

func TestParseClaimsInsecure(t *testing.T) {
	store, err := NewStore(1 * time.Second) // very short TTL
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer store.Stop()
	bindTestFP(t, store)

	token, sess, err := store.Create("dev", "test-agent", testFP, nil, []string{"test/*"}, nil, "bearer", "127.0.0.1", 1*time.Second)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Immediately, claims should be parseable
	agent, sessID, ok := store.ParseClaimsInsecure(token)
	if !ok {
		t.Fatal("expected ParseClaimsInsecure to succeed for valid token")
	}
	if agent != "test-agent" {
		t.Errorf("agent = %q, want test-agent", agent)
	}
	if sessID != sess.ID {
		t.Errorf("sessionID = %q, want %q", sessID, sess.ID)
	}

	// Wait for token to expire
	time.Sleep(2 * time.Second)

	// Validate should fail
	_, err = store.Validate(token)
	if err == nil {
		t.Fatal("expected Validate to fail for expired token")
	}

	// ParseClaimsInsecure should still succeed
	agent, sessID, ok = store.ParseClaimsInsecure(token)
	if !ok {
		t.Fatal("expected ParseClaimsInsecure to succeed for expired token")
	}
	if agent != "test-agent" {
		t.Errorf("agent = %q, want test-agent (expired)", agent)
	}
	if sessID != sess.ID {
		t.Errorf("sessionID = %q, want %q (expired)", sessID, sess.ID)
	}

	// Tampered token should fail
	_, _, ok = store.ParseClaimsInsecure(token + "tampered")
	if ok {
		t.Error("expected ParseClaimsInsecure to fail for tampered token")
	}

	// Garbage should fail
	_, _, ok = store.ParseClaimsInsecure("garbage")
	if ok {
		t.Error("expected ParseClaimsInsecure to fail for garbage input")
	}
}

// Create, Validate and Renew all check the credential, and an empty
// fingerprint never passes, whatever the check says.
func TestSessionCredentialChecked(t *testing.T) {
	current := testFP
	s := newTestStore(t, time.Hour)
	if _, err := s.BindCredentials(func(_, fp string) bool { return fp == current || fp == "" }); err != nil {
		t.Fatal(err)
	}
	mint := func(fp string) (string, *Session, error) {
		return s.Create("dev", "agent1", fp, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
	}
	for _, fp := range []string{"", "sha256:other"} {
		if _, _, err := mint(fp); err != ErrCredentialChanged {
			t.Errorf("Create with fingerprint %q: %v, want ErrCredentialChanged", fp, err)
		}
	}
	tok, _, err := mint(testFP)
	if err != nil {
		t.Fatal(err)
	}
	_, renew, err := mint(testFP)
	if err != nil {
		t.Fatal(err)
	}

	current = "sha256:new"
	if _, err := s.Validate(tok); err != ErrCredentialChanged {
		t.Errorf("Validate: %v, want ErrCredentialChanged", err)
	}
	if _, _, err := s.Renew(renew.ID, 0); err != ErrCredentialChanged {
		t.Errorf("Renew: %v, want ErrCredentialChanged", err)
	}
	current = testFP // ended for good
	if _, err := s.Validate(tok); err != ErrSessionNotFound {
		t.Errorf("Validate after ending: %v, want ErrSessionNotFound", err)
	}
	if _, _, err := s.Renew(renew.ID, 0); err != ErrSessionNotFound {
		t.Errorf("Renew after ending: %v, want ErrSessionNotFound", err)
	}
}

// A store that was never told how to check credentials trusts nothing.
func TestUnboundStoreRefusesSessions(t *testing.T) {
	s, err := NewStore(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	if _, _, err := s.Create("dev", "agent1", testFP, nil, nil, nil, "bearer", "127.0.0.1", 0); err != ErrCredentialChanged {
		t.Errorf("Create on an unbound store: %v, want ErrCredentialChanged", err)
	}
}

// No mint or use runs between ending an agent's sessions and the token
// change itself: one that starts then waits, and is refused.
func TestChangeCredentialHoldsOffMintAndUse(t *testing.T) {
	var current atomic.Value
	current.Store(testFP)
	s := newTestStore(t, time.Hour)
	if _, err := s.BindCredentials(func(_, fp string) bool { return fp == current.Load() }); err != nil {
		t.Fatal(err)
	}
	mint := func() (string, error) {
		tok, _, err := s.Create("dev", "agent1", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
		return tok, err
	}
	tok, err := mint()
	if err != nil {
		t.Fatal(err)
	}
	minted, used := make(chan error, 1), make(chan error, 1)
	_, err = s.ChangeCredential("agent1", func() error {
		go func() { _, err := mint(); minted <- err }()
		go func() { _, err := s.Validate(tok); used <- err }()
		time.Sleep(50 * time.Millisecond) // long enough for both to get in if they could
		current.Store("sha256:new")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-minted; err != ErrCredentialChanged {
		t.Errorf("mint during the change: %v, want ErrCredentialChanged", err)
	}
	if err := <-used; err != ErrSessionNotFound {
		t.Errorf("use during the change: %v, want ErrSessionNotFound", err)
	}
}

// A session revoked while a stale use is being cleaned up keeps saying
// revoked, so clients do not silently replace it.
func TestRevokeDuringStaleCleanupWins(t *testing.T) {
	s := newTestStore(t, time.Hour)
	tok, sess, err := s.Create("dev", "agent1", testFP, nil, []string{"dev/*"}, nil, "bearer", "127.0.0.1", 0)
	if err != nil {
		t.Fatal(err)
	}
	s.credentialCurrent = func(_, _ string) bool { return false }
	found, stale, err := s.lookup(sess.ID)
	if err != nil || !stale {
		t.Fatalf("lookup: stale %v, err %v", stale, err)
	}
	if err := s.Revoke(sess.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.endStale(found); err != ErrSessionRevoked {
		t.Errorf("endStale: %v, want ErrSessionRevoked", err)
	}
	if _, err := s.Validate(tok); err != ErrSessionRevoked {
		t.Errorf("Validate after: %v, want ErrSessionRevoked", err)
	}
}
