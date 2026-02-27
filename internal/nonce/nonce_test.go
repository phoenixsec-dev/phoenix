package nonce

import (
	"testing"
	"time"
)

func TestGenerateAndValidate(t *testing.T) {
	s := NewStore(5 * time.Second)
	defer s.Stop()

	entry, err := s.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if entry.Nonce == "" {
		t.Fatal("expected non-empty nonce")
	}
	if entry.Expires.IsZero() {
		t.Fatal("expected non-zero expiry")
	}

	// Validate should succeed
	if err := s.Validate(entry.Nonce); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestSingleUse(t *testing.T) {
	s := NewStore(5 * time.Second)
	defer s.Stop()

	entry, _ := s.Generate()

	// First validation succeeds
	if err := s.Validate(entry.Nonce); err != nil {
		t.Fatalf("first Validate: %v", err)
	}

	// Second validation fails (replay)
	if err := s.Validate(entry.Nonce); err == nil {
		t.Fatal("expected replay detection on second Validate")
	}
}

func TestUnknownNonce(t *testing.T) {
	s := NewStore(5 * time.Second)
	defer s.Stop()

	if err := s.Validate("nonexistent"); err == nil {
		t.Fatal("expected error for unknown nonce")
	}
}

func TestExpiredNonce(t *testing.T) {
	s := NewStore(1 * time.Millisecond)
	defer s.Stop()

	entry, _ := s.Generate()

	// Wait for expiry
	time.Sleep(10 * time.Millisecond)

	if err := s.Validate(entry.Nonce); err == nil {
		t.Fatal("expected error for expired nonce")
	}
}

func TestPendingCount(t *testing.T) {
	s := NewStore(5 * time.Second)
	defer s.Stop()

	if s.Pending() != 0 {
		t.Fatalf("expected 0 pending, got %d", s.Pending())
	}

	s.Generate()
	s.Generate()
	if s.Pending() != 2 {
		t.Fatalf("expected 2 pending, got %d", s.Pending())
	}
}

func TestCleanup(t *testing.T) {
	s := NewStore(1 * time.Millisecond)
	defer s.Stop()

	s.Generate()
	s.Generate()

	time.Sleep(10 * time.Millisecond)
	s.cleanup() // manually trigger

	if s.Pending() != 0 {
		t.Fatalf("expected 0 pending after cleanup, got %d", s.Pending())
	}
}

func TestNonceUniqueness(t *testing.T) {
	s := NewStore(5 * time.Second)
	defer s.Stop()

	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		entry, err := s.Generate()
		if err != nil {
			t.Fatalf("Generate #%d: %v", i, err)
		}
		if seen[entry.Nonce] {
			t.Fatalf("duplicate nonce on iteration %d: %s", i, entry.Nonce)
		}
		seen[entry.Nonce] = true
	}
}

func TestStopIdempotent(t *testing.T) {
	s := NewStore(5 * time.Second)
	s.Stop()
	s.Stop() // should not panic
}
