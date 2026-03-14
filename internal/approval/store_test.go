package approval

import (
	"testing"
	"time"
)

func TestStoreCreateGet(t *testing.T) {
	s := NewStore(5 * time.Minute)
	defer s.Stop()

	apr, err := s.Create("deploy", "agent-1", []byte("pubkey"), []string{"prod/*"}, []string{"read_value"}, "bearer", "", "127.0.0.1", "/dev/pts/0", 15*time.Minute, 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if apr.ID == "" || apr.ID[:4] != "apr_" {
		t.Errorf("ID = %q, want apr_ prefix", apr.ID)
	}
	if apr.Status != StatusPending {
		t.Errorf("Status = %q, want pending", apr.Status)
	}
	if apr.Role != "deploy" {
		t.Errorf("Role = %q, want deploy", apr.Role)
	}

	got := s.Get(apr.ID)
	if got == nil {
		t.Fatal("Get returned nil")
	}
	if got.ID != apr.ID {
		t.Errorf("Get.ID = %q, want %q", got.ID, apr.ID)
	}
}

func TestStoreGetNotFound(t *testing.T) {
	s := NewStore(5 * time.Minute)
	defer s.Stop()

	if got := s.Get("apr_nonexistent"); got != nil {
		t.Errorf("expected nil for nonexistent ID, got %+v", got)
	}
}

func TestStoreApprove(t *testing.T) {
	s := NewStore(5 * time.Minute)
	defer s.Stop()

	apr, _ := s.Create("deploy", "agent-1", nil, []string{"prod/*"}, nil, "bearer", "", "127.0.0.1", "", 15*time.Minute, 0)

	expiry := time.Now().Add(15 * time.Minute)
	err := s.Approve(apr.ID, "admin", "127.0.0.1", "/dev/pts/1", "phxs_token123", "ses_abc", expiry)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}

	got := s.Get(apr.ID)
	if got.Status != StatusApproved {
		t.Errorf("Status = %q, want approved", got.Status)
	}
	if got.SessionToken != "phxs_token123" {
		t.Errorf("SessionToken = %q, want phxs_token123", got.SessionToken)
	}
	if got.ApprovedBy != "admin" {
		t.Errorf("ApprovedBy = %q, want admin", got.ApprovedBy)
	}
}

func TestStoreApproveIdempotent(t *testing.T) {
	s := NewStore(5 * time.Minute)
	defer s.Stop()

	apr, _ := s.Create("deploy", "agent-1", nil, []string{"prod/*"}, nil, "bearer", "", "127.0.0.1", "", 15*time.Minute, 0)

	expiry := time.Now().Add(15 * time.Minute)
	_ = s.Approve(apr.ID, "admin", "127.0.0.1", "", "phxs_tok", "ses_1", expiry)

	// Second approve should succeed (idempotent)
	err := s.Approve(apr.ID, "admin2", "127.0.0.2", "", "phxs_tok2", "ses_2", expiry)
	if err != nil {
		t.Fatalf("second Approve should be idempotent, got: %v", err)
	}

	// Original values should be preserved
	got := s.Get(apr.ID)
	if got.SessionToken != "phxs_tok" {
		t.Errorf("SessionToken = %q, want phxs_tok (original)", got.SessionToken)
	}
}

func TestStoreDeny(t *testing.T) {
	s := NewStore(5 * time.Minute)
	defer s.Stop()

	apr, _ := s.Create("deploy", "agent-1", nil, []string{"prod/*"}, nil, "bearer", "", "127.0.0.1", "", 15*time.Minute, 0)

	err := s.Deny(apr.ID, "admin", "127.0.0.1")
	if err != nil {
		t.Fatalf("Deny: %v", err)
	}

	got := s.Get(apr.ID)
	if got.Status != StatusDenied {
		t.Errorf("Status = %q, want denied", got.Status)
	}
}

func TestStoreDenyAfterApprove(t *testing.T) {
	s := NewStore(5 * time.Minute)
	defer s.Stop()

	apr, _ := s.Create("deploy", "agent-1", nil, []string{"prod/*"}, nil, "bearer", "", "127.0.0.1", "", 15*time.Minute, 0)

	expiry := time.Now().Add(15 * time.Minute)
	_ = s.Approve(apr.ID, "admin", "127.0.0.1", "", "phxs_tok", "ses_1", expiry)

	err := s.Deny(apr.ID, "admin", "127.0.0.1")
	if err != ErrNotPending {
		t.Fatalf("Deny after Approve should return ErrNotPending, got: %v", err)
	}
}

func TestStoreApproveAfterDeny(t *testing.T) {
	s := NewStore(5 * time.Minute)
	defer s.Stop()

	apr, _ := s.Create("deploy", "agent-1", nil, []string{"prod/*"}, nil, "bearer", "", "127.0.0.1", "", 15*time.Minute, 0)

	_ = s.Deny(apr.ID, "admin", "127.0.0.1")

	expiry := time.Now().Add(15 * time.Minute)
	err := s.Approve(apr.ID, "admin", "127.0.0.1", "", "phxs_tok", "ses_1", expiry)
	if err != ErrNotPending {
		t.Fatalf("Approve after Deny should return ErrNotPending, got: %v", err)
	}
}

func TestStoreExpiry(t *testing.T) {
	s := NewStore(50 * time.Millisecond)
	defer s.Stop()

	apr, _ := s.Create("deploy", "agent-1", nil, []string{"prod/*"}, nil, "bearer", "", "127.0.0.1", "", 15*time.Minute, 50*time.Millisecond)

	// Should be pending initially
	got := s.Get(apr.ID)
	if got.Status != StatusPending {
		t.Fatalf("initial Status = %q, want pending", got.Status)
	}

	time.Sleep(60 * time.Millisecond)

	got = s.Get(apr.ID)
	if got.Status != StatusExpired {
		t.Errorf("Status = %q, want expired", got.Status)
	}

	// Approve should fail on expired
	expiry := time.Now().Add(15 * time.Minute)
	err := s.Approve(apr.ID, "admin", "127.0.0.1", "", "phxs_tok", "ses_1", expiry)
	if err != ErrNotPending {
		t.Errorf("Approve on expired should return ErrNotPending, got: %v", err)
	}
}

func TestStoreApproveNotFound(t *testing.T) {
	s := NewStore(5 * time.Minute)
	defer s.Stop()

	expiry := time.Now().Add(15 * time.Minute)
	err := s.Approve("apr_nonexistent", "admin", "127.0.0.1", "", "phxs_tok", "ses_1", expiry)
	if err != ErrNotFound {
		t.Errorf("Approve nonexistent should return ErrNotFound, got: %v", err)
	}
}

func TestStoreDenyNotFound(t *testing.T) {
	s := NewStore(5 * time.Minute)
	defer s.Stop()

	err := s.Deny("apr_nonexistent", "admin", "127.0.0.1")
	if err != ErrNotFound {
		t.Errorf("Deny nonexistent should return ErrNotFound, got: %v", err)
	}
}

func TestStoreListPending(t *testing.T) {
	s := NewStore(5 * time.Minute)
	defer s.Stop()

	// Create 3 approvals
	apr1, _ := s.Create("deploy", "agent-1", nil, []string{"prod/*"}, nil, "bearer", "", "127.0.0.1", "", 15*time.Minute, 0)
	_, _ = s.Create("viewer", "agent-2", nil, []string{"dev/*"}, nil, "bearer", "", "127.0.0.1", "", 15*time.Minute, 0)
	apr3, _ := s.Create("admin", "agent-3", nil, []string{"*"}, nil, "mtls", "", "10.0.0.1", "", 15*time.Minute, 0)

	// Approve one, deny another
	expiry := time.Now().Add(15 * time.Minute)
	_ = s.Approve(apr1.ID, "admin", "127.0.0.1", "", "phxs_tok", "ses_1", expiry)
	_ = s.Deny(apr3.ID, "admin", "127.0.0.1")

	pending := s.ListPending()
	if len(pending) != 1 {
		t.Fatalf("ListPending = %d, want 1", len(pending))
	}
	if pending[0].Role != "viewer" {
		t.Errorf("pending[0].Role = %q, want viewer", pending[0].Role)
	}
}
