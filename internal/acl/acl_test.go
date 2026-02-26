package acl

import (
	"testing"

	"git.home/vector/phoenix/internal/crypto"
)

func testACL() *ACL {
	config := &ACLConfig{
		Agents: map[string]Agent{
			"admin": {
				Name:      "admin",
				TokenHash: crypto.HashToken("admin-token"),
				Permissions: []Permission{
					{Path: "*", Actions: []Action{ActionAdmin}},
				},
			},
			"vector": {
				Name:      "vector",
				TokenHash: crypto.HashToken("vector-token"),
				Permissions: []Permission{
					{Path: "openclaw/*", Actions: []Action{ActionRead}},
					{Path: "vector/*", Actions: []Action{ActionRead, ActionWrite}},
					{Path: "infra/*", Actions: []Action{ActionRead}},
				},
			},
			"openclaw": {
				Name:      "openclaw",
				TokenHash: crypto.HashToken("openclaw-token"),
				Permissions: []Permission{
					{Path: "openclaw/*", Actions: []Action{ActionRead}},
				},
			},
		},
	}
	return NewFromConfig(config)
}

func TestAuthenticate(t *testing.T) {
	a := testACL()

	name, err := a.Authenticate("admin-token")
	if err != nil {
		t.Fatalf("Authenticate admin: %v", err)
	}
	if name != "admin" {
		t.Fatalf("expected 'admin', got %q", name)
	}

	name, err = a.Authenticate("vector-token")
	if err != nil {
		t.Fatalf("Authenticate vector: %v", err)
	}
	if name != "vector" {
		t.Fatalf("expected 'vector', got %q", name)
	}
}

func TestAuthenticateInvalid(t *testing.T) {
	a := testACL()

	_, err := a.Authenticate("wrong-token")
	if err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestAuthorizeAdmin(t *testing.T) {
	a := testACL()

	// Admin has wildcard with admin action (covers all actions)
	if err := a.Authorize("admin", "openclaw/api-key", ActionRead); err != nil {
		t.Fatalf("admin read openclaw: %v", err)
	}
	if err := a.Authorize("admin", "openclaw/api-key", ActionWrite); err != nil {
		t.Fatalf("admin write openclaw: %v", err)
	}
	if err := a.Authorize("admin", "proxmox/token", ActionDelete); err != nil {
		t.Fatalf("admin delete proxmox: %v", err)
	}
}

func TestAuthorizeVector(t *testing.T) {
	a := testACL()

	// Vector can read openclaw/*
	if err := a.Authorize("vector", "openclaw/api-key", ActionRead); err != nil {
		t.Fatalf("vector read openclaw: %v", err)
	}

	// Vector can read+write vector/*
	if err := a.Authorize("vector", "vector/config", ActionWrite); err != nil {
		t.Fatalf("vector write vector: %v", err)
	}

	// Vector CANNOT write to openclaw/*
	if err := a.Authorize("vector", "openclaw/api-key", ActionWrite); err != ErrAccessDenied {
		t.Fatalf("vector should not write openclaw, got %v", err)
	}

	// Vector CANNOT read proxmox/*
	if err := a.Authorize("vector", "proxmox/admin-token", ActionRead); err != ErrAccessDenied {
		t.Fatalf("vector should not read proxmox, got %v", err)
	}
}

func TestAuthorizeOpenClaw(t *testing.T) {
	a := testACL()

	// OpenClaw can read its own secrets
	if err := a.Authorize("openclaw", "openclaw/api-key", ActionRead); err != nil {
		t.Fatalf("openclaw read own: %v", err)
	}

	// OpenClaw CANNOT read proxmox secrets
	if err := a.Authorize("openclaw", "proxmox/admin-token", ActionRead); err != ErrAccessDenied {
		t.Fatalf("openclaw should not read proxmox, got %v", err)
	}

	// OpenClaw CANNOT write its own secrets
	if err := a.Authorize("openclaw", "openclaw/api-key", ActionWrite); err != ErrAccessDenied {
		t.Fatalf("openclaw should not write, got %v", err)
	}
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		match   bool
	}{
		{"*", "anything/here", true},
		{"*", "deep/nested/path", true},
		{"openclaw/*", "openclaw/api-key", true},
		{"openclaw/*", "openclaw/token", true},
		{"openclaw/*", "openclaw/deep/nested", false}, // single level only
		{"openclaw/*", "other/api-key", false},
		{"openclaw/**", "openclaw/api-key", true},
		{"openclaw/**", "openclaw/deep/nested", true}, // recursive
		{"openclaw/**", "other/api-key", false},
		{"openclaw/api-key", "openclaw/api-key", true}, // exact
		{"openclaw/api-key", "openclaw/other", false},
	}

	for _, tt := range tests {
		got := matchPath(tt.pattern, tt.path)
		if got != tt.match {
			t.Errorf("matchPath(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.match)
		}
	}
}

func TestHasAction(t *testing.T) {
	actions := []Action{ActionRead, ActionWrite}

	if !hasAction(actions, ActionRead) {
		t.Error("should have read")
	}
	if !hasAction(actions, ActionWrite) {
		t.Error("should have write")
	}
	if hasAction(actions, ActionDelete) {
		t.Error("should not have delete")
	}

	// Admin action grants everything
	adminActions := []Action{ActionAdmin}
	if !hasAction(adminActions, ActionRead) {
		t.Error("admin should cover read")
	}
	if !hasAction(adminActions, ActionDelete) {
		t.Error("admin should cover delete")
	}
}

func TestAddAndRemoveAgent(t *testing.T) {
	a := NewFromConfig(&ACLConfig{Agents: make(map[string]Agent)})

	err := a.AddAgent("test", "test-token", []Permission{
		{Path: "test/*", Actions: []Action{ActionRead}},
	})
	if err != nil {
		t.Fatalf("AddAgent: %v", err)
	}

	name, err := a.Authenticate("test-token")
	if err != nil {
		t.Fatalf("Authenticate new agent: %v", err)
	}
	if name != "test" {
		t.Fatalf("expected 'test', got %q", name)
	}

	err = a.RemoveAgent("test")
	if err != nil {
		t.Fatalf("RemoveAgent: %v", err)
	}

	_, err = a.Authenticate("test-token")
	if err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized after remove, got %v", err)
	}
}

func TestRemoveAgentNotFound(t *testing.T) {
	a := NewFromConfig(&ACLConfig{Agents: make(map[string]Agent)})
	err := a.RemoveAgent("nonexistent")
	if err != ErrAgentNotFound {
		t.Fatalf("expected ErrAgentNotFound, got %v", err)
	}
}

func TestFilePersistence(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/acl.json"

	a1, _ := New(path)
	a1.AddAgent("test", "token123", []Permission{
		{Path: "ns/*", Actions: []Action{ActionRead}},
	})
	a1.Save()

	a2, err := New(path)
	if err != nil {
		t.Fatalf("reload ACL: %v", err)
	}

	name, err := a2.Authenticate("token123")
	if err != nil {
		t.Fatalf("auth after reload: %v", err)
	}
	if name != "test" {
		t.Fatalf("expected 'test', got %q", name)
	}
}
