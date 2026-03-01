package main

import (
	"strings"
	"testing"
)

func TestCmdAgentCreateMissingName(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	token = "test-token"

	err := cmdAgentCreate([]string{"-t", "sometoken"})
	if err == nil {
		t.Fatal("expected error for missing name")
	}
	if !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("expected usage error, got: %v", err)
	}
}

func TestCmdAgentCreateMissingToken(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	token = "test-token"

	err := cmdAgentCreate([]string{"myagent"})
	if err == nil {
		t.Fatal("expected error for missing token")
	}
	if !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("expected usage error, got: %v", err)
	}
}

func TestCmdAgentCreateMalformedACL(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	token = "test-token"

	tests := []struct {
		name   string
		acl    string
		errStr string
	}{
		{"no colon", "nocolon", "malformed ACL rule"},
		{"empty path", ":read", "malformed ACL rule"},
		{"empty actions", "ns/*:", "malformed ACL rule"},
		{"invalid action", "ns/*:rread", "invalid action"},
		{"mixed invalid", "ns/*:read,bogus", "invalid action"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cmdAgentCreate([]string{"agent", "-t", "tok", "--acl", tt.acl})
			if err == nil {
				t.Fatalf("expected error for ACL %q", tt.acl)
			}
			if !strings.Contains(err.Error(), tt.errStr) {
				t.Fatalf("expected %q in error, got: %v", tt.errStr, err)
			}
		})
	}
}

func TestCmdAgentCreateValidACLTrimsSpaces(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	token = "test-token"
	// Valid ACL with spaces — should parse without ACL errors.
	// Will fail at API request (no server), not at parse time.
	err := cmdAgentCreate([]string{"agent", "-t", "tok", "--acl", " ns/* : read , write "})
	if err == nil {
		t.Fatal("expected error (no server), not nil")
	}
	// Should NOT be an ACL parse error
	if strings.Contains(err.Error(), "malformed ACL") || strings.Contains(err.Error(), "invalid action") {
		t.Fatalf("should not be an ACL parse error: %v", err)
	}
}

func TestCmdAgentCreateTrailingSemicolon(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	token = "test-token"
	// Trailing semicolons should be allowed
	err := cmdAgentCreate([]string{"agent", "-t", "tok", "--acl", "ns/*:read;"})
	if err == nil {
		t.Fatal("expected error (no server)")
	}
	if strings.Contains(err.Error(), "malformed ACL") {
		t.Fatalf("trailing semicolon should be allowed: %v", err)
	}
}
