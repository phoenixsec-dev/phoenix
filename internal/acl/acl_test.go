package acl

import (
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/phoenixsec/phoenix/internal/crypto"
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

func TestValidatePermissions(t *testing.T) {
	tests := []struct {
		name    string
		perms   []Permission
		wantErr bool
	}{
		{"valid", []Permission{{Path: "ns/*", Actions: []Action{ActionRead, ActionWrite}}}, false},
		{"empty path", []Permission{{Path: "", Actions: []Action{ActionRead}}}, true},
		{"no actions", []Permission{{Path: "ns/*", Actions: []Action{}}}, true},
		{"invalid action", []Permission{{Path: "ns/*", Actions: []Action{"rread"}}}, true},
		{"mixed valid and invalid", []Permission{{Path: "ns/*", Actions: []Action{ActionRead, "bogus"}}}, true},
		{"nil perms", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePermissions(tt.perms)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidatePermissions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetAgent(t *testing.T) {
	a := testACL()

	agent, err := a.GetAgent("vector")
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if agent.Name != "vector" {
		t.Fatalf("expected name 'vector', got %q", agent.Name)
	}
	if len(agent.Permissions) != 3 {
		t.Fatalf("expected 3 permissions, got %d", len(agent.Permissions))
	}
}

func TestGetAgentNotFound(t *testing.T) {
	a := testACL()

	_, err := a.GetAgent("nonexistent")
	if err != ErrAgentNotFound {
		t.Fatalf("expected ErrAgentNotFound, got %v", err)
	}
}

func TestAddAgentDuplicate(t *testing.T) {
	a := NewFromConfig(&ACLConfig{Agents: make(map[string]Agent)})

	err := a.AddAgent("agent", "token1", []Permission{
		{Path: "ns1/*", Actions: []Action{ActionRead}},
	})
	if err != nil {
		t.Fatalf("first AddAgent: %v", err)
	}

	// Second AddAgent with same name should return ErrAgentExists
	err = a.AddAgent("agent", "token2", []Permission{
		{Path: "ns2/*", Actions: []Action{ActionWrite}},
	})
	if err != ErrAgentExists {
		t.Fatalf("expected ErrAgentExists, got %v", err)
	}

	// Original token and permissions should be preserved
	name, err := a.Authenticate("token1")
	if err != nil {
		t.Fatalf("original token should still work: %v", err)
	}
	if name != "agent" {
		t.Fatalf("expected 'agent', got %q", name)
	}

	agent, _ := a.GetAgent("agent")
	if agent.Permissions[0].Path != "ns1/*" {
		t.Fatalf("expected original 'ns1/*', got %q", agent.Permissions[0].Path)
	}
}

func TestListAgents(t *testing.T) {
	a := testACL()
	names := a.ListAgents()

	if len(names) != 3 {
		t.Fatalf("expected 3 agents, got %d", len(names))
	}

	// Check all expected agents are present (order not guaranteed)
	found := map[string]bool{}
	for _, n := range names {
		found[n] = true
	}
	for _, expected := range []string{"admin", "vector", "openclaw"} {
		if !found[expected] {
			t.Fatalf("missing agent %q in list", expected)
		}
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

func TestRemoveAgentPersists(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/acl.json"

	a1, _ := New(path)
	a1.AddAgent("ephemeral", "tok1", []Permission{
		{Path: "ns/*", Actions: []Action{ActionRead}},
	})
	a1.AddAgent("keeper", "tok2", []Permission{
		{Path: "ns/*", Actions: []Action{ActionRead}},
	})

	// Remove one agent
	if err := a1.RemoveAgent("ephemeral"); err != nil {
		t.Fatalf("remove: %v", err)
	}

	// Reload from disk — removed agent must stay gone
	a2, err := New(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	if _, err := a2.Authenticate("tok1"); err == nil {
		t.Fatal("removed agent 'ephemeral' should not authenticate after reload")
	}
	if _, err := a2.Authenticate("tok2"); err != nil {
		t.Fatalf("surviving agent 'keeper' should still authenticate: %v", err)
	}
}

func TestAddAgentConcurrent(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/acl.json"

	a, _ := New(path)

	// Concurrently add 20 agents
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("agent-%d", i)
			token := fmt.Sprintf("token-%d", i)
			a.AddAgent(name, token, []Permission{
				{Path: "ns/*", Actions: []Action{ActionRead}},
			})
		}(i)
	}
	wg.Wait()

	// All 20 must be present in memory
	agents := a.ListAgents()
	if len(agents) != 20 {
		t.Fatalf("expected 20 agents, got %d", len(agents))
	}

	// Reload from disk — all 20 must survive
	a2, err := New(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	agents2 := a2.ListAgents()
	if len(agents2) != 20 {
		t.Fatalf("expected 20 agents after reload, got %d", len(agents2))
	}
}

func TestNormalizeActions(t *testing.T) {
	// Legacy "read" expands to list + read_value
	result, dep := NormalizeActions([]Action{ActionRead})
	if !dep {
		t.Fatal("expected deprecation=true for ActionRead")
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 actions, got %d: %v", len(result), result)
	}
	if result[0] != ActionList || result[1] != ActionReadValue {
		t.Fatalf("expected [list, read_value], got %v", result)
	}

	// New actions pass through unchanged
	result2, dep2 := NormalizeActions([]Action{ActionList, ActionReadValue})
	if dep2 {
		t.Fatal("expected deprecation=false for new actions")
	}
	if len(result2) != 2 || result2[0] != ActionList || result2[1] != ActionReadValue {
		t.Fatalf("expected unchanged [list, read_value], got %v", result2)
	}

	// Mixed: read + write
	result3, dep3 := NormalizeActions([]Action{ActionRead, ActionWrite})
	if !dep3 {
		t.Fatal("expected deprecation=true")
	}
	if len(result3) != 3 {
		t.Fatalf("expected 3 actions, got %d: %v", len(result3), result3)
	}

	// Deduplication: read + list should not produce double list
	result4, _ := NormalizeActions([]Action{ActionRead, ActionList})
	listCount := 0
	for _, a := range result4 {
		if a == ActionList {
			listCount++
		}
	}
	if listCount != 1 {
		t.Fatalf("expected exactly 1 list action, got %d in %v", listCount, result4)
	}
}

func TestHasActionLegacyRead(t *testing.T) {
	actions := []Action{ActionRead}

	if !hasAction(actions, ActionList) {
		t.Error("legacy read should grant list")
	}
	if !hasAction(actions, ActionReadValue) {
		t.Error("legacy read should grant read_value")
	}
}

func TestAuthorizeListOnly(t *testing.T) {
	config := &ACLConfig{
		Agents: map[string]Agent{
			"lister": {
				Name:      "lister",
				TokenHash: crypto.HashToken("lister-token"),
				Permissions: []Permission{
					{Path: "test/*", Actions: []Action{ActionList}},
				},
			},
		},
	}
	a := NewFromConfig(config)

	if err := a.Authorize("lister", "test/secret", ActionList); err != nil {
		t.Fatalf("lister should be allowed to list: %v", err)
	}
	if err := a.Authorize("lister", "test/secret", ActionReadValue); err != ErrAccessDenied {
		t.Fatalf("lister should be denied read_value, got %v", err)
	}
}

func TestAuthorizeReadValueOnly(t *testing.T) {
	config := &ACLConfig{
		Agents: map[string]Agent{
			"reader": {
				Name:      "reader",
				TokenHash: crypto.HashToken("reader-token"),
				Permissions: []Permission{
					{Path: "test/*", Actions: []Action{ActionReadValue}},
				},
			},
		},
	}
	a := NewFromConfig(config)

	if err := a.Authorize("reader", "test/secret", ActionReadValue); err != nil {
		t.Fatalf("reader should be allowed read_value: %v", err)
	}
	if err := a.Authorize("reader", "test/secret", ActionList); err != ErrAccessDenied {
		t.Fatalf("reader should be denied list, got %v", err)
	}
}

func TestAuthorizeLegacyReadBackcompat(t *testing.T) {
	config := &ACLConfig{
		Agents: map[string]Agent{
			"legacy": {
				Name:      "legacy",
				TokenHash: crypto.HashToken("legacy-token"),
				Permissions: []Permission{
					{Path: "test/*", Actions: []Action{ActionRead}},
				},
			},
		},
	}
	a := NewFromConfig(config)

	if err := a.Authorize("legacy", "test/secret", ActionList); err != nil {
		t.Fatalf("legacy read should grant list: %v", err)
	}
	if err := a.Authorize("legacy", "test/secret", ActionReadValue); err != nil {
		t.Fatalf("legacy read should grant read_value: %v", err)
	}
}

func TestValidatePermissionsNewActions(t *testing.T) {
	perms := []Permission{
		{Path: "ns/*", Actions: []Action{ActionList}},
		{Path: "ns/*", Actions: []Action{ActionReadValue}},
		{Path: "ns/*", Actions: []Action{ActionList, ActionReadValue, ActionWrite}},
	}
	if err := ValidatePermissions(perms); err != nil {
		t.Fatalf("new actions should be valid: %v", err)
	}
}

func TestSetAgentSealKey(t *testing.T) {
	a := NewFromConfig(&ACLConfig{Agents: make(map[string]Agent)})
	a.AddAgent("test", "tok", []Permission{{Path: "ns/*", Actions: []Action{ActionRead}}})

	// Valid 32-byte key in base64
	validKey := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

	if err := a.SetAgentSealKey("test", validKey); err != nil {
		t.Fatalf("SetAgentSealKey: %v", err)
	}

	got, err := a.GetAgentSealKey("test")
	if err != nil {
		t.Fatalf("GetAgentSealKey: %v", err)
	}
	if got != validKey {
		t.Errorf("seal key = %q, want %q", got, validKey)
	}
}

func TestSetAgentSealKeyNotFound(t *testing.T) {
	a := NewFromConfig(&ACLConfig{Agents: make(map[string]Agent)})

	if err := a.SetAgentSealKey("nonexistent", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="); err != ErrAgentNotFound {
		t.Errorf("expected ErrAgentNotFound, got %v", err)
	}
}

func TestSetAgentSealKeyBadBase64(t *testing.T) {
	a := NewFromConfig(&ACLConfig{Agents: make(map[string]Agent)})
	a.AddAgent("test", "tok", []Permission{{Path: "ns/*", Actions: []Action{ActionRead}}})

	if err := a.SetAgentSealKey("test", "not-valid-base64!!!"); err == nil {
		t.Error("expected error for bad base64")
	}
}

func TestSetAgentSealKeyWrongSize(t *testing.T) {
	a := NewFromConfig(&ACLConfig{Agents: make(map[string]Agent)})
	a.AddAgent("test", "tok", []Permission{{Path: "ns/*", Actions: []Action{ActionRead}}})

	// 16 bytes instead of 32
	shortKey := "AAAAAAAAAAAAAAAAAAAAAA=="
	if err := a.SetAgentSealKey("test", shortKey); err == nil {
		t.Error("expected error for wrong key size")
	}
}

func TestGetAgentSealKeyNoKey(t *testing.T) {
	a := NewFromConfig(&ACLConfig{Agents: make(map[string]Agent)})
	a.AddAgent("test", "tok", []Permission{{Path: "ns/*", Actions: []Action{ActionRead}}})

	got, err := a.GetAgentSealKey("test")
	if err != nil {
		t.Fatalf("GetAgentSealKey: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty seal key, got %q", got)
	}
}

func TestGetAgentSealKeyNotFound(t *testing.T) {
	a := NewFromConfig(&ACLConfig{Agents: make(map[string]Agent)})

	_, err := a.GetAgentSealKey("nonexistent")
	if err != ErrAgentNotFound {
		t.Errorf("expected ErrAgentNotFound, got %v", err)
	}
}

func TestSealKeyPersistence(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/acl.json"

	a1, _ := New(path)
	a1.AddAgent("test", "tok", []Permission{{Path: "ns/*", Actions: []Action{ActionRead}}})

	validKey := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if err := a1.SetAgentSealKey("test", validKey); err != nil {
		t.Fatalf("SetAgentSealKey: %v", err)
	}

	// Reload from disk
	a2, err := New(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	got, err := a2.GetAgentSealKey("test")
	if err != nil {
		t.Fatalf("GetAgentSealKey after reload: %v", err)
	}
	if got != validKey {
		t.Errorf("seal key after reload = %q, want %q", got, validKey)
	}
}

func TestSealKeyBackwardCompat(t *testing.T) {
	// Simulate loading an old ACL config with no seal_public_key field
	dir := t.TempDir()
	path := dir + "/acl.json"

	oldConfig := `{"agents":{"legacy":{"name":"legacy","token_hash":"sha256:abc","permissions":[{"path":"ns/*","actions":["list"]}]}}}`
	if err := os.WriteFile(path, []byte(oldConfig), 0600); err != nil {
		t.Fatalf("writing old config: %v", err)
	}

	a, err := New(path)
	if err != nil {
		t.Fatalf("loading old config: %v", err)
	}

	got, err := a.GetAgentSealKey("legacy")
	if err != nil {
		t.Fatalf("GetAgentSealKey: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty seal key for old config, got %q", got)
	}
}

func TestUpdateAgentPreservesSealKey(t *testing.T) {
	a := NewFromConfig(&ACLConfig{Agents: make(map[string]Agent)})
	a.AddAgent("test", "tok1", []Permission{{Path: "ns/*", Actions: []Action{ActionRead}}})

	validKey := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	a.SetAgentSealKey("test", validKey)

	// UpdateAgent with new token and permissions
	if err := a.UpdateAgent("test", "tok2", []Permission{{Path: "other/*", Actions: []Action{ActionWrite}}}); err != nil {
		t.Fatalf("UpdateAgent: %v", err)
	}

	got, err := a.GetAgentSealKey("test")
	if err != nil {
		t.Fatalf("GetAgentSealKey after update: %v", err)
	}
	if got != validKey {
		t.Errorf("seal key after UpdateAgent = %q, want %q (should be preserved)", got, validKey)
	}
}

func TestSetAgentSealKeyOverwrite(t *testing.T) {
	a := NewFromConfig(&ACLConfig{Agents: make(map[string]Agent)})
	a.AddAgent("test", "tok", []Permission{{Path: "ns/*", Actions: []Action{ActionRead}}})

	key1 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	key2 := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="

	a.SetAgentSealKey("test", key1)
	a.SetAgentSealKey("test", key2)

	got, _ := a.GetAgentSealKey("test")
	if got != key2 {
		t.Errorf("seal key = %q, want %q (should be overwritten)", got, key2)
	}
}
