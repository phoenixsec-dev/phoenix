// Package acl implements path-based access control for Phoenix.
//
// Each agent has a bearer token (hashed in config) and a set of permissions
// defined as path glob patterns with allowed actions. Evaluation is
// deny-by-default: if no matching rule explicitly allows an action, it's denied.
package acl

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/phoenixsec/phoenix/internal/crypto"
)

// Action represents a permitted operation on a secret.
type Action string

const (
	ActionRead      Action = "read"       // Deprecated: use ActionList and ActionReadValue instead
	ActionList      Action = "list"       // can enumerate paths and metadata
	ActionReadValue Action = "read_value" // can retrieve secret values
	ActionWrite     Action = "write"
	ActionDelete    Action = "delete"
	ActionAdmin     Action = "admin"
)

var (
	ErrUnauthorized  = errors.New("unauthorized: invalid or missing token")
	ErrAccessDenied  = errors.New("access denied: insufficient permissions")
	ErrAgentNotFound = errors.New("agent not found")
	ErrAgentExists   = errors.New("agent already exists")

	// ValidActions is the set of recognized action strings.
	ValidActions = map[Action]bool{
		ActionRead:      true, // deprecated but still accepted
		ActionList:      true,
		ActionReadValue: true,
		ActionWrite:     true,
		ActionDelete:    true,
		ActionAdmin:     true,
	}
)

// ValidatePermissions checks that all permissions have non-empty paths and valid actions.
func ValidatePermissions(perms []Permission) error {
	for _, p := range perms {
		if strings.TrimSpace(p.Path) == "" {
			return fmt.Errorf("empty path in ACL rule")
		}
		if len(p.Actions) == 0 {
			return fmt.Errorf("no actions specified for path %q", p.Path)
		}
		for _, a := range p.Actions {
			if !ValidActions[a] {
				return fmt.Errorf("invalid action %q for path %q (valid: list, read_value, read, write, delete, admin)", a, p.Path)
			}
		}
	}
	return nil
}

// Permission is a single ACL rule.
type Permission struct {
	Path    string   `json:"path"`
	Actions []Action `json:"actions"`
}

// Agent represents an authenticated entity with permissions.
type Agent struct {
	Name        string       `json:"name"`
	TokenHash   string       `json:"token_hash"`
	Permissions []Permission `json:"permissions"`
}

// ACLConfig is the on-disk ACL configuration.
type ACLConfig struct {
	Agents map[string]Agent `json:"agents"`
}

// ACL evaluates access control decisions.
type ACL struct {
	mu     sync.RWMutex
	config *ACLConfig
	path   string
}

// New creates a new ACL from a config file.
func New(path string) (*ACL, error) {
	a := &ACL{path: path}
	if err := a.load(); err != nil {
		return nil, err
	}
	return a, nil
}

// NormalizeActions expands the deprecated "read" action into "list" + "read_value".
// Returns the expanded slice and whether a deprecation was triggered.
func NormalizeActions(actions []Action) ([]Action, bool) {
	deprecated := false
	seen := map[Action]bool{}
	var result []Action
	for _, a := range actions {
		if a == ActionRead {
			deprecated = true
			if !seen[ActionList] {
				result = append(result, ActionList)
				seen[ActionList] = true
			}
			if !seen[ActionReadValue] {
				result = append(result, ActionReadValue)
				seen[ActionReadValue] = true
			}
			continue
		}
		if !seen[a] {
			result = append(result, a)
			seen[a] = true
		}
	}
	return result, deprecated
}

// NewFromConfig creates an ACL from an in-memory config (useful for tests).
func NewFromConfig(config *ACLConfig) *ACL {
	return &ACL{config: config}
}

func (a *ACL) load() error {
	data, err := os.ReadFile(a.path)
	if errors.Is(err, os.ErrNotExist) {
		a.config = &ACLConfig{Agents: make(map[string]Agent)}
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading ACL file: %w", err)
	}

	var config ACLConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("parsing ACL file: %w", err)
	}

	if config.Agents == nil {
		config.Agents = make(map[string]Agent)
	}

	// Normalize deprecated "read" actions to "list" + "read_value".
	for name, agent := range config.Agents {
		warned := false
		for i, perm := range agent.Permissions {
			normalized, dep := NormalizeActions(perm.Actions)
			if dep && !warned {
				log.Printf("WARNING: agent %q uses deprecated 'read' action; migrate to 'list' and/or 'read_value'", name)
				warned = true
			}
			agent.Permissions[i].Actions = normalized
		}
		config.Agents[name] = agent
	}

	a.config = &config
	return nil
}

// Save writes the ACL config to disk.
func (a *ACL) Save() error {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.saveLocked()
}

// saveLocked writes the ACL config to disk. Caller must hold the mutex.
func (a *ACL) saveLocked() error {
	if a.path == "" {
		return errors.New("no file path set for ACL")
	}

	data, err := json.MarshalIndent(a.config, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling ACL: %w", err)
	}

	dir := filepath.Dir(a.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating ACL directory: %w", err)
	}

	tmp := a.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("writing temp ACL file: %w", err)
	}
	if err := os.Rename(tmp, a.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("renaming temp ACL file: %w", err)
	}

	return nil
}

// Authenticate verifies a bearer token and returns the agent name.
func (a *ACL) Authenticate(token string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	hash := crypto.HashToken(token)
	for name, agent := range a.config.Agents {
		if agent.TokenHash == hash {
			return name, nil
		}
	}
	return "", ErrUnauthorized
}

// Authorize checks if an agent is allowed to perform an action on a path.
func (a *ACL) Authorize(agentName string, secretPath string, action Action) error {
	a.mu.RLock()
	defer a.mu.RUnlock()

	agent, ok := a.config.Agents[agentName]
	if !ok {
		return ErrAccessDenied
	}

	for _, perm := range agent.Permissions {
		if matchPath(perm.Path, secretPath) && hasAction(perm.Actions, action) {
			return nil
		}
	}

	return ErrAccessDenied
}

// AddAgent registers a new agent with a token and permissions.
// Returns ErrAgentExists if an agent with the same name already exists.
func (a *ACL) AddAgent(name, token string, permissions []Permission) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, exists := a.config.Agents[name]; exists {
		return ErrAgentExists
	}

	a.config.Agents[name] = Agent{
		Name:        name,
		TokenHash:   crypto.HashToken(token),
		Permissions: permissions,
	}

	if a.path != "" {
		return a.saveLocked()
	}
	return nil
}

// UpdateAgent overwrites an existing agent's token and permissions.
// Returns ErrAgentNotFound if the agent does not exist.
func (a *ACL) UpdateAgent(name, token string, permissions []Permission) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, exists := a.config.Agents[name]; !exists {
		return ErrAgentNotFound
	}

	a.config.Agents[name] = Agent{
		Name:        name,
		TokenHash:   crypto.HashToken(token),
		Permissions: permissions,
	}

	if a.path != "" {
		return a.saveLocked()
	}
	return nil
}

// RemoveAgent removes an agent from the ACL.
func (a *ACL) RemoveAgent(name string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, ok := a.config.Agents[name]; !ok {
		return ErrAgentNotFound
	}

	delete(a.config.Agents, name)

	if a.path != "" {
		return a.saveLocked()
	}
	return nil
}

// ListAgents returns all agent names.
func (a *ACL) ListAgents() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	names := make([]string, 0, len(a.config.Agents))
	for name := range a.config.Agents {
		names = append(names, name)
	}
	return names
}

// GetAgent returns an agent by name (without the raw token).
func (a *ACL) GetAgent(name string) (*Agent, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	agent, ok := a.config.Agents[name]
	if !ok {
		return nil, ErrAgentNotFound
	}
	return &agent, nil
}

// matchPath checks if a glob pattern matches a secret path.
// Supports:
//   - "*" matches everything
//   - "ns/*" matches any single-level path under ns/
//   - "ns/**" matches any path recursively under ns/
//   - exact match
func matchPath(pattern, path string) bool {
	if pattern == "*" || pattern == "**" {
		return true
	}

	// Handle trailing /** (recursive wildcard)
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return strings.HasPrefix(path, prefix+"/") || path == prefix
	}

	// Handle trailing /* (single-level wildcard)
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		if !strings.HasPrefix(path, prefix+"/") {
			return false
		}
		rest := strings.TrimPrefix(path, prefix+"/")
		// Single level: no more slashes
		return !strings.Contains(rest, "/")
	}

	// Exact match
	return pattern == path
}

// hasAction checks if a list of actions contains the target action.
// Legacy "read" implicitly grants both "list" and "read_value" for backward compat.
func hasAction(actions []Action, target Action) bool {
	for _, a := range actions {
		if a == target || a == ActionAdmin {
			return true
		}
		if a == ActionRead && (target == ActionList || target == ActionReadValue) {
			return true
		}
	}
	return false
}
