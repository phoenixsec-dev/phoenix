// Package acl implements path-based access control for Phoenix.
//
// Each agent has a bearer token (hashed in config) and a set of permissions
// defined as path glob patterns with allowed actions. Evaluation is
// deny-by-default: if no matching rule explicitly allows an action, it's denied.
package acl

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/phoenixsec/phoenix/internal/crypto"
	"github.com/phoenixsec/phoenix/internal/fsutil"
)

// Action represents a permitted operation on a secret.
type Action string

const (
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
	// ErrReplacedNotSaved means replacing a token could not be saved: the old
	// token no longer works until a restart, and the new one is not in force.
	ErrReplacedNotSaved = errors.New("old token ended, new one not saved and not in force")

	// ErrOwnNotSaved means an agent replacing its own token could not be saved:
	// the old token still works and the new one is not in force.
	ErrOwnNotSaved = errors.New("own token not replaced, the change could not be saved")

	// ValidActions is the set of recognized action strings.
	ValidActions = map[Action]bool{
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
		if p.Always != nil {
			return fmt.Errorf("path %q: \"always\" cannot be set by hand; it marks an answered access request", p.Path)
		}
		for _, a := range p.Actions {
			if a == removedRead {
				return fmt.Errorf("path %q: %s", p.Path, removedReadMsg)
			}
			if !ValidActions[a] {
				return fmt.Errorf("invalid action %q for path %q (valid: list, read_value, write, delete, admin)", a, p.Path)
			}
		}
	}
	return nil
}

// Permission is a single ACL rule.
type Permission struct {
	Path    string   `json:"path"`
	Actions []Action `json:"actions"`
	// Always is set on a rule made by an "always" answer (always.go). Servers
	// older than that ignore it and treat the rule as any other.
	Always *AlwaysOrigin `json:"always,omitempty"`
}

// Agent represents an authenticated entity with permissions.
type Agent struct {
	Name      string `json:"name"`
	TokenHash string `json:"token_hash"`
	// CredentialID is a random ID set each time the agent is given a token. It
	// tells apart two issues of the same token, so a session made with a token
	// that was taken away stays dead if the same token is given out again. Not
	// secret. Empty for tokens issued by v0.23.0 and older or written by hand.
	CredentialID string `json:"credential_id,omitempty"`
	// Serial is a random ID set once, when the identity is made. It tells an
	// identity apart from a later one re-made under the same name. Unlike
	// CredentialID it survives a new token, and an identity without a token
	// can have one. Not secret, but never shown or sent to anyone. Identities
	// from v0.24.0 and older get theirs at the next ACL change (fillSerialsLocked).
	Serial string `json:"serial,omitempty"`
	Labels
	Permissions   []Permission `json:"permissions"`
	SealPublicKey string       `json:"seal_public_key,omitempty"`
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
	linked bool // path was reached through a symlink
	// writeFile saves the ACL file; tests replace it to fail. Strict: a
	// replaced token must not come back after a power cut.
	writeFile func(path string, data []byte, perm os.FileMode) error
	unsaved   []AlwaysRule // taken back but not saved yet (always.go)
	dirty     bool         // the last save failed; RetrySaves tries again
}

// New creates a new ACL from a config file.
func New(path string) (*ACL, error) { return open(path, false) }

// NewExisting is New for a config file that must be there: one that is missing
// when it is read is an error, not an empty access list.
func NewExisting(path string) (*ACL, error) { return open(path, true) }

func open(path string, mustExist bool) (*ACL, error) {
	// The real file, so that saving does not replace a symlink to it.
	a := &ACL{path: fsutil.RealPath(path), linked: fsutil.RealPath(path) != path, writeFile: fsutil.WriteFileAtomicStrict}
	if err := a.load(mustExist); err != nil {
		return nil, err
	}
	return a, nil
}

// NewFromConfig creates an ACL from an in-memory config (useful for tests).
func NewFromConfig(config *ACLConfig) *ACL {
	return &ACL{config: config}
}

func (a *ACL) load(mustExist bool) error {
	data, err := os.ReadFile(a.path)
	if errors.Is(err, os.ErrNotExist) && !mustExist {
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

	if err := refuseRemovedRead(&config); err != nil {
		return err
	}

	a.config = &config
	return nil
}

// Save writes the ACL config to disk.
func (a *ACL) Save() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.saveLocked()
}

// saveLocked writes the ACL config to disk. Caller must hold the mutex for
// writing: it also fills in missing serials.
func (a *ACL) saveLocked() error {
	if a.path == "" {
		return errors.New("no file path set for ACL")
	}

	a.fillSerialsLocked()
	a.dirty = true
	data, err := json.MarshalIndent(a.config, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling ACL: %w", err)
	}

	if !a.linked { // behind a link, a missing directory is a missing volume
		if err := os.MkdirAll(filepath.Dir(a.path), 0700); err != nil {
			return fmt.Errorf("creating ACL directory: %w", err)
		}
	}

	if err := a.writeFile(a.path, data, 0600); err != nil {
		return fmt.Errorf("writing ACL file: %w", err)
	}
	a.unsaved, a.dirty = nil, false

	return nil
}

// RetrySaves saves again, every interval until ctx ends, what could not be
// saved: access taken away on a full disk must not come back at a restart.
func (a *ACL) RetrySaves(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.retrySave()
		}
	}
}

// retrySave is one try of RetrySaves.
func (a *ACL) retrySave() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.dirty {
		return
	}
	if err := a.saveLocked(); err != nil {
		log.Printf("WARNING: access list changes are still not saved, will retry: %v", err)
	}
}

// Authenticate verifies a bearer token and returns the agent name.
func (a *ACL) Authenticate(token string) (string, error) {
	name, _, err := a.AuthenticateAgent(token)
	return name, err
}

// AuthenticateAgent is Authenticate that also returns the agent record the
// token matched, as it was at that moment.
func (a *ACL) AuthenticateAgent(token string) (string, *Agent, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	hash := crypto.HashToken(token)
	for name, agent := range a.config.Agents {
		if agent.TokenHash == hash {
			return name, &agent, nil
		}
	}
	return "", nil, ErrUnauthorized
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
	return a.AddAgentLabeled(name, token, permissions, LabelChange{})
}

// AddAgentLabeled is AddAgent that also sets the new identity's labels.
func (a *ACL) AddAgentLabeled(name, token string, permissions []Permission, labels LabelChange) error {
	labels, err := labels.Normalized(name)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, exists := a.config.Agents[name]; exists {
		return ErrAgentExists
	}

	a.config.Agents[name] = Agent{
		Name:         name,
		TokenHash:    crypto.HashToken(token),
		CredentialID: newRandomID(),
		Serial:       newRandomID(),
		Labels:       labels.applyTo(Labels{}),
		Permissions:  permissions,
	}

	return a.saveOrUndo(func() { delete(a.config.Agents, name) })
}

// saveOrUndo saves a change, and undoes it if that fails: a change answered
// with an error may take access away but never gives any, now or with a later
// save. undo must not bring back a token: one that was replaced must stay dead
// even if the save failed.
func (a *ACL) saveOrUndo(undo func()) error {
	if a.path == "" {
		return nil
	}
	err := a.saveLocked()
	if err == nil {
		return nil
	}
	undo()
	if errors.Is(err, fsutil.ErrDirSyncFailed) { // the file has the change
		if uerr := a.saveLocked(); uerr != nil && !errors.Is(uerr, fsutil.ErrDirSyncFailed) {
			log.Printf("WARNING: %s still holds a change that was refused, will retry: %v", a.path, uerr)
		}
	}
	return err
}

// newRandomID returns a random ID for a newly issued token or a new identity.
func newRandomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // never fails on Go 1.24+
	return hex.EncodeToString(b)
}

// UpdateAgent overwrites an existing agent's token and permissions. The same
// token keeps its CredentialID. The serial, labels and seal key stay.
// Returns ErrAgentNotFound if the agent does not exist.
func (a *ACL) UpdateAgent(name, token string, permissions []Permission) error {
	return a.UpdateAgentLabeled(name, token, permissions, LabelChange{})
}

// UpdateAgentLabeled is UpdateAgent that also changes the labels it is given.
func (a *ACL) UpdateAgentLabeled(name, token string, permissions []Permission, labels LabelChange) error {
	return a.updateAgent(name, token, permissions, labels, false)
}

// UpdateOwnAgent is UpdateAgentLabeled for an agent replacing its own token. If
// that cannot be saved the old token goes on working: without it nobody might
// be left who can try again.
func (a *ACL) UpdateOwnAgent(name, token string, permissions []Permission, labels LabelChange) error {
	return a.updateAgent(name, token, permissions, labels, true)
}

func (a *ACL) updateAgent(name, token string, permissions []Permission, labels LabelChange, own bool) error {
	labels, err := labels.Normalized(name)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	existing, exists := a.config.Agents[name]
	if !exists {
		return ErrAgentNotFound
	}

	hash, credentialID := crypto.HashToken(token), existing.CredentialID
	if hash != existing.TokenHash {
		credentialID = newRandomID()
	}
	a.config.Agents[name] = Agent{
		Name:          name,
		TokenHash:     hash,
		CredentialID:  credentialID,
		Serial:        existing.Serial,
		Labels:        labels.applyTo(existing.Labels),
		Permissions:   permissions,
		SealPublicKey: existing.SealPublicKey,
	}

	newToken := hash != existing.TokenHash
	replaced := newToken && !own
	err = a.saveOrUndo(func() {
		undone := existing
		undone.Serial = a.config.Agents[name].Serial // the save may have given it one
		if replaced {
			undone.TokenHash, undone.CredentialID = "", "" // no token matches this
		}
		a.config.Agents[name] = undone
	})
	if err != nil && newToken && own {
		return fmt.Errorf("%w: %w", ErrOwnNotSaved, err)
	}
	if err != nil && replaced {
		return fmt.Errorf("%w: %w", ErrReplacedNotSaved, err)
	}
	return err
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

// SetAgentSealKey registers or updates an agent's public seal key.
// The key must be valid base64 encoding exactly 32 bytes (X25519 public key).
func (a *ACL) SetAgentSealKey(name string, publicKey string) error {
	raw, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return fmt.Errorf("invalid seal key encoding: %w", err)
	}
	if len(raw) != 32 {
		return fmt.Errorf("invalid seal key size: got %d bytes, want 32", len(raw))
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	agent, ok := a.config.Agents[name]
	if !ok {
		return ErrAgentNotFound
	}

	old := agent
	agent.SealPublicKey = publicKey
	a.config.Agents[name] = agent

	return a.saveOrUndo(func() {
		old.Serial = a.config.Agents[name].Serial // the save may have given it one
		a.config.Agents[name] = old
	})
}

// GetAgentSealKey returns an agent's registered public seal key.
// Returns ErrAgentNotFound if the agent does not exist.
// Returns empty string (no error) if the agent has no seal key.
func (a *ACL) GetAgentSealKey(name string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	agent, ok := a.config.Agents[name]
	if !ok {
		return "", ErrAgentNotFound
	}
	return agent.SealPublicKey, nil
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
func hasAction(actions []Action, target Action) bool {
	for _, a := range actions {
		if a == target || a == ActionAdmin {
			return true
		}
	}
	return false
}

// removedRead is the old "read" shorthand for list + read_value. It is
// refused by name rather than treated as an unknown action, so the error says
// what to write instead.
const removedRead Action = "read"

const removedReadMsg = `action "read" was removed: it was shorthand for list + read_value, and hid that it let the agent read values. Write "list", "read_value" (or just "list")`

// refuseRemovedRead returns an error naming every agent and path in an ACL
// file that still uses "read", so the server refuses to start instead of
// quietly granting or dropping access.
func refuseRemovedRead(config *ACLConfig) error {
	var lines []string
	for name, agent := range config.Agents {
		for _, perm := range agent.Permissions {
			for _, a := range perm.Actions {
				if a == removedRead {
					lines = append(lines, fmt.Sprintf("agent %q path %q", name, perm.Path))
				}
			}
		}
	}
	if len(lines) == 0 {
		return nil
	}
	sort.Strings(lines)
	return fmt.Errorf("ACL file uses settings Phoenix no longer has (fix them to start): %s. Uses:\n  %s",
		removedReadMsg, strings.Join(lines, "\n  "))
}
