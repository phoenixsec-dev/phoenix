package acl

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/phoenixsec/phoenix/internal/fsutil"
)

// AlwaysOrigin marks a rule that came from a human answering an access request
// with "always". It is what lets the dashboard show the rule and take it back;
// it does not change what the rule allows.
type AlwaysOrigin struct {
	RequestID string    `json:"request_id"`
	By        string    `json:"by"`
	At        time.Time `json:"at"`
}

// AlwaysRule is one path an agent may read because of an "always".
type AlwaysRule struct {
	Agent string
	Path  string
	AlwaysOrigin
	// Unsaved: taken back and denied now, but the file still has it, so a
	// restart would bring it back. Removing it again retries the save.
	Unsaved bool
}

// AddAlways lets agent read exactly paths, marked with origin, replacing any
// rules already there from the same request. check sees the agent's record
// under the lock, so what it verified cannot change before the rules land. On
// any error the agent can read nothing more than before.
func (a *ACL) AddAlways(agent string, origin AlwaysOrigin, paths []string, check func(Agent) error) error {
	if origin.RequestID == "" || len(paths) == 0 {
		return errors.New("always rule needs a request and at least one path")
	}
	for _, p := range paths {
		// Rules are patterns. A path that could match anything else is refused
		// here as well as when it was asked for.
		if strings.TrimSpace(p) == "" || strings.Contains(p, "*") {
			return fmt.Errorf("always rule needs an exact path, not %q", p)
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	old, ok := a.config.Agents[agent]
	if !ok {
		return ErrAgentNotFound
	}
	if err := check(old); err != nil {
		return err
	}
	updated := old
	updated.Permissions, _ = dropRules(old.Permissions, func(p Permission) bool {
		return p.Always != nil && p.Always.RequestID == origin.RequestID
	})
	for _, p := range paths {
		o := origin
		updated.Permissions = append(updated.Permissions, Permission{Path: p, Actions: []Action{ActionReadValue}, Always: &o})
	}
	a.config.Agents[agent] = updated
	if a.path == "" {
		return nil
	}
	err := a.saveLocked()
	if err == nil {
		return nil
	}
	a.config.Agents[agent] = old
	if errors.Is(err, fsutil.ErrDirSyncFailed) {
		// The new file is already in place; put the old content back.
		if rerr := a.saveLocked(); rerr != nil {
			return fmt.Errorf("%w (and the old file could not be put back: %v)", err, rerr)
		}
	}
	return err
}

// RemoveAlways takes back every "always" rule for this agent and exact path and
// returns how many there were. When the save fails the rules are gone from
// memory, so reads are denied at once, but may return after a restart.
func (a *ACL) RemoveAlways(agent, path string) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ag, ok := a.config.Agents[agent]
	if !ok {
		return 0, ErrAgentNotFound
	}
	kept, n := dropRules(ag.Permissions, func(p Permission) bool { return p.Always != nil && p.Path == path })
	if n == 0 && !slices.ContainsFunc(a.unsaved, func(r AlwaysRule) bool { return r.Agent == agent && r.Path == path }) {
		return 0, nil
	}
	removed := rulesOf(agent, ag.Permissions, func(p Permission) bool { return p.Path == path })
	ag.Permissions = kept
	a.config.Agents[agent] = ag
	return n, a.saveRemoval(removed)
}

// saveRemoval saves after rules were taken back, remembering them as unsaved
// when that fails. Caller holds a.mu.
func (a *ACL) saveRemoval(removed []AlwaysRule) error {
	if a.path == "" {
		return nil
	}
	err := a.saveLocked() // clears a.unsaved on success
	if err != nil {
		for _, r := range removed {
			r.Unsaved = true
			a.unsaved = append(a.unsaved, r)
		}
	}
	return err
}

// rulesOf lists the "always" rules in perms that match.
func rulesOf(agent string, perms []Permission, match func(Permission) bool) []AlwaysRule {
	var out []AlwaysRule
	for _, p := range perms {
		if p.Always != nil && match(p) {
			out = append(out, AlwaysRule{Agent: agent, Path: p.Path, AlwaysOrigin: *p.Always})
		}
	}
	return out
}

// ClearAlways takes back every rule that came from one request, whoever holds
// it. Same failure rule as RemoveAlways.
func (a *ACL) ClearAlways(requestID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	fromRequest := func(p Permission) bool { return p.Always != nil && p.Always.RequestID == requestID }
	var removed []AlwaysRule
	for name, ag := range a.config.Agents {
		kept, n := dropRules(ag.Permissions, fromRequest)
		if n > 0 {
			removed = append(removed, rulesOf(name, ag.Permissions, fromRequest)...)
			ag.Permissions = kept
			a.config.Agents[name] = ag
		}
	}
	if len(removed) == 0 {
		return nil
	}
	return a.saveRemoval(removed)
}

// ListAlways lists every "always" rule, by agent and then path, and the ones
// taken back but not yet saved.
func (a *ACL) ListAlways() []AlwaysRule {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := slices.Clone(a.unsaved)
	for name, ag := range a.config.Agents {
		out = append(out, rulesOf(name, ag.Permissions, func(Permission) bool { return true })...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Agent != out[j].Agent {
			return out[i].Agent < out[j].Agent
		}
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].At.Before(out[j].At)
	})
	return out
}

// dropRules returns perms without the ones drop picks, and how many went. The
// result is always a new slice: callers elsewhere hold the old one.
func dropRules(perms []Permission, drop func(Permission) bool) ([]Permission, int) {
	kept := slices.DeleteFunc(slices.Clone(perms), drop)
	return kept, len(perms) - len(kept)
}
