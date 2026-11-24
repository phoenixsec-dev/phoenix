package acl

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

// AlwaysOrigin marks a rule that came from a human answering an access request
// with "always". It is what lets the dashboard show the rule and take it back.
//
// A staged rule is written before the answer itself is saved. It has no actions,
// so no server, this version or an older one, lets anybody read through it. It
// becomes a real rule once the answer is safely on disk (internal/grant).
type AlwaysOrigin struct {
	RequestID string    `json:"request_id"`
	By        string    `json:"by"`
	At        time.Time `json:"at"`
	Staged    bool      `json:"staged,omitempty"`
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

// StageAlways writes inactive rules for agent on exactly paths, marked with
// origin, replacing any staged ones from the same request. check sees the
// agent's record under the lock. On error nothing usable was left anywhere.
func (a *ACL) StageAlways(agent string, origin AlwaysOrigin, paths []string, check func(Agent) error) error {
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
	origin.Staged = true
	updated := old
	updated.Permissions, _ = dropRules(old.Permissions, stagedFor(origin.RequestID))
	for _, p := range paths {
		o := origin
		updated.Permissions = append(updated.Permissions, Permission{Path: p, Actions: []Action{}, Always: &o})
	}
	a.config.Agents[agent] = updated
	if a.path == "" {
		return nil
	}
	if err := a.saveLocked(); err != nil {
		a.config.Agents[agent] = old // what the file may hold is inactive
		return err
	}
	return nil
}

// FinishAlways turns a request's staged rules into real ones. It counts in
// memory at once. A failed save is returned only to be logged: the file still
// has the staged rules, and the next start finishes them the same way.
func (a *ACL) FinishAlways(agent, requestID string, check func(Agent) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	ag, ok := a.config.Agents[agent]
	if !ok {
		return ErrAgentNotFound
	}
	if err := check(ag); err != nil {
		return err
	}
	staged, changed := stagedFor(requestID), false
	ag.Permissions = slices.Clone(ag.Permissions)
	for i, p := range ag.Permissions {
		if staged(p) {
			o := *p.Always
			o.Staged = false
			ag.Permissions[i] = Permission{Path: p.Path, Actions: []Action{ActionReadValue}, Always: &o}
			changed = true
		}
	}
	if !changed {
		return nil
	}
	a.config.Agents[agent] = ag
	if a.path == "" {
		return nil
	}
	return a.saveLocked()
}

// DropStaged throws away a request's staged rules, whoever holds them.
func (a *ACL) DropStaged(requestID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	changed := false
	for name, ag := range a.config.Agents {
		kept, n := dropRules(ag.Permissions, stagedFor(requestID))
		if n > 0 {
			ag.Permissions = kept
			a.config.Agents[name] = ag
			changed = true
		}
	}
	if !changed || a.path == "" {
		return nil
	}
	return a.saveLocked()
}

// StagedRequests lists the requests that staged rules belong to.
func (a *ACL) StagedRequests() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var ids []string
	for _, ag := range a.config.Agents {
		for _, p := range ag.Permissions {
			if p.Always != nil && p.Always.Staged && !slices.Contains(ids, p.Always.RequestID) {
				ids = append(ids, p.Always.RequestID)
			}
		}
	}
	return ids
}

// HasAlways reports whether an "always" lets agent read exactly path.
func (a *ACL) HasAlways(agent, path string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(rulesOf(agent, a.config.Agents[agent].Permissions, func(p Permission) bool {
		return p.Path == path && hasAction(p.Actions, ActionReadValue)
	})) > 0
}

// stagedFor matches the staged rules of one request.
func stagedFor(requestID string) func(Permission) bool {
	return func(p Permission) bool { return p.Always != nil && p.Always.Staged && p.Always.RequestID == requestID }
}

// RemoveAlways takes back the rule one request put on agent's list for path and
// reports whether there was one. When the save fails the rule is gone from
// memory, so reads are denied at once, but it may return after a restart.
func (a *ACL) RemoveAlways(agent, path, requestID string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ag, ok := a.config.Agents[agent]
	if !ok {
		return false, ErrAgentNotFound
	}
	match := func(p Permission) bool {
		return p.Always != nil && !p.Always.Staged && p.Path == path && p.Always.RequestID == requestID
	}
	kept, n := dropRules(ag.Permissions, match)
	if n == 0 && !slices.ContainsFunc(a.unsaved, func(r AlwaysRule) bool {
		return r.Agent == agent && r.Path == path && r.RequestID == requestID
	}) {
		return false, nil
	}
	removed := rulesOf(agent, ag.Permissions, match)
	ag.Permissions = kept
	a.config.Agents[agent] = ag
	return true, a.saveRemoval(removed)
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

// rulesOf lists the working "always" rules in perms that match.
func rulesOf(agent string, perms []Permission, match func(Permission) bool) []AlwaysRule {
	var out []AlwaysRule
	for _, p := range perms {
		if p.Always != nil && !p.Always.Staged && match(p) {
			out = append(out, AlwaysRule{Agent: agent, Path: p.Path, AlwaysOrigin: *p.Always})
		}
	}
	return out
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
