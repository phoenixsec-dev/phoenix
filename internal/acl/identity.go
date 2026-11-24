package acl

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/phoenixsec/phoenix/internal/fsutil"
)

// Labels are the descriptive fields of an identity. The words in them are the
// operator's own: Phoenix has no list of allowed values, and nothing in them
// decides what the identity may do. They are declared by an admin, never
// taken from a caller.
type Labels struct {
	Who       string   `json:"who,omitempty"`       // who uses the identity; empty for a service
	Authority string   `json:"authority,omitempty"` // the role it acts in
	Kind      string   `json:"kind,omitempty"`      // what sort of caller, such as agent, service or person
	Formerly  []string `json:"formerly,omitempty"`  // older identity names, so a log search by name finds their lines too
}

// LabelChange says which labels to set. A nil field is left as it is; an
// empty one is cleared.
type LabelChange struct {
	Who       *string   `json:"who"`
	Authority *string   `json:"authority"`
	Kind      *string   `json:"kind"`
	Formerly  *[]string `json:"formerly"`
}

// Limits on labels, so one identity cannot bloat every audit line.
const (
	maxLabelRunes = 64
	maxFormerly   = 32
	// Former names were identity names, which have no length limit of their
	// own; this one only keeps the ACL file sane.
	maxFormerNameRunes = 256
)

// Empty reports whether the change sets nothing.
func (c LabelChange) Empty() bool {
	return c.Who == nil && c.Authority == nil && c.Kind == nil && c.Formerly == nil
}

// Normalized returns the change with surrounding spaces trimmed, or an error
// saying which value is not usable for the identity called name.
func (c LabelChange) Normalized(name string) (LabelChange, error) {
	var out LabelChange
	var err error
	label := func(field string, v *string) *string {
		if v == nil || err != nil {
			return nil
		}
		s := strings.TrimSpace(*v)
		err = checkLabel(field, s, maxLabelRunes)
		return &s
	}
	out.Who = label("who", c.Who)
	out.Authority = label("authority", c.Authority)
	out.Kind = label("kind", c.Kind)
	if err != nil {
		return LabelChange{}, err
	}
	if c.Formerly == nil {
		return out, nil
	}
	if len(*c.Formerly) > maxFormerly {
		return LabelChange{}, fmt.Errorf("formerly: at most %d names", maxFormerly)
	}
	names := []string{}
	for _, n := range *c.Formerly {
		n = strings.TrimSpace(n)
		if n == "" {
			return LabelChange{}, fmt.Errorf("formerly: empty name")
		}
		if n == name {
			return LabelChange{}, fmt.Errorf("formerly: %q is this identity's own name", n)
		}
		if err := checkLabel("formerly", n, maxFormerNameRunes); err != nil {
			return LabelChange{}, err
		}
		if !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	out.Formerly = &names
	return out, nil
}

// checkLabel refuses text that could disguise itself in a log or on a page:
// control characters, line breaks and invisible formatting characters.
func checkLabel(field, s string, max int) error {
	if utf8.RuneCountInString(s) > max {
		return fmt.Errorf("%s: longer than %d characters", field, max)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) || r == utf8.RuneError {
			return fmt.Errorf("%s: control and invisible characters are not allowed", field)
		}
	}
	return nil
}

// applyTo returns old with the change made. The change must be normalized.
func (c LabelChange) applyTo(old Labels) Labels {
	if c.Who != nil {
		old.Who = *c.Who
	}
	if c.Authority != nil {
		old.Authority = *c.Authority
	}
	if c.Kind != nil {
		old.Kind = *c.Kind
	}
	if c.Formerly != nil {
		old.Formerly = slices.Clone(*c.Formerly)
	}
	return old
}

// SetLabels changes an identity's labels and nothing else: its token, its
// permissions and the sessions made from it carry on. An error means the
// change is not safely saved. The labels in use then match the ACL file: the
// old ones, or the new ones if the file was replaced and only the final sync
// failed.
func (a *ACL) SetLabels(name string, change LabelChange) (Labels, error) {
	change, err := change.Normalized(name)
	if err != nil {
		return Labels{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	agent, ok := a.config.Agents[name]
	if !ok {
		return Labels{}, ErrAgentNotFound
	}
	before := agent.Labels
	agent.Labels = change.applyTo(before)
	a.config.Agents[name] = agent
	if a.path != "" {
		if err := a.saveLocked(); errors.Is(err, fsutil.ErrDirSyncFailed) {
			return Labels{}, err
		} else if err != nil {
			agent = a.config.Agents[name] // keeps the serial the save gave it
			agent.Labels = before
			a.config.Agents[name] = agent
			return Labels{}, err
		}
	}
	return agent.Labels.clone(), nil
}

// clone copies the labels so a caller cannot change the ACL's slice.
func (l Labels) clone() Labels {
	l.Formerly = slices.Clone(l.Formerly)
	return l
}

// Identity is an identity's name and labels, for showing to an admin.
type Identity struct {
	Name string `json:"name"`
	Labels
}

// Identities returns every identity's name and labels, sorted by name.
func (a *ACL) Identities() []Identity {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]Identity, 0, len(a.config.Agents))
	for name, agent := range a.config.Agents {
		out = append(out, Identity{Name: name, Labels: agent.Labels.clone()})
	}
	slices.SortFunc(out, func(x, y Identity) int { return strings.Compare(x.Name, y.Name) })
	return out
}

// FormerNames returns the older names recorded on an identity, or nil.
func (a *ACL) FormerNames(name string) []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return slices.Clone(a.config.Agents[name].Formerly)
}

// fillSerialsLocked gives a serial to every identity that has none (ACL files
// from v0.24.0 and older, or a block written by hand). Two identities with
// the same serial, which a hand-copied block makes, both get a new one, since
// nothing says which is the original. Caller must hold the mutex.
func (a *ACL) fillSerialsLocked() {
	count := make(map[string]int, len(a.config.Agents))
	for _, agent := range a.config.Agents {
		count[agent.Serial]++
	}
	for name, agent := range a.config.Agents {
		if agent.Serial == "" || count[agent.Serial] > 1 {
			agent.Serial = newRandomID()
			a.config.Agents[name] = agent
		}
	}
}
