package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// AccessRequestsConfig is the "access_requests" block: agents may ask a
// human for temporary use of exact secret paths (request-use grants).
// See docs/access-requests.md. Durations are strings like "15m".
type AccessRequestsConfig struct {
	Enabled          bool     `json:"enabled"`
	RequestTTL       string   `json:"request_ttl,omitempty"`       // how long a request waits for a human (default 15m)
	DefaultGrantTTL  string   `json:"default_grant_ttl,omitempty"` // grant length when the agent does not ask (default 1h)
	MaxGrantTTL      string   `json:"max_grant_ttl,omitempty"`     // ceiling for any grant (default 8h, at most 24h)
	GrantableActions []string `json:"grantable_actions,omitempty"` // must be ["read_value"] in this version
	// RequireSealed and BindSourceIP default to true when left out, so they
	// are pointers: a missing value and an explicit false must differ.
	RequireSealed      *bool    `json:"require_sealed,omitempty"`
	BindSourceIP       *bool    `json:"bind_source_ip,omitempty"`
	Approvers          []string `json:"approvers"`  // ACL agent names allowed to approve over the API; empty = dashboard only
	DenyPaths          []string `json:"deny_paths"` // globs that can never be requested, e.g. "phoenix/**"
	NotifyURL          string   `json:"notify_url,omitempty"`
	NotifyTokenRef     string   `json:"notify_token_ref,omitempty"`
	NotifyIncludePaths bool     `json:"notify_include_paths,omitempty"`
	StorePath          string   `json:"store_path,omitempty"` // empty = grants.json next to the ACL file
}

// AccessRequestsSettings is the parsed, defaulted form of the block that the
// server uses at runtime. A config without the block gives Enabled=false.
type AccessRequestsSettings struct {
	Enabled          bool
	RequestTTL       time.Duration
	DefaultGrantTTL  time.Duration
	MaxGrantTTL      time.Duration
	GrantableActions []string
	RequireSealed    bool
	BindSourceIP     bool
	Approvers        []string
	DenyPaths        []string
	StorePath        string
}

// Access-request defaults and limits (plan section 6).
const (
	DefaultAccessRequestTTL  = 15 * time.Minute
	DefaultAccessGrantTTL    = time.Hour
	DefaultAccessMaxGrantTTL = 8 * time.Hour
	maxAccessGrantTTLLimit   = 24 * time.Hour
	minAccessTTL             = time.Minute
	grantsFileName           = "grants.json"
)

// grantableNow is the only grantable action in this version.
var grantableNow = []string{"read_value"}

// NewInstallAccessRequests is the block written for new installs (--init and
// config.example.json): the feature is on with all defaults. Existing configs
// without the block stay off.
func NewInstallAccessRequests() *AccessRequestsConfig {
	t := true
	return &AccessRequestsConfig{
		Enabled:          true,
		RequestTTL:       "15m",
		DefaultGrantTTL:  "1h",
		MaxGrantTTL:      "8h",
		GrantableActions: []string{"read_value"},
		RequireSealed:    &t,
		BindSourceIP:     &t,
		Approvers:        []string{},
		DenyPaths:        []string{},
	}
}

// AccessRequestsSettings returns the parsed settings. Call Validate first;
// invalid durations here fall back to defaults.
func (c *Config) AccessRequestsSettings() AccessRequestsSettings {
	s := AccessRequestsSettings{
		RequestTTL:       DefaultAccessRequestTTL,
		DefaultGrantTTL:  DefaultAccessGrantTTL,
		MaxGrantTTL:      DefaultAccessMaxGrantTTL,
		GrantableActions: append([]string(nil), grantableNow...),
		RequireSealed:    true,
		BindSourceIP:     true,
		StorePath:        c.GrantStorePath(),
	}
	ar := c.AccessRequests
	if ar == nil {
		return s
	}
	s.Enabled = ar.Enabled
	s.RequestTTL = durationOr(ar.RequestTTL, s.RequestTTL)
	s.DefaultGrantTTL = durationOr(ar.DefaultGrantTTL, s.DefaultGrantTTL)
	s.MaxGrantTTL = durationOr(ar.MaxGrantTTL, s.MaxGrantTTL)
	if ar.RequireSealed != nil {
		s.RequireSealed = *ar.RequireSealed
	}
	if ar.BindSourceIP != nil {
		s.BindSourceIP = *ar.BindSourceIP
	}
	s.Approvers = append([]string(nil), ar.Approvers...)
	s.DenyPaths = append([]string(nil), ar.DenyPaths...)
	return s
}

// GrantStorePath is where grants.json lives: access_requests.store_path, or
// grants.json in the same directory as the ACL file.
func (c *Config) GrantStorePath() string {
	if c.AccessRequests != nil && c.AccessRequests.StorePath != "" {
		return c.AccessRequests.StorePath
	}
	return filepath.Join(filepath.Dir(c.ACL.Path), grantsFileName)
}

func durationOr(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return d
}

// validateAccessRequests applies the load-time rules from plan section 6.
// A missing block is valid (feature off). Rules are checked even when
// enabled is false, so a block that is switched on later cannot be broken.
func (c *Config) validateAccessRequests() error {
	ar := c.AccessRequests
	if ar == nil {
		return nil
	}
	parse := func(field, v string, def time.Duration) (time.Duration, error) {
		if v == "" {
			return def, nil
		}
		d, err := time.ParseDuration(v)
		if err != nil {
			return 0, fmt.Errorf("access_requests.%s: invalid duration %q: %w", field, v, err)
		}
		return d, nil
	}
	reqTTL, err := parse("request_ttl", ar.RequestTTL, DefaultAccessRequestTTL)
	if err != nil {
		return err
	}
	defTTL, err := parse("default_grant_ttl", ar.DefaultGrantTTL, DefaultAccessGrantTTL)
	if err != nil {
		return err
	}
	maxTTL, err := parse("max_grant_ttl", ar.MaxGrantTTL, DefaultAccessMaxGrantTTL)
	if err != nil {
		return err
	}
	if reqTTL < minAccessTTL {
		return errors.New("access_requests.request_ttl must be at least 1m")
	}
	if defTTL < minAccessTTL || defTTL > maxTTL || maxTTL > maxAccessGrantTTLLimit {
		return errors.New("access_requests: need 1m <= default_grant_ttl <= max_grant_ttl <= 24h")
	}

	if len(ar.GrantableActions) > 0 {
		for _, a := range ar.GrantableActions {
			switch a {
			case "read_value":
			case "write":
				return errors.New("access_requests.grantable_actions: write grants are not supported yet; use [\"read_value\"]")
			case "list", "delete", "admin", "read":
				return fmt.Errorf("access_requests.grantable_actions: %q can never be granted; use [\"read_value\"]", a)
			default:
				return fmt.Errorf("access_requests.grantable_actions: unknown action %q; use [\"read_value\"]", a)
			}
		}
		if len(ar.GrantableActions) != 1 {
			return errors.New("access_requests.grantable_actions must be exactly [\"read_value\"]")
		}
	}

	for _, p := range ar.DenyPaths {
		if err := ValidatePathGlob(p); err != nil {
			return fmt.Errorf("access_requests.deny_paths: %w", err)
		}
	}
	for _, name := range ar.Approvers {
		if strings.TrimSpace(name) == "" {
			return errors.New("access_requests.approvers: empty agent name")
		}
	}

	// The grants file must never overwrite another Phoenix file.
	grants := filepath.Clean(c.GrantStorePath())
	protected := map[string]string{
		"acl.path":         c.ACL.Path,
		"audit.path":       c.Audit.Path,
		"store.path":       c.Store.Path,
		"store.master_key": c.Store.MasterKey,
		"policy.path":      c.Policy.Path,
	}
	for field, p := range protected {
		if p == "" {
			continue
		}
		p = filepath.Clean(p)
		if grants == p || strings.HasPrefix(grants, p+".tmp") || strings.HasPrefix(p, grants+".tmp") {
			return fmt.Errorf("access_requests.store_path %q collides with %s (or its temp file)", grants, field)
		}
	}
	return nil
}

// ValidatePathGlob checks a path pattern in the ACL / session namespace
// syntax: "*", "**", "prefix/*", "prefix/**", or an exact path. Wildcards
// anywhere else are rejected.
func ValidatePathGlob(p string) error {
	if strings.TrimSpace(p) == "" {
		return errors.New("empty pattern")
	}
	if p == "*" || p == "**" {
		return nil
	}
	base := strings.TrimSuffix(strings.TrimSuffix(p, "/**"), "/*")
	if base == "" || strings.HasPrefix(base, "/") || strings.ContainsAny(base, "*?[]{}") {
		return fmt.Errorf("invalid pattern %q (use an exact path, prefix/*, prefix/** or *)", p)
	}
	for _, r := range base {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("invalid pattern %q: control character", p)
		}
	}
	return nil
}
