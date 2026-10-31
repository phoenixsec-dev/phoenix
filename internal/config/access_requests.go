package config

import (
	"errors"
	"fmt"
	"os"
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
//
// The result is canonical: absolute, with the directory's symlinks and ".."
// resolved the way the kernel resolves them. The server opens exactly this
// path and ValidateGrantStorePath checks exactly this path, so a spelling
// like "link/../x" cannot make the two disagree about which file it is.
func (c *Config) GrantStorePath() string {
	if c.AccessRequests != nil && c.AccessRequests.StorePath != "" {
		return parentResolved(c.AccessRequests.StorePath)
	}
	// rawDir, not filepath.Dir: Dir would clean "link/.." away before the
	// symlink is followed.
	return parentResolved(rawDir(c.ACL.Path) + "/" + grantsFileName)
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

	return nil
}

// ValidateGrantStorePath checks that the EFFECTIVE grants file (store_path,
// or the default grants.json next to the ACL file) and its temp files are
// not the same file as another Phoenix file or one of its temp files. It
// runs whether or not the access_requests block exists, because the server
// always opens the grant store; without it an install whose secrets file or
// ACL happens to be grants.json would have it overwritten or quarantined.
// Paths are compared absolute and with symlinks resolved, so "data/x" vs
// "/srv/data/x" or a symlinked directory cannot slip past. It only reads
// the filesystem.
func (c *Config) ValidateGrantStorePath() error {
	grants := c.GrantStorePath()
	// The grants file itself must not be a symlink: its target could be a
	// protected file's temp name, which no comparison of names would catch.
	if fi, err := os.Lstat(grants); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("access_requests: the grants file %q is a symlink; "+
			"set access_requests.store_path to a regular file path", grants)
	}
	protected := []struct{ field, path string }{
		{"acl.path", c.ACL.Path},
		{"audit.path", c.Audit.Path},
		{"store.path", c.Store.Path},
		{"store.master_key", c.Store.MasterKey},
		{"policy.path", c.Policy.Path},
		{"auth.mtls.crl_path", c.Auth.MTLS.CRLPath},
	}
	for _, pr := range protected {
		if pr.path == "" {
			continue
		}
		// Two names per file: where it really lives (link target), and the
		// configured name in its resolved directory. Writers derive their
		// temp names ("<name>.tmp", "<name>.tmp-<random>") from the
		// configured name, so a symlinked file's temp sits next to the link.
		for _, p := range []string{fullyResolved(pr.path), parentResolved(pr.path)} {
			if grants == p || strings.HasPrefix(grants, p+".tmp") || strings.HasPrefix(p, grants+".tmp") || sameFile(grants, p) {
				return fmt.Errorf("access_requests: the grants file %q is the same file as %s %q (or one of its temp files); "+
					"set access_requests.store_path to a separate file such as %q",
					grants, pr.field, pr.path, filepath.Join(filepath.Dir(p), "phoenix-grants.json"))
			}
		}
	}
	return nil
}

// rawAbs makes p absolute WITHOUT cleaning it, so ".." after a symlink is
// still there for EvalSymlinks to resolve after following the link.
func rawAbs(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	wd, err := os.Getwd()
	if err != nil {
		return p
	}
	return wd + string(filepath.Separator) + p
}

// rawDir is the directory part of p as written (everything before the last
// separator), without cleaning.
func rawDir(p string) string {
	p = rawAbs(p)
	i := strings.LastIndex(p, string(filepath.Separator))
	if i <= 0 {
		return string(filepath.Separator)
	}
	return p[:i]
}

// parentResolved returns p with its directory resolved (symlinks and "..",
// kernel order) and the final name kept as written. When the directory does
// not exist yet it falls back to the cleaned absolute path.
//
// It never calls fullyResolved, so the two helpers cannot loop.
func parentResolved(p string) string {
	base := filepath.Base(p)
	if base == "." || base == ".." || base == string(filepath.Separator) ||
		strings.HasSuffix(p, string(filepath.Separator)) {
		// No plain final name to keep: resolve the whole path if it exists,
		// else fall back to the cleaned absolute path.
		if real, err := filepath.EvalSymlinks(rawAbs(p)); err == nil {
			if abs, err := filepath.Abs(real); err == nil {
				return abs
			}
		}
		return filepath.Clean(rawAbs(p))
	}
	if dir, err := filepath.EvalSymlinks(rawDir(p)); err == nil {
		if abs, err := filepath.Abs(dir); err == nil {
			return filepath.Join(abs, base)
		}
	}
	return filepath.Clean(rawAbs(p))
}

// fullyResolved returns the file p really names (final symlink followed
// too). When p does not exist it falls back to parentResolved.
func fullyResolved(p string) string {
	if real, err := filepath.EvalSymlinks(rawAbs(p)); err == nil {
		if abs, err := filepath.Abs(real); err == nil {
			return abs
		}
	}
	return parentResolved(p)
}

// sameFile catches hard links and bind mounts that path comparison misses.
func sameFile(a, b string) bool {
	ia, err := os.Stat(a)
	if err != nil {
		return false
	}
	ib, err := os.Stat(b)
	return err == nil && os.SameFile(ia, ib)
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
	// Strip at most ONE supported suffix; any wildcard left is an error
	// ("infra/*/**" would otherwise pass but match nothing at runtime).
	base := p
	if b, ok := strings.CutSuffix(p, "/**"); ok {
		base = b
	} else if b, ok := strings.CutSuffix(p, "/*"); ok {
		base = b
	}
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
