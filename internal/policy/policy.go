// Package policy implements attestation policy evaluation for Phoenix.
//
// A policy adds checks on top of the ACL for secrets matching a path
// pattern: the caller's source IP (source_ip) and sealed delivery
// (require_sealed, allow_unseal). Everything here is something the server
// can check itself; rules that trusted what the caller said were removed
// (see removed.go).
//
// Policies are keyed by secret path patterns (using the same glob syntax
// as ACL rules) and evaluated after ACL authorization succeeds.
//
// Policy file format (JSON):
//
//	{
//	  "attestation": {
//	    "openclaw/*": {
//	      "source_ip": ["192.168.0.115", "10.0.0.0/24"],
//	      "require_sealed": true
//	    }
//	  }
//	}
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/phoenixsec/phoenix/internal/removed"
)

// Rule defines attestation requirements for secrets matching a path pattern.
type Rule struct {
	AllowedIPs []string `json:"source_ip,omitempty"` // exact IPs or CIDRs

	// Sealed response requirements
	RequireSealed bool `json:"require_sealed,omitempty"` // deny if no valid seal key presented
	AllowUnseal   bool `json:"allow_unseal,omitempty"`   // gate for MCP unseal tool
}

// RequestContext contains attestation evidence extracted from an HTTP request.
type RequestContext struct {
	SourceIP string

	// Seal key validation (set when X-Phoenix-Seal-Key is present and validated)
	SealKeyPresented bool

	// Session identity (set when authenticated via session token)
	SessionID   string
	SessionRole string
}

// Engine loads and evaluates attestation policies.
type Engine struct {
	// rules maps path patterns to their attestation requirements.
	rules map[string]Rule
}

// policyFile is the top-level JSON structure.
type policyFile struct {
	Attestation map[string]Rule `json:"attestation"`
}

// legacyPolicyFile preserves compatibility with early list-style policy files:
// {"rules":[{"path":"secure/*","allowed_ips":["10.0.0.0/24"]}]}
type legacyPolicyFile struct {
	Rules []legacyRule `json:"rules"`
}

type legacyRule struct {
	Path string `json:"path"`

	AllowedIPs    []string `json:"allowed_ips,omitempty"` // legacy name
	SourceIP      []string `json:"source_ip,omitempty"`   // canonical name
	RequireSealed bool     `json:"require_sealed,omitempty"`
	AllowUnseal   bool     `json:"allow_unseal,omitempty"`
}

// NewEngine creates a policy engine with no rules (all requests pass).
func NewEngine() *Engine {
	return &Engine{rules: make(map[string]Rule)}
}

// LoadFile loads attestation policies from a JSON file.
func LoadFile(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}
	return Load(data)
}

// Load parses attestation policies from JSON bytes.
func Load(data []byte) (*Engine, error) {
	// Treat empty/whitespace-only as no rules
	if len(strings.TrimSpace(string(data))) == 0 {
		return NewEngine(), nil
	}

	if err := removed.Error("policy file", removed.Find(data, removedRuleFields)); err != nil {
		return nil, err
	}

	// Parse top-level once so we can support both canonical and legacy formats.
	var top map[string]json.RawMessage
	if err := strictUnmarshal(data, &top); err != nil {
		return nil, fmt.Errorf("parsing policy JSON: %w", err)
	}

	if _, ok := top["attestation"]; ok {
		var pf policyFile
		if err := strictUnmarshal(data, &pf); err != nil {
			return nil, fmt.Errorf("parsing policy JSON: %w", err)
		}
		if pf.Attestation == nil {
			pf.Attestation = make(map[string]Rule)
		}
		return &Engine{rules: pf.Attestation}, nil
	}

	if _, ok := top["rules"]; ok {
		var legacy legacyPolicyFile
		if err := strictUnmarshal(data, &legacy); err != nil {
			return nil, fmt.Errorf("parsing policy JSON: %w", err)
		}
		rules := make(map[string]Rule, len(legacy.Rules))
		for i, r := range legacy.Rules {
			pattern := strings.TrimSpace(r.Path)
			if pattern == "" {
				return nil, fmt.Errorf("parsing policy JSON: rules[%d].path is required", i)
			}
			if _, exists := rules[pattern]; exists {
				return nil, fmt.Errorf("parsing policy JSON: duplicate rule path %q", pattern)
			}

			ips := r.SourceIP
			if len(ips) == 0 {
				ips = r.AllowedIPs
			}
			rules[pattern] = Rule{
				AllowedIPs:    ips,
				RequireSealed: r.RequireSealed,
				AllowUnseal:   r.AllowUnseal,
			}
		}
		return &Engine{rules: rules}, nil
	}

	// "{}" is valid and means no rules.
	if len(top) == 0 {
		return NewEngine(), nil
	}

	return nil, fmt.Errorf(`parsing policy JSON: expected top-level "attestation" object (or legacy "rules" array)`)
}

func strictUnmarshal(data []byte, v interface{}) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("unexpected trailing JSON content")
	}
	return nil
}

// Evaluate checks whether the request context satisfies attestation
// requirements for the given secret path. Returns nil if allowed.
func (e *Engine) Evaluate(secretPath string, ctx *RequestContext) error {
	rule, pattern := e.matchRule(secretPath)
	if rule == nil {
		return nil // no policy = allow
	}

	// Check source_ip
	if len(rule.AllowedIPs) > 0 {
		if !matchIP(ctx.SourceIP, rule.AllowedIPs) {
			return &DeniedError{
				Pattern: pattern,
				Reason:  fmt.Sprintf("source IP %s not in allowed list", ctx.SourceIP),
			}
		}
	}

	// Check sealed response requirement
	if rule.RequireSealed && !ctx.SealKeyPresented {
		return &DeniedError{
			Pattern:        pattern,
			Reason:         "sealed response required but no valid seal key presented",
			SealedRequired: true,
		}
	}

	return nil
}

// containsString checks if a slice contains a string.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// RuleFor returns the attestation rule and pattern matching a secret path,
// or nil if no rule matches.
func (e *Engine) RuleFor(secretPath string) (*Rule, string) {
	return e.matchRule(secretPath)
}

// Rules returns all configured rules (for display/debugging).
func (e *Engine) Rules() map[string]Rule {
	out := make(map[string]Rule, len(e.rules))
	for k, v := range e.rules {
		out[k] = v
	}
	return out
}

// matchRule finds the most specific rule matching the secret path.
// More specific = longer pattern prefix before wildcard.
// Ties are broken lexicographically by pattern to ensure deterministic
// evaluation regardless of map iteration order.
func (e *Engine) matchRule(secretPath string) (*Rule, string) {
	var bestRule *Rule
	var bestPattern string
	bestSpecificity := -1

	for pattern, rule := range e.rules {
		if matchPath(pattern, secretPath) {
			spec := specificity(pattern)
			if spec > bestSpecificity || (spec == bestSpecificity && pattern < bestPattern) {
				r := rule // copy
				bestRule = &r
				bestPattern = pattern
				bestSpecificity = spec
			}
		}
	}
	return bestRule, bestPattern
}

// DeniedError is returned when attestation policy denies a request.
type DeniedError struct {
	Pattern string
	Reason  string
	// SealedRequired is true when the only unmet requirement is require_sealed,
	// so the API can tell the caller to use sealed delivery (phoenix exec).
	SealedRequired bool
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("attestation denied by policy %q: %s", e.Pattern, e.Reason)
}

// matchPath checks whether a secret path matches a glob pattern.
// Supports: "*" (match all), "ns/*" (single level), "ns/**" (recursive),
// and exact match.
func matchPath(pattern, path string) bool {
	if pattern == "*" || pattern == "**" {
		return true
	}
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return strings.HasPrefix(path, prefix+"/") || path == prefix
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		if !strings.HasPrefix(path, prefix+"/") {
			return false
		}
		rest := strings.TrimPrefix(path, prefix+"/")
		return !strings.Contains(rest, "/")
	}
	return pattern == path
}

// specificity returns a score for pattern matching priority.
// Longer literal prefixes = more specific.
func specificity(pattern string) int {
	pattern = strings.TrimSuffix(pattern, "/**")
	pattern = strings.TrimSuffix(pattern, "/*")
	pattern = strings.TrimSuffix(pattern, "*")
	return len(pattern)
}

// matchIP checks if the source IP is in the allowed list.
// Supports both individual IPs and CIDR notation.
func matchIP(sourceIP string, allowed []string) bool {
	ip := net.ParseIP(sourceIP)
	if ip == nil {
		return false
	}
	for _, entry := range allowed {
		if strings.Contains(entry, "/") {
			_, cidr, err := net.ParseCIDR(entry)
			if err == nil && cidr.Contains(ip) {
				return true
			}
		} else {
			if net.ParseIP(entry) != nil && entry == sourceIP {
				return true
			}
		}
	}
	return false
}
