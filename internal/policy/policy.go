// Package policy implements attestation policy evaluation for Phoenix.
//
// Attestation policies bind secrets to specific identity evidence beyond
// basic ACL checks. They enforce requirements like mTLS authentication,
// source IP restrictions, and certificate fingerprint pinning.
//
// Policies are keyed by secret path patterns (using the same glob syntax
// as ACL rules) and evaluated after ACL authorization succeeds.
//
// Policy file format (JSON):
//
//	{
//	  "attestation": {
//	    "openclaw/*": {
//	      "require_mtls": true,
//	      "source_ip": ["192.168.0.115"],
//	      "cert_fingerprint": "sha256:abc123",
//	      "deny_bearer": true
//	    }
//	  }
//	}
package policy

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// Rule defines attestation requirements for secrets matching a path pattern.
type Rule struct {
	RequireMTLS     bool     `json:"require_mtls"`
	AllowedIPs      []string `json:"source_ip,omitempty"`
	CertFingerprint string   `json:"cert_fingerprint,omitempty"`
	DenyBearer      bool     `json:"deny_bearer"`
}

// RequestContext contains attestation evidence extracted from an HTTP request.
type RequestContext struct {
	UsedMTLS        bool
	UsedBearer      bool
	SourceIP        string
	CertFingerprint string // "sha256:<hex>"
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
	var pf policyFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parsing policy JSON: %w", err)
	}
	if pf.Attestation == nil {
		pf.Attestation = make(map[string]Rule)
	}
	return &Engine{rules: pf.Attestation}, nil
}

// Evaluate checks whether the request context satisfies attestation
// requirements for the given secret path. Returns nil if allowed.
func (e *Engine) Evaluate(secretPath string, ctx *RequestContext) error {
	rule, pattern := e.matchRule(secretPath)
	if rule == nil {
		return nil // no policy = allow
	}

	// Check deny_bearer first
	if rule.DenyBearer && ctx.UsedBearer {
		return &DeniedError{
			Pattern: pattern,
			Reason:  "bearer token authentication not allowed; mTLS required",
		}
	}

	// Check require_mtls
	if rule.RequireMTLS && !ctx.UsedMTLS {
		return &DeniedError{
			Pattern: pattern,
			Reason:  "mTLS client certificate required",
		}
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

	// Check cert_fingerprint
	if rule.CertFingerprint != "" {
		if ctx.CertFingerprint == "" {
			return &DeniedError{
				Pattern: pattern,
				Reason:  "certificate fingerprint required but no client certificate presented",
			}
		}
		if !strings.EqualFold(ctx.CertFingerprint, rule.CertFingerprint) {
			return &DeniedError{
				Pattern: pattern,
				Reason:  fmt.Sprintf("certificate fingerprint mismatch: got %s", ctx.CertFingerprint),
			}
		}
	}

	return nil
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
