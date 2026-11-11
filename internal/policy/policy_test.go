package policy

import (
	"strings"
	"testing"
)

func TestLoadEmpty(t *testing.T) {
	e, err := Load([]byte(""))
	if err != nil {
		t.Fatalf("Load empty: %v", err)
	}
	if err := e.Evaluate("any/path", &RequestContext{}); err != nil {
		t.Fatalf("empty policy should allow: %v", err)
	}
}

func TestLoadAndEvaluate(t *testing.T) {
	cfg := `{
		"attestation": {
			"openclaw/*": {
				"source_ip": ["192.168.0.115", "192.168.0.117"]
			},
			"sealed/*": {
				"require_sealed": true
			}
		}
	}`
	e, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	tests := []struct {
		name    string
		path    string
		ctx     RequestContext
		wantErr bool
	}{
		{"allowed IP passes", "openclaw/api-key", RequestContext{SourceIP: "192.168.0.115"}, false},
		{"wrong IP denied", "openclaw/api-key", RequestContext{SourceIP: "10.0.0.1"}, true},
		{"no seal key denied", "sealed/key", RequestContext{SourceIP: "10.0.0.1"}, true},
		{"seal key passes", "sealed/key", RequestContext{SealKeyPresented: true}, false},
		{"unmatched path passes (no policy)", "other/secret", RequestContext{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := e.Evaluate(tt.path, &tt.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("Evaluate(%q): err=%v, wantErr=%v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestSourceIPCIDR(t *testing.T) {
	cfg := `{
		"attestation": {
			"infra/*": {
				"source_ip": ["192.168.0.0/24", "10.0.0.5"]
			}
		}
	}`
	e, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	tests := []struct {
		ip      string
		wantErr bool
	}{
		{"192.168.0.50", false},
		{"192.168.0.255", false},
		{"192.168.1.1", true},
		{"10.0.0.5", false},
		{"10.0.0.6", true},
	}

	for _, tt := range tests {
		err := e.Evaluate("infra/key", &RequestContext{SourceIP: tt.ip})
		if (err != nil) != tt.wantErr {
			t.Errorf("IP %s: err=%v, wantErr=%v", tt.ip, err, tt.wantErr)
		}
	}
}

func TestSpecificityMostSpecificWins(t *testing.T) {
	cfg := `{
		"attestation": {
			"*": {
				"source_ip": ["10.0.0.0/8"]
			},
			"openclaw/*": {
				"source_ip": ["192.168.0.115"]
			}
		}
	}`
	e, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// openclaw/* is more specific than *, so only its IP list applies
	if err := e.Evaluate("openclaw/key", &RequestContext{SourceIP: "10.0.0.1"}); err == nil {
		t.Fatal("more specific rule should deny 10.0.0.1")
	}
	if err := e.Evaluate("openclaw/key", &RequestContext{SourceIP: "192.168.0.115"}); err != nil {
		t.Fatalf("more specific rule should allow its IP: %v", err)
	}

	// other paths match only *
	if err := e.Evaluate("other/key", &RequestContext{SourceIP: "10.0.0.1"}); err != nil {
		t.Fatalf("wildcard rule should allow 10.0.0.1: %v", err)
	}
}

func TestRuleFor(t *testing.T) {
	cfg := `{
		"attestation": {
			"openclaw/*": {
				"require_sealed": true,
				"source_ip": ["192.168.0.115"]
			}
		}
	}`
	e, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	rule, pattern := e.RuleFor("openclaw/key")
	if rule == nil {
		t.Fatal("expected rule for openclaw/key")
	}
	if pattern != "openclaw/*" {
		t.Fatalf("pattern = %q, want openclaw/*", pattern)
	}
	if !rule.RequireSealed {
		t.Fatal("expected RequireSealed=true")
	}

	rule, _ = e.RuleFor("other/key")
	if rule != nil {
		t.Fatal("expected no rule for other/key")
	}
}

func TestDeniedError(t *testing.T) {
	err := &DeniedError{Pattern: "openclaw/*", Reason: "test reason"}
	want := `attestation denied by policy "openclaw/*": test reason`
	if err.Error() != want {
		t.Fatalf("Error() = %q, want %q", err.Error(), want)
	}
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		pattern, path string
		want          bool
	}{
		{"*", "anything/here", true},
		{"**", "anything/here/deep", true},
		{"ns/*", "ns/key", true},
		{"ns/*", "ns/deep/key", false},
		{"ns/**", "ns/deep/key", true},
		{"ns/**", "ns/key", true},
		{"ns/key", "ns/key", true},
		{"ns/key", "ns/other", false},
		{"ns/*", "other/key", false},
	}

	for _, tt := range tests {
		if got := matchPath(tt.pattern, tt.path); got != tt.want {
			t.Errorf("matchPath(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
}

func TestLoadFile(t *testing.T) {
	_, err := LoadFile("/nonexistent/policy.json")
	if err == nil {
		t.Fatal("LoadFile should fail for nonexistent file")
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	_, err := Load([]byte("{invalid json"))
	if err == nil {
		t.Fatal("Load should fail for invalid JSON")
	}
}

func TestLoadRejectsUnknownRuleField(t *testing.T) {
	// Typo: "allowed_ips" is not valid inside canonical "attestation" format.
	cfg := `{
		"attestation": {
			"secure/*": {
				"require_sealed": true,
				"allowed_ips": ["192.168.0.0/24"]
			}
		}
	}`
	_, err := Load([]byte(cfg))
	if err == nil {
		t.Fatal("Load should fail for unknown field")
	}
}

func TestNewEngineAllowsAll(t *testing.T) {
	e := NewEngine()
	if err := e.Evaluate("any/path", &RequestContext{SourceIP: "10.0.0.1"}); err != nil {
		t.Fatalf("NewEngine should allow all: %v", err)
	}
}

func TestEqualSpecificityDeterministic(t *testing.T) {
	// secure/* and secure/** have equal specificity (len("secure/") == 7).
	// The lexicographically smaller pattern ("secure/*") must always win
	// regardless of map iteration order.
	cfg := `{
		"attestation": {
			"secure/**": {
				"source_ip": ["10.0.0.1"]
			},
			"secure/*": {
				"source_ip": ["10.0.0.2"]
			}
		}
	}`
	e, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Run many times to catch map iteration nondeterminism
	for i := 0; i < 100; i++ {
		err := e.Evaluate("secure/key", &RequestContext{SourceIP: "10.0.0.1"})
		if err == nil {
			t.Fatalf("iteration %d: expected deny (secure/* should always win), but got allow", i)
		}
	}
}

func TestRulesReturnsCopy(t *testing.T) {
	cfg := `{
		"attestation": {
			"ns/*": {"source_ip": ["10.0.0.1"]}
		}
	}`
	e, _ := Load([]byte(cfg))
	rules := e.Rules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	// Mutating the returned map should not affect the engine
	delete(rules, "ns/*")
	if len(e.Rules()) != 1 {
		t.Fatal("Rules() should return a copy")
	}
}

// --- Sealed response policy tests ---

func TestRequireSealedDeniesWithoutKey(t *testing.T) {
	policyJSON := `{"attestation":{"secure/*":{"require_sealed":true}}}`
	e, err := Load([]byte(policyJSON))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	ctx := &RequestContext{SealKeyPresented: false}
	err = e.Evaluate("secure/api-key", ctx)
	if err == nil {
		t.Fatal("expected denial when require_sealed and no seal key")
	}
	denied, ok := err.(*DeniedError)
	if !ok {
		t.Fatalf("expected DeniedError, got %T", err)
	}
	if !strings.Contains(denied.Reason, "sealed response required") {
		t.Errorf("unexpected reason: %s", denied.Reason)
	}
}

func TestRequireSealedAllowsWithKey(t *testing.T) {
	policyJSON := `{"attestation":{"secure/*":{"require_sealed":true}}}`
	e, err := Load([]byte(policyJSON))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	ctx := &RequestContext{SealKeyPresented: true}
	if err := e.Evaluate("secure/api-key", ctx); err != nil {
		t.Fatalf("expected allow with seal key, got: %v", err)
	}
}

func TestRequireSealedNoEffectOnUnmatchedPaths(t *testing.T) {
	policyJSON := `{"attestation":{"secure/*":{"require_sealed":true}}}`
	e, err := Load([]byte(policyJSON))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Path that doesn't match the policy
	ctx := &RequestContext{SealKeyPresented: false}
	if err := e.Evaluate("open/key", ctx); err != nil {
		t.Fatalf("expected allow for unmatched path, got: %v", err)
	}
}

func TestAllowUnsealParseBackwardCompat(t *testing.T) {
	// allow_unseal should parse without breaking anything
	policyJSON := `{"attestation":{"ns/*":{"allow_unseal":true}}}`
	e, err := Load([]byte(policyJSON))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	rule, _ := e.RuleFor("ns/secret")
	if rule == nil {
		t.Fatal("expected rule for ns/secret")
	}
	if !rule.AllowUnseal {
		t.Error("expected AllowUnseal=true")
	}

	// Should not affect evaluation (allow_unseal is not an access check)
	ctx := &RequestContext{}
	if err := e.Evaluate("ns/secret", ctx); err != nil {
		t.Fatalf("allow_unseal should not deny access: %v", err)
	}
}

func TestNoNewFieldsNoChange(t *testing.T) {
	// Existing policy without any sealed fields should work as before
	policyJSON := `{"attestation":{"ns/*":{"source_ip":["10.0.0.1"]}}}`
	e, err := Load([]byte(policyJSON))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	ctx := &RequestContext{SourceIP: "10.0.0.1"}
	if err := e.Evaluate("ns/key", ctx); err != nil {
		t.Fatalf("expected allow, got: %v", err)
	}

	rule, _ := e.RuleFor("ns/key")
	if rule.RequireSealed {
		t.Error("RequireSealed should default to false")
	}
	if rule.AllowUnseal {
		t.Error("AllowUnseal should default to false")
	}
}

// A policy file that still uses removed rule fields is refused with one line
// per field, not loaded with the rule quietly ignored.
func TestLoadRefusesRemovedFields(t *testing.T) {
	data := `{"attestation": {
		"a/*": {"source_ip": ["10.0.0.1"], "require_mtls": true, "allowed_tools": ["x"]},
		"b/*": {"time_window": "09:00-17:00", "process": {"uid": 1}}
	}}`
	_, err := Load([]byte(data))
	if err == nil {
		t.Fatal("policy with removed fields loaded")
	}
	for _, want := range []string{"attestation.a/*.require_mtls: removed", "attestation.a/*.allowed_tools: removed",
		"attestation.b/*.time_window: removed", "attestation.b/*.process: removed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}
	// The old "rules" list format is refused as a whole, with the move to make.
	if _, err := Load([]byte(`{"rules": [{"path": "x/*", "allowed_ips": ["10.0.0.1"]}]}`)); err == nil ||
		!strings.Contains(err.Error(), "rules: removed") || !strings.Contains(err.Error(), "source_ip") {
		t.Errorf("old rules format: %v", err)
	}
	for _, f := range removedRuleFields {
		if f.Why == "" {
			t.Errorf("%s has no reason", f.Path)
		}
	}
}
