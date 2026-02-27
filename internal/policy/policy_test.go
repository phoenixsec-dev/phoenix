package policy

import (
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
				"require_mtls": true,
				"source_ip": ["192.168.0.115", "192.168.0.117"],
				"deny_bearer": true
			},
			"monitoring/*": {
				"require_mtls": true,
				"deny_bearer": false
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
		{
			name: "mTLS from allowed IP passes",
			path: "openclaw/api-key",
			ctx: RequestContext{
				UsedMTLS: true,
				SourceIP: "192.168.0.115",
			},
			wantErr: false,
		},
		{
			name: "bearer denied for openclaw",
			path: "openclaw/api-key",
			ctx: RequestContext{
				UsedBearer: true,
				SourceIP:   "192.168.0.115",
			},
			wantErr: true,
		},
		{
			name: "wrong IP denied",
			path: "openclaw/api-key",
			ctx: RequestContext{
				UsedMTLS: true,
				SourceIP: "10.0.0.1",
			},
			wantErr: true,
		},
		{
			name: "no mTLS denied",
			path: "openclaw/api-key",
			ctx: RequestContext{
				SourceIP: "192.168.0.115",
			},
			wantErr: true,
		},
		{
			name: "monitoring allows bearer with mTLS",
			path: "monitoring/grafana-admin",
			ctx: RequestContext{
				UsedMTLS:   true,
				UsedBearer: true,
				SourceIP:   "192.168.0.107",
			},
			wantErr: false,
		},
		{
			name: "unmatched path passes (no policy)",
			path: "other/secret",
			ctx:  RequestContext{},
			wantErr: false,
		},
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

func TestCertFingerprintPinning(t *testing.T) {
	cfg := `{
		"attestation": {
			"secure/*": {
				"require_mtls": true,
				"cert_fingerprint": "sha256:abcdef1234567890"
			}
		}
	}`
	e, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Correct fingerprint
	err = e.Evaluate("secure/key", &RequestContext{
		UsedMTLS:        true,
		CertFingerprint: "sha256:abcdef1234567890",
	})
	if err != nil {
		t.Fatalf("correct fingerprint should pass: %v", err)
	}

	// Wrong fingerprint
	err = e.Evaluate("secure/key", &RequestContext{
		UsedMTLS:        true,
		CertFingerprint: "sha256:wrong",
	})
	if err == nil {
		t.Fatal("wrong fingerprint should fail")
	}

	// No fingerprint
	err = e.Evaluate("secure/key", &RequestContext{
		UsedMTLS: true,
	})
	if err == nil {
		t.Fatal("missing fingerprint should fail")
	}
}

func TestCertFingerprintCaseInsensitive(t *testing.T) {
	cfg := `{
		"attestation": {
			"secure/*": {
				"cert_fingerprint": "sha256:ABCDEF"
			}
		}
	}`
	e, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	err = e.Evaluate("secure/key", &RequestContext{
		CertFingerprint: "sha256:abcdef",
	})
	if err != nil {
		t.Fatalf("case-insensitive match should pass: %v", err)
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
				"deny_bearer": false
			},
			"openclaw/*": {
				"deny_bearer": true
			}
		}
	}`
	e, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// openclaw/* is more specific than *, so deny_bearer should be true
	err = e.Evaluate("openclaw/key", &RequestContext{UsedBearer: true})
	if err == nil {
		t.Fatal("more specific rule should deny bearer")
	}

	// other paths match only *, which allows bearer
	err = e.Evaluate("other/key", &RequestContext{UsedBearer: true})
	if err != nil {
		t.Fatalf("wildcard rule should allow bearer: %v", err)
	}
}

func TestRuleFor(t *testing.T) {
	cfg := `{
		"attestation": {
			"openclaw/*": {
				"require_mtls": true,
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
	if !rule.RequireMTLS {
		t.Fatal("expected RequireMTLS=true")
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

func TestNewEngineAllowsAll(t *testing.T) {
	e := NewEngine()
	if err := e.Evaluate("any/path", &RequestContext{UsedBearer: true}); err != nil {
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
				"deny_bearer": false
			},
			"secure/*": {
				"deny_bearer": true
			}
		}
	}`
	e, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Run many times to catch map iteration nondeterminism
	for i := 0; i < 100; i++ {
		err := e.Evaluate("secure/key", &RequestContext{UsedBearer: true})
		if err == nil {
			t.Fatalf("iteration %d: expected deny (secure/* should always win), but got allow", i)
		}
	}
}

func TestRulesReturnsCopy(t *testing.T) {
	cfg := `{
		"attestation": {
			"ns/*": {"require_mtls": true}
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
