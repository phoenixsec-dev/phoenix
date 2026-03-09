package policy

import (
	"strings"
	"testing"
	"time"
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
			name:    "unmatched path passes (no policy)",
			path:    "other/secret",
			ctx:     RequestContext{},
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

func TestLoadLegacyRulesFormat(t *testing.T) {
	cfg := `{
		"rules": [
			{
				"path": "secure/*",
				"require_mtls": true,
				"allowed_ips": ["192.168.0.0/24"]
			}
		]
	}`
	e, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load legacy format: %v", err)
	}
	rule, pattern := e.RuleFor("secure/db")
	if rule == nil || pattern != "secure/*" {
		t.Fatalf("expected secure/* match, got rule=%v pattern=%q", rule, pattern)
	}
	if !rule.RequireMTLS {
		t.Fatal("expected require_mtls=true")
	}
	if len(rule.AllowedIPs) != 1 || rule.AllowedIPs[0] != "192.168.0.0/24" {
		t.Fatalf("expected allowed IP copied from allowed_ips, got %v", rule.AllowedIPs)
	}
}

func TestLoadRejectsUnknownRuleField(t *testing.T) {
	// Typo: "allowed_ips" is not valid inside canonical "attestation" format.
	cfg := `{
		"attestation": {
			"secure/*": {
				"require_mtls": true,
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

// --- Wave 2: Tool-scoped policy tests ---

func TestToolScopedAllowedTools(t *testing.T) {
	cfg := `{
		"attestation": {
			"api/*": {
				"allowed_tools": ["git-sync", "api-call"]
			}
		}
	}`
	e, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	tests := []struct {
		name    string
		tool    string
		wantErr bool
	}{
		{"allowed tool passes", "git-sync", false},
		{"another allowed tool passes", "api-call", false},
		{"denied tool fails", "shell", true},
		{"empty tool fails", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := e.Evaluate("api/key", &RequestContext{Tool: tt.tool})
			if (err != nil) != tt.wantErr {
				t.Errorf("tool=%q: err=%v, wantErr=%v", tt.tool, err, tt.wantErr)
			}
		})
	}
}

func TestToolScopedDenyTools(t *testing.T) {
	cfg := `{
		"attestation": {
			"secure/*": {
				"deny_tools": ["shell", "file-write"]
			}
		}
	}`
	e, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Denied tool should fail
	err = e.Evaluate("secure/key", &RequestContext{Tool: "shell"})
	if err == nil {
		t.Fatal("denied tool should fail")
	}

	// Non-denied tool should pass
	err = e.Evaluate("secure/key", &RequestContext{Tool: "api-call"})
	if err != nil {
		t.Fatalf("non-denied tool should pass: %v", err)
	}

	// Empty tool should pass (deny_tools only applies when tool is set)
	err = e.Evaluate("secure/key", &RequestContext{})
	if err != nil {
		t.Fatalf("empty tool should pass with deny_tools: %v", err)
	}
}

// --- Wave 2: Time-window policy tests ---

func TestTimeWindowNormalRange(t *testing.T) {
	cfg := `{
		"attestation": {
			"prod/*": {
				"time_window": "06:00-23:00"
			}
		}
	}`
	e, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// 14:00 is within range
	at14 := time.Date(2026, 2, 27, 14, 0, 0, 0, time.UTC)
	if err := e.Evaluate("prod/key", &RequestContext{EvalTime: at14}); err != nil {
		t.Fatalf("14:00 should be within 06:00-23:00: %v", err)
	}

	// 03:00 is outside range
	at03 := time.Date(2026, 2, 27, 3, 0, 0, 0, time.UTC)
	if err := e.Evaluate("prod/key", &RequestContext{EvalTime: at03}); err == nil {
		t.Fatal("03:00 should be outside 06:00-23:00")
	}

	// 06:00 is at boundary (inclusive start)
	at06 := time.Date(2026, 2, 27, 6, 0, 0, 0, time.UTC)
	if err := e.Evaluate("prod/key", &RequestContext{EvalTime: at06}); err != nil {
		t.Fatalf("06:00 should be within window (inclusive start): %v", err)
	}

	// 23:00 is at boundary (exclusive end)
	at23 := time.Date(2026, 2, 27, 23, 0, 0, 0, time.UTC)
	if err := e.Evaluate("prod/key", &RequestContext{EvalTime: at23}); err == nil {
		t.Fatal("23:00 should be at boundary (exclusive end)")
	}
}

func TestTimeWindowMidnightCrossover(t *testing.T) {
	cfg := `{
		"attestation": {
			"night/*": {
				"time_window": "22:00-06:00"
			}
		}
	}`
	e, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// 23:00 is within range (after start)
	at23 := time.Date(2026, 2, 27, 23, 0, 0, 0, time.UTC)
	if err := e.Evaluate("night/key", &RequestContext{EvalTime: at23}); err != nil {
		t.Fatalf("23:00 should be within 22:00-06:00: %v", err)
	}

	// 03:00 is within range (before end)
	at03 := time.Date(2026, 2, 27, 3, 0, 0, 0, time.UTC)
	if err := e.Evaluate("night/key", &RequestContext{EvalTime: at03}); err != nil {
		t.Fatalf("03:00 should be within 22:00-06:00: %v", err)
	}

	// 12:00 is outside range
	at12 := time.Date(2026, 2, 27, 12, 0, 0, 0, time.UTC)
	if err := e.Evaluate("night/key", &RequestContext{EvalTime: at12}); err == nil {
		t.Fatal("12:00 should be outside 22:00-06:00")
	}
}

func TestTimeWindowWithTimezone(t *testing.T) {
	cfg := `{
		"attestation": {
			"prod/*": {
				"time_window": "09:00-17:00",
				"time_zone": "America/New_York"
			}
		}
	}`
	e, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// 14:00 EST = within window
	ny, _ := time.LoadLocation("America/New_York")
	at14NY := time.Date(2026, 2, 27, 14, 0, 0, 0, ny)
	if err := e.Evaluate("prod/key", &RequestContext{EvalTime: at14NY}); err != nil {
		t.Fatalf("14:00 NY should be within 09:00-17:00 NY: %v", err)
	}

	// 14:00 UTC = 09:00 EST = within window
	at14UTC := time.Date(2026, 2, 27, 14, 0, 0, 0, time.UTC)
	if err := e.Evaluate("prod/key", &RequestContext{EvalTime: at14UTC}); err != nil {
		t.Fatalf("14:00 UTC (09:00 EST) should be within window: %v", err)
	}
}

func TestTimeWindowInvalidFormat(t *testing.T) {
	cfg := `{
		"attestation": {
			"bad/*": {
				"time_window": "not-a-time"
			}
		}
	}`
	e, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if err := e.Evaluate("bad/key", &RequestContext{
		EvalTime: time.Date(2026, 2, 27, 12, 0, 0, 0, time.UTC),
	}); err == nil {
		t.Fatal("invalid time_window should fail")
	}
}

// --- Wave 2: Process attestation tests ---

func TestProcessAttestation(t *testing.T) {
	uid := 1001
	cfg := `{
		"attestation": {
			"prod/*": {
				"process": {
					"uid": 1001,
					"binary_hash": "sha256:ABC123"
				}
			}
		}
	}`
	e, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Correct process context passes
	err = e.Evaluate("prod/key", &RequestContext{
		Process: &ProcessContext{
			UID:        uid,
			BinaryHash: "sha256:abc123",
		},
	})
	if err != nil {
		t.Fatalf("correct process context should pass: %v", err)
	}

	// No process context fails
	err = e.Evaluate("prod/key", &RequestContext{})
	if err == nil {
		t.Fatal("missing process context should fail")
	}

	// Wrong UID fails
	err = e.Evaluate("prod/key", &RequestContext{
		Process: &ProcessContext{
			UID:        9999,
			BinaryHash: "sha256:abc123",
		},
	})
	if err == nil {
		t.Fatal("wrong UID should fail")
	}

	// Wrong hash fails
	err = e.Evaluate("prod/key", &RequestContext{
		Process: &ProcessContext{
			UID:        uid,
			BinaryHash: "sha256:wrong",
		},
	})
	if err == nil {
		t.Fatal("wrong hash should fail")
	}
}

func TestProcessAttestationUIDOnly(t *testing.T) {
	cfg := `{
		"attestation": {
			"dev/*": {
				"process": {
					"uid": 1000
				}
			}
		}
	}`
	e, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Correct UID without hash passes
	err = e.Evaluate("dev/key", &RequestContext{
		Process: &ProcessContext{UID: 1000},
	})
	if err != nil {
		t.Fatalf("correct UID should pass: %v", err)
	}
}

// --- Wave 2: Nonce requirement tests ---

func TestNonceRequirement(t *testing.T) {
	cfg := `{
		"attestation": {
			"secure/*": {
				"require_nonce": true
			}
		}
	}`
	e, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Without nonce validation, fails
	err = e.Evaluate("secure/key", &RequestContext{})
	if err == nil {
		t.Fatal("missing nonce should fail")
	}

	// With nonce validation, passes
	err = e.Evaluate("secure/key", &RequestContext{NonceValidated: true})
	if err != nil {
		t.Fatalf("validated nonce should pass: %v", err)
	}
}

// --- Wave 2: Credential freshness tests ---

func TestCredentialFreshness(t *testing.T) {
	cfg := `{
		"attestation": {
			"prod/*": {
				"credential_ttl": "15m",
				"require_fresh_attestation": true
			}
		}
	}`
	e, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	now := time.Now()

	// Fresh token passes
	fresh := now.Add(-5 * time.Minute)
	err = e.Evaluate("prod/key", &RequestContext{
		TokenIssuedAt: &fresh,
		EvalTime:      now,
	})
	if err != nil {
		t.Fatalf("fresh token should pass: %v", err)
	}

	// Expired token fails
	old := now.Add(-20 * time.Minute)
	err = e.Evaluate("prod/key", &RequestContext{
		TokenIssuedAt: &old,
		EvalTime:      now,
	})
	if err == nil {
		t.Fatal("expired token should fail")
	}

	// No token timestamp fails
	err = e.Evaluate("prod/key", &RequestContext{
		EvalTime: now,
	})
	if err == nil {
		t.Fatal("missing token timestamp should fail")
	}
}

func TestCredentialFreshnessDefaultTTL(t *testing.T) {
	cfg := `{
		"attestation": {
			"prod/*": {
				"require_fresh_attestation": true
			}
		}
	}`
	e, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	now := time.Now()

	// Within default 15m TTL
	fresh := now.Add(-10 * time.Minute)
	err = e.Evaluate("prod/key", &RequestContext{
		TokenIssuedAt: &fresh,
		EvalTime:      now,
	})
	if err != nil {
		t.Fatalf("within default TTL should pass: %v", err)
	}

	// Outside default 15m TTL
	old := now.Add(-20 * time.Minute)
	err = e.Evaluate("prod/key", &RequestContext{
		TokenIssuedAt: &old,
		EvalTime:      now,
	})
	if err == nil {
		t.Fatal("outside default TTL should fail")
	}
}

func TestCredentialFreshnessFutureDated(t *testing.T) {
	cfg := `{
		"attestation": {
			"prod/*": {
				"require_fresh_attestation": true,
				"credential_ttl": "15m"
			}
		}
	}`
	e, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	now := time.Now()

	// Token issued 5 minutes in the future should be rejected
	future := now.Add(5 * time.Minute)
	err = e.Evaluate("prod/key", &RequestContext{
		TokenIssuedAt: &future,
		EvalTime:      now,
	})
	if err == nil {
		t.Fatal("future-dated token should be rejected")
	}

	// Token issued just 10 seconds in the future should be allowed (within 30s skew tolerance)
	slightFuture := now.Add(10 * time.Second)
	err = e.Evaluate("prod/key", &RequestContext{
		TokenIssuedAt: &slightFuture,
		EvalTime:      now,
	})
	if err != nil {
		t.Fatalf("token within clock skew tolerance should pass: %v", err)
	}
}

// --- Wave 2: Combined attestation level tests ---

func TestCombinedAttestationLevels(t *testing.T) {
	uid := 1001
	cfg := `{
		"attestation": {
			"production/*": {
				"require_mtls": true,
				"source_ip": ["192.168.0.110"],
				"cert_fingerprint": "sha256:CERT123",
				"allowed_tools": ["api-call"],
				"process": {
					"uid": 1001,
					"binary_hash": "sha256:BIN456"
				},
				"time_window": "06:00-23:00",
				"require_nonce": true,
				"credential_ttl": "15m",
				"require_fresh_attestation": true
			}
		}
	}`
	e, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	now := time.Date(2026, 2, 27, 14, 0, 0, 0, time.UTC)
	fresh := now.Add(-5 * time.Minute)

	// Full attestation passes
	err = e.Evaluate("production/db-password", &RequestContext{
		UsedMTLS:        true,
		SourceIP:        "192.168.0.110",
		CertFingerprint: "sha256:cert123",
		Tool:            "api-call",
		Process: &ProcessContext{
			UID:        uid,
			BinaryHash: "sha256:bin456",
		},
		NonceValidated: true,
		TokenIssuedAt:  &fresh,
		EvalTime:       now,
	})
	if err != nil {
		t.Fatalf("full attestation should pass: %v", err)
	}
}

func TestLoadPolicyWithNewFields(t *testing.T) {
	cfg := `{
		"attestation": {
			"app/*": {
				"require_mtls": true,
				"allowed_tools": ["resolve", "get"],
				"deny_tools": ["shell"],
				"time_window": "09:00-17:00",
				"time_zone": "UTC",
				"process": {
					"uid": 1000,
					"binary_hash": "sha256:abc"
				},
				"require_nonce": true,
				"nonce_max_age": "30s",
				"credential_ttl": "10m",
				"require_fresh_attestation": true
			}
		}
	}`

	e, err := Load([]byte(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	rule, _ := e.RuleFor("app/key")
	if rule == nil {
		t.Fatal("expected rule")
	}
	if !rule.RequireMTLS {
		t.Fatal("expected RequireMTLS")
	}
	if len(rule.AllowedTools) != 2 {
		t.Fatalf("expected 2 allowed_tools, got %d", len(rule.AllowedTools))
	}
	if len(rule.DenyTools) != 1 {
		t.Fatalf("expected 1 deny_tools, got %d", len(rule.DenyTools))
	}
	if rule.TimeWindow != "09:00-17:00" {
		t.Fatalf("TimeWindow = %q", rule.TimeWindow)
	}
	if rule.Process == nil {
		t.Fatal("expected Process rule")
	}
	if rule.Process.UID == nil || *rule.Process.UID != 1000 {
		t.Fatalf("Process.UID = %v", rule.Process.UID)
	}
	if !rule.RequireNonce {
		t.Fatal("expected RequireNonce")
	}
	if rule.NonceMaxAge != "30s" {
		t.Fatalf("NonceMaxAge = %q", rule.NonceMaxAge)
	}
	if rule.CredentialTTL != "10m" {
		t.Fatalf("CredentialTTL = %q", rule.CredentialTTL)
	}
	if !rule.RequireFreshAttestation {
		t.Fatal("expected RequireFreshAttestation")
	}
}

func TestRequireSignedDenied(t *testing.T) {
	e, err := Load([]byte(`{
		"attestation": {
			"signed/*": {
				"require_nonce": true,
				"require_signed": true
			}
		}
	}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Nonce validated but no signature — should be denied
	ctx := &RequestContext{
		UsedMTLS:          true,
		NonceValidated:    true,
		SignatureVerified: false,
	}
	err = e.Evaluate("signed/key", ctx)
	if err == nil {
		t.Fatal("expected denial when require_signed but no signature")
	}
	de, ok := err.(*DeniedError)
	if !ok {
		t.Fatalf("expected DeniedError, got %T: %v", err, err)
	}
	if !strings.Contains(de.Reason, "signed resolve payload required") {
		t.Fatalf("unexpected reason: %s", de.Reason)
	}
}

func TestRequireSignedAllowed(t *testing.T) {
	e, err := Load([]byte(`{
		"attestation": {
			"signed/*": {
				"require_nonce": true,
				"require_signed": true
			}
		}
	}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	ctx := &RequestContext{
		UsedMTLS:          true,
		NonceValidated:    true,
		SignatureVerified: true,
	}
	if err := e.Evaluate("signed/key", ctx); err != nil {
		t.Fatalf("expected allow when signed, got: %v", err)
	}
}

func TestRequireSignedNotNeededWithoutPolicy(t *testing.T) {
	// When require_signed is false, SignatureVerified doesn't matter
	e, err := Load([]byte(`{
		"attestation": {
			"open/*": {
				"require_nonce": true
			}
		}
	}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	ctx := &RequestContext{
		NonceValidated:    true,
		SignatureVerified: false,
	}
	if err := e.Evaluate("open/key", ctx); err != nil {
		t.Fatalf("expected allow when require_signed not set, got: %v", err)
	}
}

// --- L9: Sealed Response Policy Tests ---

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

func TestRequireSealedWithOtherChecks(t *testing.T) {
	policyJSON := `{"attestation":{"secure/*":{"require_sealed":true,"require_nonce":true}}}`
	e, err := Load([]byte(policyJSON))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Seal key but no nonce — should fail on nonce check (L8 before L9)
	ctx := &RequestContext{SealKeyPresented: true, NonceValidated: false}
	err = e.Evaluate("secure/key", ctx)
	if err == nil {
		t.Fatal("expected denial for missing nonce")
	}
	if !strings.Contains(err.Error(), "nonce") {
		t.Errorf("expected nonce denial, got: %v", err)
	}

	// Nonce but no seal key — should fail on sealed check (L9)
	ctx = &RequestContext{SealKeyPresented: false, NonceValidated: true}
	err = e.Evaluate("secure/key", ctx)
	if err == nil {
		t.Fatal("expected denial for missing seal key")
	}
	if !strings.Contains(err.Error(), "sealed") {
		t.Errorf("expected sealed denial, got: %v", err)
	}

	// Both present — should pass
	ctx = &RequestContext{SealKeyPresented: true, NonceValidated: true}
	if err := e.Evaluate("secure/key", ctx); err != nil {
		t.Fatalf("expected allow with both, got: %v", err)
	}
}

func TestNoNewFieldsNoChange(t *testing.T) {
	// Existing policy without any sealed fields should work as before
	policyJSON := `{"attestation":{"ns/*":{"require_mtls":true}}}`
	e, err := Load([]byte(policyJSON))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	ctx := &RequestContext{UsedMTLS: true}
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

func TestRequireSealedLegacyFormat(t *testing.T) {
	policyJSON := `{"rules":[{"path":"secure/*","require_sealed":true,"allow_unseal":true}]}`
	e, err := Load([]byte(policyJSON))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	rule, _ := e.RuleFor("secure/key")
	if rule == nil {
		t.Fatal("expected rule")
	}
	if !rule.RequireSealed {
		t.Error("expected RequireSealed=true from legacy format")
	}
	if !rule.AllowUnseal {
		t.Error("expected AllowUnseal=true from legacy format")
	}
}
