package approval

import (
	"testing"

	"github.com/phoenixsec/phoenix/internal/config"
)

func TestValidateForMint(t *testing.T) {
	roles := map[string]config.RoleConfig{
		"deploy": {
			Namespaces:     []string{"prod/*"},
			Actions:        []string{"list", "read_value"},
			BootstrapTrust: []string{"bearer"},
			StepUp:         true,
		},
	}

	apr := &Approval{
		Role:            "deploy",
		Agent:           "agent1",
		BootstrapMethod: "bearer",
		SourceIP:        "10.0.0.1",
		Status:          StatusPending,
	}

	role, err := ValidateForMint(apr, roles)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if role.Namespaces[0] != "prod/*" {
		t.Fatalf("expected role namespaces, got %v", role.Namespaces)
	}
}

func TestValidateRoleRemoved(t *testing.T) {
	roles := map[string]config.RoleConfig{} // empty

	apr := &Approval{
		Role:            "deploy",
		BootstrapMethod: "bearer",
		SourceIP:        "10.0.0.1",
	}

	_, err := ValidateForMint(apr, roles)
	if err == nil {
		t.Fatal("expected error for removed role")
	}
}

func TestValidateStepUpDisabled(t *testing.T) {
	roles := map[string]config.RoleConfig{
		"deploy": {
			Namespaces:     []string{"prod/*"},
			BootstrapTrust: []string{"bearer"},
			StepUp:         false, // no longer step-up
		},
	}

	apr := &Approval{
		Role:            "deploy",
		BootstrapMethod: "bearer",
		SourceIP:        "10.0.0.1",
	}

	_, err := ValidateForMint(apr, roles)
	if err == nil {
		t.Fatal("expected error when step-up disabled")
	}
}

func TestValidateBootstrapChanged(t *testing.T) {
	roles := map[string]config.RoleConfig{
		"deploy": {
			Namespaces:     []string{"prod/*"},
			BootstrapTrust: []string{"mtls"}, // was bearer, now mtls only
			StepUp:         true,
		},
	}

	apr := &Approval{
		Role:            "deploy",
		BootstrapMethod: "bearer",
		SourceIP:        "10.0.0.1",
	}

	_, err := ValidateForMint(apr, roles)
	if err == nil {
		t.Fatal("expected error for changed bootstrap trust")
	}
}

func TestValidateSealKeyRequired(t *testing.T) {
	roles := map[string]config.RoleConfig{
		"deploy": {
			Namespaces:     []string{"prod/*"},
			BootstrapTrust: []string{"bearer"},
			StepUp:         true,
			RequireSealKey: true,
		},
	}

	apr := &Approval{
		Role:            "deploy",
		BootstrapMethod: "bearer",
		SourceIP:        "10.0.0.1",
		SealPubKey:      nil, // no seal key
	}

	_, err := ValidateForMint(apr, roles)
	if err == nil {
		t.Fatal("expected error for missing seal key")
	}
}

func TestBootstrapAllowed(t *testing.T) {
	tests := []struct {
		name    string
		trust   []string
		method  string
		isLocal bool
		want    bool
	}{
		{"direct match", []string{"bearer"}, "bearer", false, true},
		{"no match", []string{"mtls"}, "bearer", false, false},
		{"local additive", []string{"local"}, "bearer", true, true},
		{"local not loopback", []string{"local"}, "bearer", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BootstrapAllowed(tt.trust, tt.method, tt.isLocal)
			if got != tt.want {
				t.Errorf("BootstrapAllowed(%v, %q, %v) = %v, want %v", tt.trust, tt.method, tt.isLocal, got, tt.want)
			}
		})
	}
}

func TestCheckAttestation(t *testing.T) {
	if reason := CheckAttestation([]string{"require_mtls"}, "bearer", "", "10.0.0.1"); reason == "" {
		t.Error("expected failure for require_mtls with bearer")
	}
	if reason := CheckAttestation([]string{"require_mtls"}, "mtls", "", "10.0.0.1"); reason != "" {
		t.Errorf("expected success for require_mtls with mtls, got: %s", reason)
	}
	if reason := CheckAttestation([]string{"source_ip"}, "bearer", "", "10.0.0.1"); reason == "" {
		t.Error("expected failure for source_ip with non-local")
	}
	if reason := CheckAttestation([]string{"source_ip"}, "bearer", "", "127.0.0.1"); reason != "" {
		t.Errorf("expected success for source_ip with loopback, got: %s", reason)
	}
	if reason := CheckAttestation([]string{"cert_fingerprint"}, "mtls", "", "10.0.0.1"); reason == "" {
		t.Error("expected failure for cert_fingerprint with empty")
	}
	if reason := CheckAttestation([]string{"cert_fingerprint"}, "mtls", "sha256:abc", "10.0.0.1"); reason != "" {
		t.Errorf("expected success for cert_fingerprint, got: %s", reason)
	}
}
