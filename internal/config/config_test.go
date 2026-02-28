package config

import (
	"encoding/json"
	"testing"
)

func TestValidateRequiresAuthMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Auth.Bearer.Enabled = false
	cfg.Auth.MTLS.Enabled = false

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error when no auth mode enabled")
	}
}

func TestValidateMTLSRequiresPaths(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Auth.MTLS.Enabled = true
	cfg.Auth.MTLS.CACert = "/data/ca.crt"
	cfg.Auth.MTLS.CAKey = "/data/ca.key"
	// Missing server cert/key

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error when mTLS enabled without server cert paths")
	}
}

func TestValidateMTLSComplete(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Auth.MTLS.Enabled = true
	cfg.Auth.MTLS.CACert = "/data/ca.crt"
	cfg.Auth.MTLS.CAKey = "/data/ca.key"
	cfg.Auth.MTLS.ServerCert = "/data/server.crt"
	cfg.Auth.MTLS.ServerKey = "/data/server.key"

	err := cfg.Validate()
	if err != nil {
		t.Fatalf("complete mTLS config should validate: %v", err)
	}
}

func TestValidateDefaultPasses(t *testing.T) {
	cfg := DefaultConfig()
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("default config should validate: %v", err)
	}
}

func TestValidateBearerOnlyPasses(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Auth.Bearer.Enabled = true
	cfg.Auth.MTLS.Enabled = false

	err := cfg.Validate()
	if err != nil {
		t.Fatalf("bearer-only config should validate: %v", err)
	}
}

func TestValidateNonceMaxAgeValid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Attestation.Nonce.Enabled = true
	cfg.Attestation.Nonce.MaxAge = "30s"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid nonce max_age should pass: %v", err)
	}
}

func TestValidateNonceMaxAgeInvalid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Attestation.Nonce.Enabled = true
	cfg.Attestation.Nonce.MaxAge = "not-a-duration"

	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid nonce max_age should fail validation")
	}
}

func TestValidateTokenTTLValid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Attestation.Token.Enabled = true
	cfg.Attestation.Token.TTL = "15m"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid token TTL should pass: %v", err)
	}
}

func TestValidateTokenTTLInvalid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Attestation.Token.Enabled = true
	cfg.Attestation.Token.TTL = "bogus"

	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid token TTL should fail validation")
	}
}

func TestValidateAttestationDisabledIgnoresBadValues(t *testing.T) {
	// When disabled, bad duration strings should not cause validation errors
	cfg := DefaultConfig()
	cfg.Attestation.Nonce.Enabled = false
	cfg.Attestation.Nonce.MaxAge = "not-a-duration"
	cfg.Attestation.Token.Enabled = false
	cfg.Attestation.Token.TTL = "bogus"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled attestation should not validate durations: %v", err)
	}
}

func TestAttestationConfigJSON(t *testing.T) {
	// Verify JSON round-trip for attestation config
	cfg := DefaultConfig()
	cfg.Attestation.Nonce.Enabled = true
	cfg.Attestation.Nonce.MaxAge = "45s"
	cfg.Attestation.Token.Enabled = true
	cfg.Attestation.Token.TTL = "10m"

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed Config
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !parsed.Attestation.Nonce.Enabled {
		t.Error("nonce.enabled should be true after round-trip")
	}
	if parsed.Attestation.Nonce.MaxAge != "45s" {
		t.Errorf("nonce.max_age = %q, want %q", parsed.Attestation.Nonce.MaxAge, "45s")
	}
	if !parsed.Attestation.Token.Enabled {
		t.Error("token.enabled should be true after round-trip")
	}
	if parsed.Attestation.Token.TTL != "10m" {
		t.Errorf("token.ttl = %q, want %q", parsed.Attestation.Token.TTL, "10m")
	}
}

func TestDefaultConfigNoAttestation(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Attestation.Nonce.Enabled {
		t.Error("nonce should be disabled by default")
	}
	if cfg.Attestation.Token.Enabled {
		t.Error("tokens should be disabled by default")
	}
}
