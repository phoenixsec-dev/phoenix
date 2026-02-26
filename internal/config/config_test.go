package config

import "testing"

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
