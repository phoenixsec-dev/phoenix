package main

import "testing"

// --passphrase was removed; --init takes the passphrase from the environment
// (or stdin), and no passphrase at all means an unprotected key.
func TestInitPassphraseFromEnv(t *testing.T) {
	t.Setenv("PHOENIX_MASTER_PASSPHRASE", "")
	if p, err := initPassphrase(false); err != nil || p != "" {
		t.Fatalf("no source: got %q, %v", p, err)
	}
	t.Setenv("PHOENIX_MASTER_PASSPHRASE", "from-env")
	if p, err := initPassphrase(false); err != nil || p != "from-env" {
		t.Fatalf("env: got %q, %v", p, err)
	}
}
