package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phoenixsec/phoenix/internal/config"
)

// --reissue-cert writes three files. A config that names one of them twice, or
// another Phoenix file, must not cost the CA key or the store.
func TestReissueCertRefusesSharedPaths(t *testing.T) {
	for name, change := range map[string]func(c *config.Config){
		"server key is the CA key":  func(c *config.Config) { c.HTTPSListener.Key = c.HTTPSListener.CAKey },
		"cert is the CA key":        func(c *config.Config) { c.HTTPSListener.Cert = c.HTTPSListener.CAKey },
		"cert and key are one file": func(c *config.Config) { c.HTTPSListener.Key = c.HTTPSListener.Cert },
		"cert is the store":         func(c *config.Config) { c.HTTPSListener.Cert = c.Store.Path },
		"cert is the CA cert":       func(c *config.Config) { c.HTTPSListener.Cert = c.HTTPSListener.CACert },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := quietInit(t, dir); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(filepath.Join(dir, "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			change(cfg)
			before, _ := os.ReadFile(cfg.HTTPSListener.CAKey)
			if err := runReissueCert(cfg, sanList{"192.0.2.1"}); err == nil || !strings.Contains(err.Error(), "same file") {
				t.Errorf("runReissueCert = %v, want a refusal", err)
			}
			if after, _ := os.ReadFile(cfg.HTTPSListener.CAKey); string(after) != string(before) {
				t.Error("the CA key was replaced")
			}
		})
	}
}

// The ordinary case still works, twice.
func TestReissueCert(t *testing.T) {
	dir := t.TempDir()
	if err := quietInit(t, dir); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := runReissueCert(cfg, sanList{"192.0.2.1"}); err != nil {
			t.Fatal(err)
		}
		cfg.HTTPSListener.Enabled = true
		if _, err := loadHTTPSListener(cfg.HTTPSListener); err != nil {
			t.Error(err)
		}
	}
}
