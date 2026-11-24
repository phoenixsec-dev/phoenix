package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/phoenixsec/phoenix/internal/config"
)

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

// A fresh install must be able to approve: --init leaves a config that starts
// as is, with the dashboard on and only a hash of its password on disk.
func TestInitTurnsDashboardOn(t *testing.T) {
	const password = "synthetic-dash-password"
	// runInit prints the admin token; keep it out of the test output.
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	stdout := os.Stdout
	os.Stdout = devNull
	defer func() { os.Stdout = stdout }()
	for _, https := range []bool{false, true} {
		dir := filepath.Join(t.TempDir(), "data")
		if err := runInit(dir, initOptions{DashboardPassword: password, HTTPS: https}); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(filepath.Join(dir, "config.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("new config does not validate: %v", err)
		}
		if !cfg.Dashboard.Enabled || bcrypt.CompareHashAndPassword([]byte(cfg.Dashboard.PasswordHash), []byte(password)) != nil {
			t.Fatal("the dashboard is off, or its hash does not match the password")
		}
		if !cfg.AccessRequestsSettings().Enabled || cfg.HTTPSListener.Enabled != https {
			t.Fatalf("access requests %v, https %v (want %v)", cfg.AccessRequestsSettings().Enabled, cfg.HTTPSListener.Enabled, https)
		}
		files, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			data, err := os.ReadFile(filepath.Join(dir, f.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), password) {
				t.Fatalf("%s holds the dashboard password in plain text", f.Name())
			}
		}
		if err := runInit(dir, initOptions{DashboardPassword: password}); err == nil {
			t.Fatal("a second --init on the same directory was not refused")
		}
	}
}

// A password bcrypt cannot take must not leave a half-made directory, because
// the next --init would refuse it.
func TestInitBadPasswordCreatesNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := runInit(dir, initOptions{DashboardPassword: strings.Repeat("x", 73)}); err == nil {
		t.Fatal("a 73-byte password was accepted")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the directory exists after a refused --init (%v)", err)
	}
}

func TestAskDashboardPassword(t *testing.T) {
	old := promptHidden
	defer func() { promptHidden = old }()
	ask := func(answers ...string) (string, bool, error) {
		promptHidden = func(string) (string, error) {
			a := answers[0]
			answers = answers[1:]
			return a, nil
		}
		return askDashboardPassword()
	}
	if p, generated, err := ask("long-enough-pw", "long-enough-pw"); err != nil || generated || p != "long-enough-pw" {
		t.Fatalf("chosen password: generated=%v, err=%v", generated, err)
	}
	if _, _, err := ask("long-enough-pw", "something-else"); err == nil {
		t.Fatal("two different answers were accepted")
	}
	if _, _, err := ask("short"); err == nil {
		t.Fatal("a short password was accepted")
	}
	if _, _, err := ask("\U0001F525\U0001F525\U0001F525"); err == nil {
		t.Fatal("three characters of four bytes each were accepted")
	}
	p1, generated, err := ask("")
	if err != nil || !generated || len(p1) != 23 {
		t.Fatalf("empty answer: generated=%v, length %d, err=%v", generated, len(p1), err)
	}
	if p2, _, _ := ask(""); p1 == p2 {
		t.Fatal("two generated passwords are the same")
	}
}
