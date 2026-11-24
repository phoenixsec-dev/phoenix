package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/fsutil"
)

// --passphrase was removed; --init takes the passphrase from the environment
// (or stdin), and no passphrase at all means an unprotected key.
func TestInitPassphraseFromEnv(t *testing.T) {
	t.Setenv("PHOENIX_MASTER_PASSPHRASE", "")
	if p, err := initPassphrase(false); err != nil || p != "" {
		t.Fatalf("no source: got %d characters, %v", len(p), err)
	}
	t.Setenv("PHOENIX_MASTER_PASSPHRASE", "from-env")
	if p, err := initPassphrase(false); err != nil || p != "from-env" {
		t.Fatalf("env: wrong passphrase, %v", err)
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
		if err := runInit(dir, initOptions{DashboardPassword: password, HTTPS: https, Reveal: https}); err != nil {
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
		if cfg.Dashboard.Reveal != https || !cfg.Dashboard.NotifyOnRevealEnabled() {
			t.Fatalf("showing secrets %v (want %v), ping %v (want true)", cfg.Dashboard.Reveal, https, cfg.Dashboard.NotifyOnRevealEnabled())
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

// Only a clear yes lets the dashboard show secrets, and only at a terminal.
func TestAskReveal(t *testing.T) {
	for answer, want := range map[string]bool{"y\n": true, "YES\n": true, "yes": true, "\n": false, "": false, "n\n": false, "yep\n": false, "maybe\ny\n": false} {
		if got := askReveal(strings.NewReader(answer)); got != want {
			t.Errorf("%q: %v", answer, got)
		}
	}
	if initReveal() { // tests have no terminal
		t.Error("on without a terminal")
	}
}

// --init never replaces a file that is already there. A data directory whose
// master key lives elsewhere, or was lost, still holds a store, CA and config
// that nothing can make again.
func TestInitRefusesToReplaceAnything(t *testing.T) {
	for _, name := range []string{"master.key", "store.json", "acl.json", "config.json", "ca.crt", "ca.key", "server.crt", "server.key"} {
		for _, kind := range []string{"file", "dangling link"} {
			t.Run(name+" "+kind, func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, name)
				var err error
				if kind == "file" {
					err = os.WriteFile(path, []byte("{}"), 0600)
				} else {
					err = os.Symlink(filepath.Join(dir, "elsewhere", "x"), path)
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := quietInit(t, dir); err == nil || !strings.Contains(err.Error(), name) {
					t.Errorf("runInit = %v, want a refusal naming %s", err, name)
				}
				if ents, _ := os.ReadDir(dir); len(ents) != 2 {
					t.Errorf("init left %d files, want only the one that was there and its lock", len(ents))
				}
			})
		}
	}
}

// Two at once would both find the directory empty.
func TestInitRefusesWhileAnotherRuns(t *testing.T) {
	dir := t.TempDir()
	lock, err := fsutil.Lock(filepath.Join(dir, "init"))
	if err != nil {
		t.Fatal(err)
	}
	if err := quietInit(t, dir); err == nil || !strings.Contains(err.Error(), "another --init") {
		t.Errorf("runInit = %v, want a refusal", err)
	}
	lock.Release()
	if err := quietInit(t, dir); err != nil {
		t.Errorf("afterwards: %v", err)
	}
}

// A new directory, and one that holds unrelated files, both work.
func TestInitNextToOtherFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("mine"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := quietInit(t, dir); err != nil {
		t.Fatal(err)
	}
	if err := runCheckConfig(filepath.Join(dir, "config.json")); err != nil {
		t.Errorf("the config --init wrote: %v", err)
	}
}

// quietInit is runInit without its output, which ends with an admin token.
func quietInit(t *testing.T, dir string) error {
	t.Helper()
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	stdout := os.Stdout
	os.Stdout = null
	defer func() { os.Stdout = stdout }()
	return runInit(dir, initOptions{DashboardPassword: "synthetic-dash-password"})
}

// Pages name the config file the server opened, also through "link/..".
func TestRealConfigPath(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(dir, "real", "config.json")
	for _, p := range []string{real, filepath.Join(dir, "config.json")} {
		if err := os.MkdirAll(filepath.Join(filepath.Dir(p), "sub"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(dir, "real", "sub"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if got := realConfigPath(dir + "/link/../config.json"); got != real {
		t.Errorf("got %s, want %s", got, real)
	}
	t.Chdir(filepath.Join(dir, "link"))
	t.Setenv("PWD", filepath.Join(dir, "link")) // as a shell that came in through the link
	if got := realConfigPath("../config.json"); got != real {
		t.Errorf("from a linked folder: got %s, want %s", got, real)
	}
	if got := realConfigPath("missing.json"); !filepath.IsAbs(got) {
		t.Errorf("missing file: %s is not a full path", got)
	}
}
