package main

import (
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/crypto"
	"github.com/phoenixsec/phoenix/internal/store"
)

// missingData is refuseMissingData's error.
func missingData(cfg *config.Config) error {
	_, err := refuseMissingData(cfg)
	return err
}

// A new install has no store yet and starts. Where a store or an access list is
// gone, the server refuses, names the file and changes nothing.
func TestMissingDataIsRefused(t *testing.T) {
	line := func(action, status string) string {
		return `{"ts":"2026-01-02T03:04:05Z","agent":"admin","action":"` + action + `","path":"a/b","status":"` + status + `"}` + "\n"
	}
	unused := line("list", "allowed") + line("read_value", "denied") + line("session.mint.approved", "allowed") + line("create-agent", "allowed")
	gz := func(s string) string {
		var b strings.Builder
		zw := gzip.NewWriter(&b)
		zw.Write([]byte(s))
		zw.Close()
		return b.String()
	}
	const archive = "audit-20260102T030405.000Z.log"
	for name, c := range map[string]struct {
		files map[string]string
		want  string // file the refusal names; "" = it starts
	}{
		"new install":             {map[string]string{"acl.json": "{}"}, ""},
		"used, but no secret yet": {map[string]string{"acl.json": "{}", "audit.log": unused, archive: unused, archive + ".gz": gz(unused)}, ""},
		"everything there":        {map[string]string{"acl.json": "{}", "store.json": "{}", "audit.log": line("write", "allowed")}, ""},
		"no access list":          {map[string]string{"store.json": "{}"}, "acl.json"},
		"nothing at all":          {nil, "acl.json"},
		"store written":           {map[string]string{"acl.json": "{}", "audit.log": unused + line("write", "allowed") + unused}, "store.json"},
		"store read":              {map[string]string{"acl.json": "{}", "audit.log": line("resolve", "allowed")}, "store.json"},
		"only in an archive":      {map[string]string{"acl.json": "{}", "audit.log": unused, archive: line("write", "allowed")}, "store.json"},
		"only in a gzipped one":   {map[string]string{"acl.json": "{}", "audit.log": unused, archive + ".gz": gz(line("write", "allowed"))}, "store.json"},
		"half a line at the end":  {map[string]string{"acl.json": "{}", "audit.log": line("write", "allowed") + `{"ts":"2026`}, "store.json"},
		"an archive is damaged":   {map[string]string{"acl.json": "{}", archive + ".gz": "damaged"}, "store.json"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for f, content := range c.files {
				if err := os.WriteFile(filepath.Join(dir, f), []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			cfg := config.DefaultConfig()
			cfg.ACL.Path, cfg.Store.Path, cfg.Audit.Path = filepath.Join(dir, "acl.json"), filepath.Join(dir, "store.json"), filepath.Join(dir, "audit.log")
			err := missingData(cfg)
			if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), filepath.Join(dir, c.want)+" is not there")) {
				t.Errorf("got %v, want a refusal naming %q", err, c.want)
			}
			if now, _ := os.ReadDir(dir); len(now) != len(c.files) {
				t.Error("files were made")
			}
			// The refusal says how to go on with nothing on purpose.
			if c.want == "store.json" {
				if err := errors.Join(os.WriteFile(cfg.Store.Path, []byte(`{"version":1,"secrets":{},"namespaces":{}}`), 0600), missingData(cfg)); err != nil {
					t.Errorf("with an empty store file: %v", err)
				}
			}
			cfg.Store.Backend = "1password"
			if err := missingData(cfg); (err != nil) != (c.want == "acl.json") {
				t.Errorf("1password: %v", err)
			}
		})
	}
}

// Archives lie next to the real log, under its name, not next to a link to it.
func TestLostStoreSeenThroughLinkedLog(t *testing.T) {
	for _, gzipped := range []bool{false, true} {
		dir, logs := t.TempDir(), t.TempDir()
		archive, content := filepath.Join(logs, "phoenix-20260102T030405.000Z.log"), []byte(`{"action":"write","status":"allowed"}`+"\n")
		if gzipped {
			var b strings.Builder
			zw := gzip.NewWriter(&b)
			zw.Write(content)
			zw.Close()
			archive, content = archive+".gz", []byte(b.String())
		}
		cfg := config.DefaultConfig()
		cfg.ACL.Path, cfg.Store.Path, cfg.Audit.Path = filepath.Join(dir, "acl.json"), filepath.Join(dir, "store.json"), filepath.Join(dir, "audit.log")
		if err := errors.Join(os.WriteFile(cfg.ACL.Path, []byte("{}"), 0600), os.WriteFile(archive, content, 0600),
			os.WriteFile(filepath.Join(logs, "phoenix.log"), nil, 0600), os.Symlink(filepath.Join(logs, "phoenix.log"), cfg.Audit.Path)); err != nil {
			t.Fatal(err)
		}
		if err := missingData(cfg); err == nil || !strings.Contains(err.Error(), cfg.Store.Path+" is not there") {
			t.Errorf("gzipped %v: got %v, want a refusal", gzipped, err)
		}
	}
}

// --init makes the store, so a new install starts whatever its log says, for
// example one that shares it with a server in use, and a lost one is noticed.
func TestInitMakesTheStore(t *testing.T) {
	dir := t.TempDir()
	if err := quietInit(t, dir); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.LoadMasterKey(cfg.Store.MasterKey)
	if err != nil {
		t.Fatal(err)
	}
	if st, err := store.New(cfg.Store.Path, key); err != nil || st.Count() != 0 {
		t.Fatalf("the new store: %v", err)
	}
	if err := os.WriteFile(cfg.Audit.Path, []byte(`{"action":"write","status":"allowed"}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := missingData(cfg); err != nil {
		t.Errorf("shared log: %v", err)
	}
	if err := os.Remove(cfg.Store.Path); err != nil {
		t.Fatal(err)
	}
	if err := missingData(cfg); err == nil {
		t.Error("the lost store was not noticed")
	}
}

// A link to a volume that is not mounted counts as missing.
func TestMissingDataBehindLink(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.ACL.Path, cfg.Store.Path, cfg.Audit.Path = filepath.Join(dir, "acl.json"), filepath.Join(dir, "store.json"), filepath.Join(dir, "audit.log")
	if err := os.Symlink(filepath.Join(dir, "not-mounted", "acl.json"), cfg.ACL.Path); err != nil {
		t.Fatal(err)
	}
	if err := missingData(cfg); err == nil || !strings.Contains(err.Error(), cfg.ACL.Path) {
		t.Errorf("got %v", err)
	}
}

// A file that goes away after the check, here while the server waits for the
// passphrase, is refused when it is read, even if it is back right afterwards.
func TestDataGoneDuringPassphraseWait(t *testing.T) {
	for _, gone := range []string{"store.json", "acl.json"} {
		t.Run(gone, func(t *testing.T) {
			dir := t.TempDir()
			if err := quietInit(t, dir); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(filepath.Join(dir, "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			key, err := crypto.LoadMasterKey(cfg.Store.MasterKey)
			if err != nil {
				t.Fatal(err)
			}
			const pass = "synthetic-passphrase"
			if err := crypto.SaveProtectedMasterKey(cfg.Store.MasterKey, key, pass); err != nil {
				t.Fatal(err)
			}
			st, _, err := openFileStore(cfg, true, func() (string, error) { return pass, nil })
			if err != nil {
				t.Fatal(err)
			}
			if err := st.Set("app/key", "synthetic-value", "admin", "", nil); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, gone)
			before, _ := os.ReadFile(path)

			// Startup's steps, in its order.
			there, err := refuseMissingData(cfg)
			if err != nil || !there {
				t.Fatalf("check: %v %v", there, err)
			}
			waited := false
			_, _, storeErr := openFileStore(cfg, there, func() (string, error) {
				waited = true
				return pass, os.Rename(path, path+".away")
			})
			_, aclErr := acl.NewExisting(cfg.ACL.Path)
			if err := os.Rename(path+".away", path); err != nil {
				t.Fatal(err)
			}
			if !waited {
				t.Fatal("no passphrase was asked for")
			}
			got := map[string]error{"store.json": storeErr, "acl.json": aclErr}
			for name, err := range got {
				if refused := errors.Is(err, os.ErrNotExist); refused != (name == gone) {
					t.Errorf("%s: %v, want it refused only if it was gone", name, err)
				}
			}
			if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
				t.Error("the file changed")
			}
		})
	}
}

// A store that was not there at the first check, with an audit log that had no
// line about a secret either, is checked again once everything is read: the log
// may have come back, here while the server waits for the passphrase, and say
// that there was a store.
func TestAuditHistoryBackDuringPassphraseWait(t *testing.T) {
	const pass = "synthetic-passphrase"
	for history, refused := range map[string]bool{"": false, "audit.log": true, "audit-20260102T030405.000Z.log": true} {
		t.Run("back: "+history, func(t *testing.T) {
			dir := t.TempDir()
			if err := quietInit(t, dir); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(filepath.Join(dir, "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			key, err := crypto.LoadMasterKey(cfg.Store.MasterKey)
			if err != nil {
				t.Fatal(err)
			}
			if err := errors.Join(crypto.SaveProtectedMasterKey(cfg.Store.MasterKey, key, pass), os.Remove(cfg.Store.Path)); err != nil {
				t.Fatal(err)
			}

			// Startup's steps, in its order.
			there, err := refuseMissingData(cfg)
			if err != nil || there {
				t.Fatalf("first check: %v %v", there, err)
			}
			_, _, err = openFileStore(cfg, there, func() (string, error) {
				if history == "" {
					return pass, nil
				}
				return pass, os.WriteFile(filepath.Join(dir, history), []byte(`{"action":"write","status":"allowed"}`+"\n"), 0600)
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = openACL(cfg)
			if refused != (err != nil && strings.Contains(err.Error(), cfg.Store.Path+" is not there")) || !refused && err != nil {
				t.Errorf("got %v, want refused %v", err, refused)
			}
		})
	}
}
