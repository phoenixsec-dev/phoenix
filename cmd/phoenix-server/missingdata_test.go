package main

import (
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phoenixsec/phoenix/internal/config"
)

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
			err := refuseMissingData(cfg)
			if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), filepath.Join(dir, c.want)+" is not there")) {
				t.Errorf("got %v, want a refusal naming %q", err, c.want)
			}
			if now, _ := os.ReadDir(dir); len(now) != len(c.files) {
				t.Error("files were made")
			}
			// The refusal says how to go on with nothing on purpose.
			if c.want == "store.json" {
				if err := errors.Join(os.WriteFile(cfg.Store.Path, []byte(`{"version":1,"secrets":{},"namespaces":{}}`), 0600), refuseMissingData(cfg)); err != nil {
					t.Errorf("with an empty store file: %v", err)
				}
			}
			cfg.Store.Backend = "1password"
			if err := refuseMissingData(cfg); (err != nil) != (c.want == "acl.json") {
				t.Errorf("1password: %v", err)
			}
		})
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
	if err := refuseMissingData(cfg); err == nil || !strings.Contains(err.Error(), cfg.ACL.Path) {
		t.Errorf("got %v", err)
	}
}
