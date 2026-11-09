package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// metadataServer answers /v1/metadata/ with two secrets, one described and
// tagged, and the old list route with their bare paths.
func metadataServer(t *testing.T, gotTag *string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/metadata/svc/":
			*gotTag = r.URL.Query().Get("tag")
			json.NewEncoder(w).Encode(map[string]interface{}{"secrets": []map[string]interface{}{
				{"path": "svc/mail-password", "description": "Mail vault login", "tags": []string{"mail"}},
				{"path": "svc/app-password", "description": ""},
			}})
		case "/v1/secrets/svc/":
			json.NewEncoder(w).Encode(map[string][]string{"paths": {"svc/mail-password", "svc/app-password"}})
		default:
			t.Errorf("unexpected request %s", r.URL)
			http.NotFound(w, r)
		}
	}
}

func TestCmdListShowsDescriptions(t *testing.T) {
	var tag string
	withMockServer(t, metadataServer(t, &tag), func() {
		var err error
		out := captureStdout(t, func() { err = cmdList([]string{"svc/"}) })
		if err != nil {
			t.Fatal(err)
		}
		want := "svc/mail-password\n  Mail vault login  [mail]\nsvc/app-password\n  (no description)\n"
		if out != want {
			t.Fatalf("got:\n%s\nwant:\n%s", out, want)
		}
	})
}

func TestCmdListNamesOnlyAndTag(t *testing.T) {
	var tag string
	withMockServer(t, metadataServer(t, &tag), func() {
		out := captureStdout(t, func() { cmdList([]string{"svc/", "--names"}) })
		if out != "svc/mail-password\nsvc/app-password\n" {
			t.Fatalf("--names output = %q", out)
		}
		captureStdout(t, func() { cmdList([]string{"--tag", "mail", "svc/"}) })
		if tag != "mail" {
			t.Fatalf("--tag not sent to server, got %q", tag)
		}
	})
	if err := cmdList([]string{"--bogus"}); err == nil || !strings.Contains(err.Error(), "unknown option") {
		t.Fatalf("unknown option should fail, got %v", err)
	}
}

// An old server (no /v1/metadata) still lists names instead of failing.
func TestCmdListOldServerFallsBackToNames(t *testing.T) {
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/secrets/" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string][]string{"paths": {"a/b"}})
	}, func() {
		var out string
		stderr := captureStderr(t, func() { out = captureStdout(t, func() { cmdList(nil) }) })
		if out != "a/b\n" || !strings.Contains(stderr, "too old") {
			t.Fatalf("stdout %q stderr %q", out, stderr)
		}
	})
}

func TestCmdInfoNeverPrintsValue(t *testing.T) {
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/metadata/svc/mail-password" {
			t.Errorf("unexpected request %s", r.URL)
		}
		w.Write([]byte(`{"path":"svc/mail-password","description":"Mail vault login","tags":["mail","prod"],` +
			`"created":"2026-01-02T03:04:05Z","created_by":"aaron","updated_by":"vector"}`))
	}, func() {
		var err error
		out := captureStdout(t, func() { err = cmdInfo([]string{"svc/mail-password"}) })
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"path:         svc/mail-password", "description:  Mail vault login", "tags:         mail, prod", "by aaron", "updated:      by vector"} {
			if !strings.Contains(out, want) {
				t.Errorf("info output missing %q:\n%s", want, out)
			}
		}
	})
	if err := cmdInfo([]string{"svc/"}); err == nil {
		t.Fatal("info on a prefix should be a usage error")
	}
}

func TestCmdSetNudgesWhenNoDescription(t *testing.T) {
	for _, tc := range []struct {
		name, response string
		nudge          bool
	}{
		{"none stored", `{"status":"ok","path":"a/b","description":""}`, true},
		{"kept from before", `{"status":"ok","path":"a/b","description":"old one"}`, false},
		{"old server", `{"status":"ok","path":"a/b"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tc.response))
			}, func() {
				var err error
				stderr := captureStderr(t, func() {
					captureStdout(t, func() { err = cmdSet([]string{"a/b", "-v", "x"}) })
				})
				if err != nil {
					t.Fatal(err)
				}
				if got := strings.Contains(stderr, "has no description"); got != tc.nudge {
					t.Fatalf("nudge = %v, want %v; stderr %q", got, tc.nudge, stderr)
				}
			})
		})
	}
}
