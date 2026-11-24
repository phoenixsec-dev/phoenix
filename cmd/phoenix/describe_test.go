package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// describe sends only the fields it was given, to the metadata route.
func TestCmdDescribe(t *testing.T) {
	var method, path, body string
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		method, path, body = r.Method, r.URL.Path, string(b)
		w.Write([]byte(`{"status":"ok","changed":["tags","username"]}`))
	}, func() {
		if err := cmdDescribe([]string{"a/b", "--tags", "x, y", "--username", ""}); err != nil {
			t.Fatal(err)
		}
		if method != "PATCH" || path != "/v1/metadata/a/b" || body != `{"tags":["x","y"],"username":""}` {
			t.Errorf("sent %s %s %s", method, path, body)
		}
		body = "unsent"
		for _, args := range [][]string{{"a/b"}, {"-d", "x"}, {"a/", "-d", "x"}, {"a/b", "c/d", "-d", "x"}} {
			if err := cmdDescribe(args); err == nil || !strings.Contains(err.Error(), "usage") {
				t.Errorf("%v: %v", args, err)
			}
		}
		for _, odd := range []string{"a/b#old", "a/b?x", "a%2Fb"} {
			if cmdDescribe([]string{odd, "-d", "x"}) == nil || cmdInfo([]string{odd}) == nil || cmdSet([]string{odd}) == nil {
				t.Errorf("%s was accepted", odd)
			}
		}
		if body != "unsent" {
			t.Error("a usage error reached the server")
		}
	})
}

// An older server is named as the problem, for describe and for the login
// options of set (which an older server would drop without a word).
func TestLoginOptionsOnAnOlderServer(t *testing.T) {
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PATCH" {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Write([]byte(`{"status":"ok","path":"a/b","has_description":true}`))
	}, func() {
		if err := cmdDescribe([]string{"a/b", "-d", "x"}); err == nil || !strings.Contains(err.Error(), "too old") {
			t.Errorf("describe: %v", err)
		}
		_, err := runOpenClawExecProviderCommandWithStdinResult(t, "x", func() error {
			return cmdSet([]string{"a/b", "--value-stdin", "--username", "me"})
		})
		if err == nil || !strings.Contains(err.Error(), "too old to store the username") {
			t.Errorf("set: %v", err)
		}
	})
}
