package main

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

// exitCalled is what the test osExit panics with, so a test can see the code.
type exitCalled int

// runMain runs the real CLI entry point with argv, catching its exit. It
// returns the exit code (-1 if main returned), stdout and stderr.
func runMain(t *testing.T, argv ...string) (code int, stdout, stderr string) {
	t.Helper()
	oldArgs, oldExit, oldOut, oldErr := os.Args, osExit, os.Stdout, os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Args, os.Stdout, os.Stderr = append([]string{"phoenix"}, argv...), wOut, wErr
	osExit = func(c int) { panic(exitCalled(c)) }
	var outBuf, errBuf bytes.Buffer
	done := make(chan struct{})
	go func() { io.Copy(&outBuf, rOut); close(done) }()
	errDone := make(chan struct{})
	go func() { io.Copy(&errBuf, rErr); close(errDone) }()
	code = -1
	func() {
		defer func() {
			if r := recover(); r != nil {
				c, ok := r.(exitCalled)
				if !ok {
					panic(r)
				}
				code = int(c)
			}
		}()
		main()
	}()
	wOut.Close()
	wErr.Close()
	<-done
	<-errDone
	os.Args, osExit, os.Stdout, os.Stderr = oldArgs, oldExit, oldOut, oldErr
	return code, outBuf.String(), errBuf.String()
}

// The commands main dispatches. Each must be in cmdSpecs, or a typo in it
// would reach the server.
var allCommands = []string{
	"get", "set", "delete", "list", "export", "import", "audit",
	"agent create", "agent list", "agent delete", "resolve", "openclaw-exec-provider",
	"exec", "verify", "status", "policy show", "policy test", "rotate-master",
	"emergency get", "sessions list", "sessions info", "sessions revoke",
	"keypair generate", "keypair show", "request", "request status", "ssh",
	"whoami", "pending", "approve", "deny", "grants", "grants revoke", "mcp-server",
	"version", "help", "--version", "-V", "--help", "-h",
}

// tsk_20261108_0033: an unknown option on any command is a usage error
// (exit 2, "no such option", the usage line) and no request is sent, so it
// can never come back from the server as a fake permission denial.
func TestEveryCommandRejectsUnknownOptions(t *testing.T) {
	var hits atomic.Int32
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}, func() {
		for _, c := range allCommands {
			name := c
			if alias, isAlias := cmdAliases[c]; isAlias {
				name = alias
			}
			spec, ok := cmdSpecs[name]
			if !ok {
				t.Errorf("%s: missing from cmdSpecs", c)
				continue
			}
			for _, bad := range []string{"--bogus", "-z", "-"} {
				argv := append(strings.Fields(c), "some/path", bad)
				code, _, stderr := runMain(t, argv...)
				if code != 2 || !strings.Contains(stderr, "phoenix "+name+": no such option: "+bad) ||
					!strings.Contains(stderr, spec.usage) || !strings.Contains(stderr, "Run 'phoenix "+name+" --help'") {
					t.Errorf("phoenix %s %s: exit %d, stderr %q", c, bad, code, stderr)
				}
			}
			if code, stdout, _ := runMain(t, append(strings.Fields(c), "--help")...); code != 0 || !strings.Contains(stdout, spec.usage) {
				t.Errorf("phoenix %s --help: exit %d, stdout %q", c, code, stdout)
			}
		}
	})
	if n := hits.Load(); n != 0 {
		t.Fatalf("%d requests reached the server", n)
	}
}

// Option values are values even when they look like options, "--" ends the
// options, and a path after "--" comes first so the command finds it.
func TestCheckArgsValuesAndDoubleDash(t *testing.T) {
	cases := []struct {
		cmd  string
		args []string
		want []string
	}{
		{"set", []string{"a/b", "-d", "--value", "--value-stdin"}, []string{"a/b", "-d", "--value", "--value-stdin"}},
		{"set", []string{"--description=-v", "--", "-x/y"}, []string{"-x/y", "--description", "-v"}},
		{"get", []string{"--", "-x/y"}, []string{"-x/y"}},
		{"get", []string{"--", "-"}, []string{"-"}},
		{"exec", []string{"--env=A=phoenix://a/b", "--", "tool", "--output-env", "--bogus"}, []string{"--env", "A=phoenix://a/b", "--", "tool", "--output-env", "--bogus"}},
		{"agent", []string{"create", "bot", "--force", "-t", "-tok-"}, []string{"create", "bot", "--force", "-t", "-tok-"}},
	}
	for _, c := range cases {
		if got := checkArgs(c.cmd, c.args); strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s %v: got %v, want %v", c.cmd, c.args, got, c.want)
		}
	}
}

// Removed flags are refused by name with the removal message (exit 1), but
// only where they are options: not as another option's value, and not after
// "--" (review R1-03 on tsk_20261109_0002).
func TestRemovedFlagsRefusedOnlyAsOptions(t *testing.T) {
	for _, argv := range [][]string{
		{"set", "a/b", "-v", "x"},
		{"set", "a/b", "--value=x"},
		{"set", "a/b", "--description", "--", "-v", "x"},
		{"exec", "--output-env", "f", "--env", "A=phoenix://a/b", "--", "true"},
		{"resolve", "--stdin-json"},
		{"mcp-server", "--http=:1"},
		{"policy", "test", "--time", "x"},
	} {
		code, _, stderr := runMain(t, argv...)
		if code != 1 || !strings.Contains(stderr, "was removed") {
			t.Errorf("%v: exit %d, stderr %q", argv, code, stderr)
		}
	}
	if got := checkArgs("set", []string{"a/b", "-d", "-v", "--value-stdin"}); len(got) != 4 {
		t.Errorf("description \"-v\" refused: %v", got)
	}
}

// tsk_20261108_0033: the three ways people write a folder all list it; any
// other wildcard is a usage error and sends nothing. Kit's case: --prefix.
func TestListFolderForms(t *testing.T) {
	var got []string
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Path)
		w.Write([]byte(`{"paths":[]}`))
	}, func() {
		for _, form := range []string{"services/browser", "services/browser/", "services/browser/*"} {
			if code, _, stderr := runMain(t, "list", form); code != -1 {
				t.Errorf("list %s: exit %d %s", form, code, stderr)
			}
		}
		for _, bad := range []string{"services/br*", "services/*/x", "services/browser?", "a/[ab]"} {
			if code, _, stderr := runMain(t, "list", bad); code != 2 || !strings.Contains(stderr, "list takes a folder") {
				t.Errorf("list %s: exit %d, stderr %q", bad, code, stderr)
			}
		}
		if code, _, stderr := runMain(t, "list", "--prefix", "services/browser/"); code != 2 || !strings.Contains(stderr, "no such option: --prefix") {
			t.Errorf("list --prefix: exit %d, stderr %q", code, stderr)
		}
	})
	for _, p := range got {
		if p != "/v1/secrets/services/browser/" {
			t.Errorf("requested %s", p)
		}
	}
	if len(got) != 3 {
		t.Fatalf("got %d requests, want 3: %v", len(got), got)
	}
}

// MCP phoenix_list takes the same folder forms as the CLI.
func TestMCPListFolderForms(t *testing.T) {
	var got []string
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Path)
		w.Write([]byte(`{"paths":[]}`))
	}, func() {
		if _, isErr := mcpToolList([]byte(`{"prefix":"services/browser/*"}`), nil); isErr {
			t.Error("folder/* refused")
		}
		if msg, isErr := mcpToolList([]byte(`{"prefix":"services/br*"}`), nil); !isErr || !strings.Contains(msg, "list takes a folder") {
			t.Errorf("wildcard: %v %q", isErr, msg)
		}
	})
	if len(got) != 1 || got[0] != "/v1/secrets/services/browser/" {
		t.Fatalf("requests: %v", got)
	}
}

// Review R1 on tsk_20261108_0033: after "--" a path named like one of the
// command's own options is refused, never read as that option (set would
// otherwise turn on --value-stdin and write).
func TestDoubleDashNeverRevivesAnOption(t *testing.T) {
	var hits atomic.Int32
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }, func() {
		for _, argv := range [][]string{
			{"set", "k/v", "--", "--value-stdin"},
			{"verify", "--", "--dry-run"},
			{"export", "-f", "env", "--", "--format=x/"},
		} {
			if code, _, stderr := runMain(t, argv...); code != 2 || !strings.Contains(stderr, "named like one of this command's options") {
				t.Errorf("%v: exit %d, stderr %q", argv, code, stderr)
			}
		}
	})
	if n := hits.Load(); n != 0 {
		t.Fatalf("%d requests reached the server", n)
	}
}
