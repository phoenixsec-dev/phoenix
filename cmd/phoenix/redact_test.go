package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
)

var redactTestValues = []redactValue{
	{Name: "API_TOKEN", Value: "supersecret-1"},
	{Name: "DB_PASS", Value: "hunter2hunter2"},
}

func TestRedactorReplacesEveryValue(t *testing.T) {
	var out bytes.Buffer
	r := newRedactor(&out, redactTestValues)
	in := "Authorization: Bearer supersecret-1\npass=hunter2hunter2 again supersecret-1\n"
	r.Write([]byte(in))
	r.Flush()
	want := "Authorization: Bearer [REDACTED:API_TOKEN]\npass=[REDACTED:DB_PASS] again [REDACTED:API_TOKEN]\n"
	if out.String() != want {
		t.Fatalf("got %q\nwant %q", out.String(), want)
	}
}

// Every way of cutting the stream into two writes must give the same result.
func TestRedactorValueSplitAcrossWrites(t *testing.T) {
	in := "x supersecret-1 y hunter2hunter2 z"
	want := "x [REDACTED:API_TOKEN] y [REDACTED:DB_PASS] z"
	for cut := 0; cut <= len(in); cut++ {
		var out bytes.Buffer
		r := newRedactor(&out, redactTestValues)
		r.Write([]byte(in[:cut]))
		r.Write([]byte(in[cut:]))
		r.Flush()
		if out.String() != want {
			t.Fatalf("cut at %d: got %q", cut, out.String())
		}
	}
	// One byte per write.
	var out bytes.Buffer
	r := newRedactor(&out, redactTestValues)
	for i := 0; i < len(in); i++ {
		r.Write([]byte{in[i]})
	}
	r.Flush()
	if out.String() != want {
		t.Fatalf("byte-at-a-time: got %q", out.String())
	}
}

func TestRedactorLongestValueWinsAndShortSkipped(t *testing.T) {
	var out bytes.Buffer
	r := newRedactor(&out, []redactValue{{"SHORT", "abcd"}, {"LONG", "abcdefgh"}, {"TINY", "ab1"}})
	r.Write([]byte("abcdefgh abcd ab1"))
	r.Flush()
	if got, want := out.String(), "[REDACTED:LONG] [REDACTED:SHORT] ab1"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestRedactorHoldsOnlyPossiblePrefix(t *testing.T) {
	var out bytes.Buffer
	r := newRedactor(&out, redactTestValues)
	r.Write([]byte("hello super"))
	if out.String() != "hello " {
		t.Fatalf("before flush: %q (only the possible prefix should be held)", out.String())
	}
	r.Flush()
	if out.String() != "hello super" {
		t.Fatalf("after flush: %q", out.String())
	}
}

func TestChildEnvStripsBrokerCredentials(t *testing.T) {
	env := childEnv([]string{"PATH=/bin", "PHOENIX_TOKEN=t", "PHOENIX_CLIENT_KEY=k", "PHOENIX_SEAL_KEY=s", "REF=phoenix://a/b"}, true)
	if strings.Join(env, ",") != "PATH=/bin" {
		t.Fatalf("child env = %v", env)
	}
}

// The leak found in the 2026-11 review: these reached the child before.
// PHOENIX_ROLE would let the child mint its own session; the others are
// credentials outright. A 1Password token under a custom name (named by
// PHOENIX_OP_TOKEN_ENV) goes too; unrelated variables stay.
func TestChildEnvStripsEveryPhoenixCredential(t *testing.T) {
	env := childEnv([]string{
		"PATH=/bin", "HOME=/home/a",
		"PHOENIX_MCP_TOKEN=m", "PHOENIX_MASTER_PASSPHRASE=p", "PHOENIX_ROLE=r",
		"OP_SERVICE_ACCOUNT_TOKEN=o", "PHOENIX_OP_TOKEN_ENV=MY_OP", "MY_OP=o2",
		"PHOENIX_SOMETHING_NEW=x", "NOT_PHOENIX_TOKEN=keep",
	}, false)
	if got := strings.Join(env, ","); got != "PATH=/bin,HOME=/home/a,NOT_PHOENIX_TOKEN=keep" {
		t.Fatalf("child env = %s", got)
	}
}

func TestRunRedactedStdoutStderrSplitAndExitCode(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	env := append(childEnv([]string{"PATH=" + os.Getenv("PATH"), "PHOENIX_TOKEN=broker-cred"}, false),
		"API_TOKEN=supersecret-1", "DB_PASS=hunter2hunter2")
	// The first value is written in two pieces with a pause, so it crosses a
	// real pipe read boundary.
	script := `printf 'out: supers'; sleep 0.2; printf 'ecret-1\n'; echo "err: $DB_PASS" >&2; env; exit 7`
	var stdout, stderr bytes.Buffer
	code, err := runRedacted(sh, []string{"sh", "-c", script}, env, redactTestValues, nil, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if code != 7 {
		t.Errorf("exit code = %d, want 7", code)
	}
	all := stdout.String() + stderr.String()
	for _, secret := range []string{"supersecret-1", "hunter2hunter2", "broker-cred", "PHOENIX_TOKEN"} {
		if strings.Contains(all, secret) {
			t.Errorf("output contains %q:\n%s", secret, all)
		}
	}
	if !strings.Contains(stdout.String(), "out: [REDACTED:API_TOKEN]\n") || !strings.Contains(stderr.String(), "err: [REDACTED:DB_PASS]") {
		t.Errorf("redaction markers missing:\nstdout %q\nstderr %q", stdout.String(), stderr.String())
	}
}

func TestRunRedactedSignalExitCode(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	code, err := runRedacted(sh, []string{"sh", "-c", "kill -TERM $$"}, nil, nil, nil, io.Discard, io.Discard)
	if err != nil || code != 143 {
		t.Fatalf("code=%d err=%v, want 143", code, err)
	}
}

// Full cmdExec path: resolve over HTTP, run the child redacted, pass the
// exit code back as exitCodeError.
func TestCmdExecRedactOutput(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	useMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"values": map[string]string{"phoenix://ns/api": "supersecret-1"}})
	})
	t.Setenv("PHOENIX_TOKEN", "broker-cred")
	t.Setenv("PHOENIX_ROLE", "")

	rd, wr, _ := os.Pipe()
	oldOut := os.Stdout
	os.Stdout = wr
	err := cmdExec([]string{"--redact-output", "--env", "API_TOKEN=phoenix://ns/api", "--",
		"sh", "-c", `echo "token=$API_TOKEN cred=${PHOENIX_TOKEN:-none}"; exit 3`})
	os.Stdout = oldOut
	wr.Close()
	got, _ := io.ReadAll(rd)

	var code exitCodeError
	if !errors.As(err, &code) || code != 3 {
		t.Fatalf("err = %v, want exit code 3", err)
	}
	if string(got) != "token=[REDACTED:API_TOKEN] cred=none\n" {
		t.Fatalf("output = %q", got)
	}
}

func TestCmdExecRedactRejectsOutputEnv(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	token = "test-token"
	err := cmdExec([]string{"--redact-output", "--output-env", "/tmp/x", "--env", "A=phoenix://a/b"})
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("err = %v", err)
	}
}

// Review R1-02: every MCP-over-HTTP flag is refused, in both spellings.
func TestRemovedMCPFlags(t *testing.T) {
	for _, args := range [][]string{{"--http", "127.0.0.1:1"}, {"--tls-cert", "x"}, {"--tls-key=x"}, {"--mcp-token", "t"}, {"-v", "--http=:1"}} {
		if removedMCPFlag(args) == "" {
			t.Errorf("%v not refused", args)
		}
	}
	if f := removedMCPFlag([]string{"--verbose"}); f != "" {
		t.Errorf("--verbose refused as %q", f)
	}
}
