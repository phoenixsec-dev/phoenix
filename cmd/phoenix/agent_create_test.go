package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestCmdAgentCreateMissingName(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	token = "test-token"

	err := cmdAgentCreate([]string{"-t", "sometoken"})
	if err == nil {
		t.Fatal("expected error for missing name")
	}
	if !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("expected usage error, got: %v", err)
	}
}

func TestCmdAgentCreateMissingToken(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	token = "test-token"

	err := cmdAgentCreate([]string{"myagent"})
	if err == nil {
		t.Fatal("expected error for missing token")
	}
	if !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("expected usage error, got: %v", err)
	}
}

func TestCmdAgentCreateMalformedACL(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	token = "test-token"

	tests := []struct {
		name   string
		acl    string
		errStr string
	}{
		{"no colon", "nocolon", "malformed ACL rule"},
		{"empty path", ":list", "malformed ACL rule"},
		{"empty actions", "ns/*:", "malformed ACL rule"},
		{"invalid action", "ns/*:rread", "invalid action"},
		{"mixed invalid", "ns/*:list,bogus", "invalid action"},
		{"removed read", "ns/*:read", `action "read" was removed`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cmdAgentCreate([]string{"agent", "-t", "tok", "--acl", tt.acl})
			if err == nil {
				t.Fatalf("expected error for ACL %q", tt.acl)
			}
			if !strings.Contains(err.Error(), tt.errStr) {
				t.Fatalf("expected %q in error, got: %v", tt.errStr, err)
			}
		})
	}
}

func TestCmdAgentCreateValidACLTrimsSpaces(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	token = "test-token"
	// Valid ACL with spaces — should parse without ACL errors.
	// Will fail at API request (no server), not at parse time.
	err := cmdAgentCreate([]string{"agent", "-t", "tok", "--acl", " ns/* : list , read_value "})
	if err == nil {
		t.Fatal("expected error (no server), not nil")
	}
	// Should NOT be an ACL parse error
	if strings.Contains(err.Error(), "malformed ACL") || strings.Contains(err.Error(), "invalid action") || strings.Contains(err.Error(), "was removed") {
		t.Fatalf("should not be an ACL parse error: %v", err)
	}
}

func TestCmdAgentCreateTrailingSemicolon(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	token = "test-token"
	// Trailing semicolons should be allowed
	err := cmdAgentCreate([]string{"agent", "-t", "tok", "--acl", "ns/*:list;"})
	if err == nil {
		t.Fatal("expected error (no server)")
	}
	if strings.Contains(err.Error(), "malformed ACL") || strings.Contains(err.Error(), "was removed") {
		t.Fatalf("trailing semicolon should be allowed: %v", err)
	}
}

// The token comes from stdin, from -t or from a prompt asked twice, and what is
// sent is exactly it. A bad answer sends nothing.
func TestCmdAgentCreateTokenSources(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	for name, tc := range map[string]struct {
		args     []string
		stdin    string
		terminal []string // answers typed, nil = no terminal
		want     string   // "" = refused
	}{
		"stdin":           {args: []string{"--token-stdin"}, stdin: "tok-one\n", want: "tok-one"},
		"stdin, no break": {args: []string{"--token-stdin"}, stdin: "tok-one", want: "tok-one"},
		"empty stdin":     {args: []string{"--token-stdin"}},
		"two lines":       {args: []string{"--token-stdin"}, stdin: "tok\ntwo\n"},
		"stdin and -t":    {args: []string{"--token-stdin", "-t", "tok-two"}, stdin: "tok-one"},
		"-t":              {args: []string{"-t", "tok-two"}, stdin: "unused", want: "tok-two"},
		"prompt":          {terminal: []string{" tok-three ", "tok-three"}, want: "tok-three"},
		"prompt mismatch": {terminal: []string{"tok-three", "tok-four"}},
		"prompt empty":    {terminal: []string{""}},
		"nothing given":   {stdin: "tok-one"}, // stdin is read only when asked for
	} {
		t.Run(name, func(t *testing.T) {
			oldPrompt, oldTerm := promptToken, stdinIsTerminal
			defer func() { promptToken, stdinIsTerminal = oldPrompt, oldTerm }()
			stdinIsTerminal = func() bool { return tc.terminal != nil }
			promptToken = func(string) (string, error) {
				a := tc.terminal[0]
				tc.terminal = tc.terminal[1:]
				return a, nil
			}
			sent := ""
			withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				sent = string(b)
				w.Write([]byte(`{"status":"ok"}`))
			}, func() {
				out, err := run(t, tc.stdin, func() error {
					return cmdAgentCreate(append([]string{"bot", "--acl", "ns/*:list"}, tc.args...))
				})
				if tc.want == "" {
					if err == nil || sent != "" {
						t.Errorf("not refused (err %v, %d bytes sent)", err, len(sent))
					}
				} else if err != nil || !strings.Contains(sent, `"token":"`+tc.want+`"`) || strings.Contains(out, tc.want) {
					t.Errorf("err %v, wrong token sent or printed", err)
				}
			})
		})
	}
}
