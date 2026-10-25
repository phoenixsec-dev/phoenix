package main

import (
	"fmt"
	"strings"
	"unicode"
)

// Client side of the server's denial contract (internal/api/denial.go,
// docs/denial-codes.md). The CLI, phoenix exec and the MCP server use these
// helpers to show a denial's code and a fixed, client-authored next step.

// refDenial is one entry of /v1/resolve's error_codes map.
type refDenial struct {
	Code     string `json:"code"`
	NextStep string `json:"next_step"`
}

// nextStepHints holds the text shown for each next_step. The text is ours,
// not the server's, so a hostile or buggy server cannot inject instructions.
var nextStepHints = map[string]string{
	"request_use":    "request temporary use of this secret from a human",
	"wait":           "a human decision is pending; check again shortly",
	"use_exec":       "use phoenix exec --env NAME=phoenix://<path> -- <command>; it requests and decrypts sealed values for you",
	"remint_session": "mint a new session, or one whose role covers this path and action",
	"ask_user":       "ask the user or Phoenix operator; this cannot be fixed by retrying",
	"none":           "check the reference; retrying will not help",
}

// nextStepHint returns the hint for a next_step. Unknown or missing values
// are treated as ask_user.
func nextStepHint(step string) string {
	if hint, ok := nextStepHints[step]; ok {
		return hint
	}
	return nextStepHints["ask_user"]
}

// maxServerTextRunes caps server-supplied text shown to users and agents.
const maxServerTextRunes = 300

// cleanServerText makes server-supplied text safe to print: it drops control
// characters (including terminal escape sequences), Unicode format characters
// (bidi overrides, zero-width), and caps the length.
func cleanServerText(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if n == maxServerTextRunes {
			b.WriteString("...")
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// cleanCode keeps a denial code only if it looks like one (A-Z, 0-9, _).
func cleanCode(code string) string {
	if code == "" || len(code) > 64 {
		return ""
	}
	for _, r := range code {
		if !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_') {
			return ""
		}
	}
	return code
}

// formatRefError renders one failed ref from a /v1/resolve response:
// "[CODE] message (next: hint)". Servers without error_codes still get
// the legacy message.
func formatRefError(ref, msg string, codes map[string]refDenial) string {
	msg = cleanServerText(msg)
	d, ok := codes[ref]
	if !ok {
		return msg
	}
	if code := cleanCode(d.Code); code != "" {
		msg = fmt.Sprintf("[%s] %s", code, msg)
	}
	return fmt.Sprintf("%s (next: %s)", msg, nextStepHint(d.NextStep))
}
