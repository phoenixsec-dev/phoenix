package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestNextStepHintUnknownFallsBackToAskUser(t *testing.T) {
	for _, step := range []string{"", "rm -rf /", "REQUEST_USE", "approve_yourself"} {
		if got := nextStepHint(step); got != nextStepHints["ask_user"] {
			t.Errorf("nextStepHint(%q) = %q, want ask_user hint", step, got)
		}
	}
	if got := nextStepHint("use_exec"); !strings.Contains(got, "phoenix exec") {
		t.Errorf("use_exec hint = %q", got)
	}
}

func TestCleanServerTextStripsControlAndFormatChars(t *testing.T) {
	in := "ok\x1b[31mred\x1b[0m‮evil​zero\nline"
	got := cleanServerText(in)
	for _, bad := range []string{"\x1b", "‮", "​", "\n"} {
		if strings.Contains(got, bad) {
			t.Fatalf("cleanServerText kept %q: %q", bad, got)
		}
	}
	long := cleanServerText(strings.Repeat("a", 1000))
	if len([]rune(long)) != maxServerTextRunes+3 {
		t.Fatalf("long text not capped: %d runes", len([]rune(long)))
	}
}

func TestCleanCodeRejectsNonCodes(t *testing.T) {
	for _, bad := range []string{"", "acl_denied", "ACL DENIED", "ACL_DENIED\x1b", strings.Repeat("A", 65)} {
		if cleanCode(bad) != "" {
			t.Errorf("cleanCode(%q) accepted", bad)
		}
	}
	if cleanCode("ACL_DENIED") != "ACL_DENIED" {
		t.Error("cleanCode rejected a valid code")
	}
}

func TestFormatRefError(t *testing.T) {
	codes := map[string]refDenial{"phoenix://a/b": {Code: "ACL_DENIED", NextStep: "ask_user"}}
	got := formatRefError("phoenix://a/b", "access denied", codes)
	if !strings.Contains(got, "[ACL_DENIED] access denied") || !strings.Contains(got, nextStepHints["ask_user"]) {
		t.Fatalf("formatRefError = %q", got)
	}
	// Older servers send no error_codes: legacy message only.
	if got := formatRefError("phoenix://x/y", "access denied", nil); got != "access denied" {
		t.Fatalf("legacy formatRefError = %q", got)
	}
}

func TestMCPFormatDenialShowsNextStepAndCleansText(t *testing.T) {
	body := []byte(`{"error":"access_denied","code":"ACL_DENIED","detail":"no\u001b[2Jaccess","remediation":"ask‮admin","next_step":"ask_user"}`)
	got := mcpFormatDenial(body, 403)
	if !strings.Contains(got, "[ACL_DENIED]") || !strings.Contains(got, "next: "+nextStepHints["ask_user"]) {
		t.Fatalf("mcpFormatDenial = %q", got)
	}
	if strings.Contains(got, "\x1b") || strings.Contains(got, "‮") {
		t.Fatalf("mcpFormatDenial kept control chars: %q", got)
	}
	// A malformed code is not echoed as a code.
	got = mcpFormatDenial([]byte(`{"error":"access_denied","code":"<b>x</b>","detail":"d"}`), 403)
	if strings.Contains(got, "<b>") {
		t.Fatalf("mcpFormatDenial echoed malformed code: %q", got)
	}
}

func TestHandleErrorShowsNextStep(t *testing.T) {
	resp := &http.Response{
		StatusCode: 403,
		Body: io.NopCloser(strings.NewReader(
			`{"error":"access_denied","code":"SEALED_REQUIRED","detail":"sealed only","next_step":"use_exec"}`)),
	}
	err := handleError(resp)
	if err == nil || !strings.Contains(err.Error(), "[SEALED_REQUIRED]") || !strings.Contains(err.Error(), "next: "+nextStepHints["use_exec"]) {
		t.Fatalf("handleError = %v", err)
	}
}
