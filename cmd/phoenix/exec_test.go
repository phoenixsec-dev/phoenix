package main

import (
	"strings"
	"testing"
)

func TestCmdExecRejectsInvalidTimeout(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	token = "test-token"

	err := cmdExec([]string{
		"--timeout", "not-a-duration",
		"--env", "FOO=phoenix://ns/secret",
		"--", "echo",
	})
	if err == nil {
		t.Fatal("expected error for invalid timeout")
	}
	if !strings.Contains(err.Error(), "invalid --timeout") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCmdExecParsesTimeout(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	token = "test-token"

	// Valid timeout but no server — should fail at resolve, not timeout parse.
	err := cmdExec([]string{
		"--timeout", "5s",
		"--env", "FOO=phoenix://ns/secret",
		"--", "echo",
	})
	if err == nil {
		t.Fatal("expected error (no server)")
	}
	if strings.Contains(err.Error(), "invalid --timeout") {
		t.Fatalf("timeout should have parsed successfully: %v", err)
	}
}

func TestCmdExecMaskEnvParsing(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	token = "test-token"

	// --mask-env is a boolean flag, should parse without issue.
	// Will fail at resolve (no server).
	err := cmdExec([]string{
		"--mask-env",
		"--env", "FOO=phoenix://ns/secret",
		"--", "echo",
	})
	if err == nil {
		t.Fatal("expected error (no server)")
	}
	// Should be a network error, not a parse error
	if strings.Contains(err.Error(), "usage:") {
		t.Fatalf("should not see usage error: %v", err)
	}
}

func TestCmdExecRejectsZeroTimeout(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	token = "test-token"

	err := cmdExec([]string{
		"--timeout", "0s",
		"--env", "FOO=phoenix://ns/secret",
		"--", "echo",
	})
	if err == nil {
		t.Fatal("expected error for zero timeout")
	}
	if !strings.Contains(err.Error(), "positive duration") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCmdExecRejectsNegativeTimeout(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	token = "test-token"

	err := cmdExec([]string{
		"--timeout", "-1s",
		"--env", "FOO=phoenix://ns/secret",
		"--", "echo",
	})
	if err == nil {
		t.Fatal("expected error for negative timeout")
	}
	if !strings.Contains(err.Error(), "positive duration") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCmdExecRejectsMissingTimeoutValue(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	token = "test-token"

	// --timeout as the very last arg (no value follows)
	err := cmdExec([]string{
		"--env", "FOO=phoenix://ns/secret",
		"--timeout",
	})
	if err == nil {
		t.Fatal("expected error for missing timeout value")
	}
	if !strings.Contains(err.Error(), "--timeout requires") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCmdExecMissingEnvMapping(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	token = "test-token"

	err := cmdExec([]string{"--", "echo"})
	if err == nil {
		t.Fatal("expected error for missing --env")
	}
	if !strings.Contains(err.Error(), "at least one --env") {
		t.Fatalf("unexpected error: %v", err)
	}
}
