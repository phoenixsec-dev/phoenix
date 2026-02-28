package main

import (
	"os"
	"strings"
	"testing"
)

func TestCmdSetRejectsValueAndValueStdin(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	token = "test-token"
	err := cmdSet([]string{"test/secret", "-v", "myvalue", "--value-stdin"})
	if err == nil {
		t.Fatal("expected error combining -v and --value-stdin")
	}
	if !strings.Contains(err.Error(), "cannot combine") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCmdSetValueStdinReadsFromStdin(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	token = "test-token"

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.WriteString("supersecret\n")
	w.Close()

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	// Will fail at API request (no server), but stdin parsing succeeds.
	err = cmdSet([]string{"test/secret", "--value-stdin"})
	if err == nil {
		t.Fatal("expected error (no server running)")
	}
	if strings.Contains(err.Error(), "stdin") {
		t.Fatalf("stdin parsing should have succeeded, got: %v", err)
	}
	if strings.Contains(err.Error(), "usage:") {
		t.Fatalf("should not see usage error: %v", err)
	}
}

func TestCmdSetValueStdinRejectsEmpty(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	token = "test-token"

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.Close()

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	err = cmdSet([]string{"test/secret", "--value-stdin"})
	if err == nil {
		t.Fatal("expected error for empty stdin")
	}
	if !strings.Contains(err.Error(), "stdin was empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCmdSetValueStdinTrimsTrailingNewline(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	token = "test-token"

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.WriteString("secret-with-newline\n")
	w.Close()

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	err = cmdSet([]string{"test/secret", "--value-stdin"})
	if err == nil {
		t.Fatal("expected error (no server running)")
	}
	if strings.Contains(err.Error(), "stdin was empty") {
		t.Fatal("should have read the value, not rejected as empty")
	}
}

func TestCmdSetNoValueNoStdin(t *testing.T) {
	t.Setenv("PHOENIX_TOKEN", "test-token")
	token = "test-token"

	err := cmdSet([]string{"test/secret"})
	if err == nil {
		t.Fatal("expected usage error")
	}
	if !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("expected usage error, got: %v", err)
	}
}
