package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestParseSSHArgs(t *testing.T) {
	a, err := parseSSHArgs([]string{"arch-omen", "-r", "deploy", "--ttl", "5m", "--", "sudo", "-n", "id", "--", "x"})
	if err != nil {
		t.Fatal(err)
	}
	if a.machine != "arch-omen" || a.reason != "deploy" || a.ttl != "5m" || !slices.Equal(a.command, []string{"sudo", "-n", "id", "--", "x"}) {
		t.Fatalf("parsed %+v", a)
	}
	if a, err = parseSSHArgs([]string{"vm204"}); err != nil || a.ttl != defaultSSHTTL {
		t.Fatalf("default ttl: %+v, %v", a, err)
	}
	for _, bad := range [][]string{{}, {"-oProxyCommand=evil"}, {"a", "b"}, {"Has.Dots"}, {"a", "--reason"}, {"--", "cmd"}} {
		if _, err := parseSSHArgs(bad); err == nil {
			t.Errorf("%v should be refused", bad)
		}
	}
}

func TestRevokedGrantIsOnlyReRequestedWhenAsked(t *testing.T) {
	if !sshNeedsApproval(&serverDenial{Code: "SSH_GRANT_REQUIRED"}, false) || !sshNeedsApproval(&serverDenial{Code: "GRANT_EXPIRED"}, false) {
		t.Fatal("no grant yet and an expired grant should file a request")
	}
	if sshNeedsApproval(&serverDenial{Code: "GRANT_REVOKED"}, false) {
		t.Fatal("a revoked grant must go back to the human, not file a new request")
	}
	if !sshNeedsApproval(&serverDenial{Code: "GRANT_REVOKED"}, true) {
		t.Fatal("--ask-again should file a request after a revoke")
	}
	if a, err := parseSSHArgs([]string{"vm204", "--ask-again"}); err != nil || !a.askAgain {
		t.Fatalf("--ask-again: %+v, %v", a, err)
	}
}

// Approval status must not land on stdout, which belongs to the remote command.
func TestApprovalSummaryCanGoToAnyWriter(t *testing.T) {
	var b strings.Builder
	fprintRequest(&b, accessRequestView{ID: "req_1", Status: "approved", Action: "ssh_login", NextStep: "use_exec", GrantedPaths: []string{"ssh/vm204"}})
	if !strings.Contains(b.String(), "phoenix ssh vm204 -- <command>") {
		t.Fatalf("summary = %q", b.String())
	}
}

func TestThrowawayKeyIsPrivateAndOnlyItIsOffered(t *testing.T) {
	dir := t.TempDir()
	keyPath, publicKey, err := writeThrowawayKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(keyPath)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, err %v", fi.Mode().Perm(), err)
	}
	if !strings.HasPrefix(publicKey, "ssh-ed25519 ") {
		t.Fatalf("public key = %q", publicKey)
	}
	args := sshCommandArgs(keyPath, filepath.Join(dir, "cert"), "agent", "192.168.0.99", []string{"id"})
	joined := strings.Join(args, " ")
	for _, want := range []string{"IdentitiesOnly=yes", "IdentityAgent=none", "BatchMode=yes", "-l agent 192.168.0.99 id"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}
}
