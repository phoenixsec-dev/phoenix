package main

import (
	"net/http"
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
	for _, list := range [][]string{{}, {"--list"}} {
		if a, err := parseSSHArgs(list); err != nil || !a.list {
			t.Errorf("%v should list machines: %+v, %v", list, a, err)
		}
	}
	for _, bad := range [][]string{{"--list", "vm204"}, {"--list", "-r", "x"}, {"-oProxyCommand=evil"}, {"a", "b"}, {"Has.Dots"}, {"a", "--reason"}, {"--", "cmd"}} {
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

// machinesJSON is a /v1/ssh/machines answer with one approved machine.
const machinesJSON = `{"agent":"vector","enabled":true,"machines":[{"name":"arch-omen","approved_until":"2026-11-11T08:00:00Z"},{"name":"vm204"}]}`

// "phoenix ssh --list" and plain "phoenix ssh" show the machines and the
// caller's approvals; plain "phoenix ssh" adds the usage line.
func TestSSHList(t *testing.T) {
	useMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/ssh/machines" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.Write([]byte(machinesJSON))
	})
	out := captureStdout(t, func() {
		if err := cmdSSH([]string{"--list"}); err != nil {
			t.Error(err)
		}
	})
	for _, want := range []string{"as agent vector", "arch-omen  approved until 2026-11-11T08:00:00Z", "  vm204\n"} {
		if !strings.Contains(out, want) {
			t.Fatalf("--list missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "usage:") {
		t.Fatalf("--list should not print usage:\n%s", out)
	}
	if out := captureStdout(t, func() { _ = cmdSSH(nil) }); !strings.Contains(out, "vm204") || !strings.Contains(out, "usage: phoenix ssh <machine>") {
		t.Fatalf("plain phoenix ssh:\n%s", out)
	}

	var b strings.Builder
	printSSHMachines(&b, sshMachineList{Note: "SSH certificates are not enabled on this server"})
	if b.String() != "SSH certificates are not enabled on this server.\n" {
		t.Fatalf("off = %q", b.String())
	}
}

// Inside an active approval the login is signed on the first try, so no
// --reason is needed and no request is filed.
func TestSSHReasonOptionalInsideApproval(t *testing.T) {
	var calls callLog
	useMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.add(r)
		w.Write([]byte(`{"certificate":"c","address":"192.0.2.5","user":"agent","expires_at":"x"}`))
	})
	signed, err := sshCertificate(sshArgs{machine: "arch-omen"}, "pk")
	if err != nil || signed.Address != "192.0.2.5" {
		t.Fatalf("signed=%+v err=%v", signed, err)
	}
	if got := calls.String(); strings.Contains(got, "access-requests") || strings.Count(got, "\n") != 0 {
		t.Fatalf("calls:\n%s", got)
	}
}

// With no approval and no --reason, the error names the agent the CLI runs
// as, since a different PHOENIX_TOKEN is the usual cause when a human did
// approve. It files nothing.
func TestSSHNoApprovalNamesTheAgent(t *testing.T) {
	var calls callLog
	useMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.add(r)
		if r.URL.Path == "/v1/ssh/machines" {
			w.Write([]byte(machinesJSON))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"access_denied","code":"SSH_GRANT_REQUIRED","next_step":"request_use"}`))
	})
	_, err := sshCertificate(sshArgs{machine: "vm204"}, "pk")
	if err == nil || !strings.Contains(err.Error(), "for agent vector") || !strings.Contains(err.Error(), "PHOENIX_TOKEN") || !strings.Contains(err.Error(), "--reason") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(calls.String(), "access-requests") {
		t.Fatalf("filed a request without a reason:\n%s", calls.String())
	}
}
