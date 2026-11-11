package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
)

// phoenix ssh logs an agent in to a machine with a human's temporary approval.
//
// It makes a throwaway key, asks the server to sign it, and runs the system ssh
// with the resulting certificate. If there is no approval yet it files a request
// and waits. The key and certificate live in a temp directory that is removed
// when ssh exits, so nothing long-lived is left on this machine.

var (
	sshMachinePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	// The address and user come from the server and go on an ssh command line,
	// so they are checked here too: a leading "-" would be read as an option.
	sshAddressPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.:-]{0,254}$`)
	sshUserPattern    = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

const sshUsage = `usage: phoenix ssh <machine> [--reason "why you need it"] [--ttl 15m] [--ask-again] [-- 'command']
       phoenix ssh --list`

// defaultSSHTTL is what an agent asks for unless it says otherwise.
const defaultSSHTTL = "15m"

type sshArgs struct {
	machine, reason, ttl string
	askAgain             bool // file a new request even after a human revoked the last one
	list                 bool // print the machines instead of logging in
	command              []string
}

func parseSSHArgs(args []string) (sshArgs, error) {
	a := sshArgs{ttl: defaultSSHTTL}
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--":
			a.command = args[i+1:]
			i = len(args)
		case args[i] == "--reason" || args[i] == "-r":
			if i++; i >= len(args) {
				return a, errors.New("--reason needs a value")
			}
			a.reason = args[i]
		case args[i] == "--ttl":
			if i++; i >= len(args) {
				return a, errors.New("--ttl needs a duration like 15m")
			}
			a.ttl = args[i]
		case args[i] == "--ask-again":
			a.askAgain = true
		case args[i] == "--list":
			a.list = true
		case strings.HasPrefix(args[i], "-") || a.machine != "":
			return a, errors.New(sshUsage)
		default:
			a.machine = args[i]
		}
	}
	// No machine and nothing else: show what there is to log in to.
	if a.machine == "" && a.command == nil && a.reason == "" && !a.askAgain {
		a.list = true
	}
	if a.list {
		if a.machine != "" || a.command != nil || a.reason != "" || a.askAgain {
			return a, errors.New("--list takes no machine, command or other option\n" + sshUsage)
		}
		return a, nil
	}
	if !sshMachinePattern.MatchString(a.machine) {
		return a, errors.New(sshUsage)
	}
	return a, nil
}

// sshMachineList is the server's answer from GET /v1/ssh/machines.
type sshMachineList struct {
	Agent    string `json:"agent"`
	Enabled  bool   `json:"enabled"`
	Note     string `json:"note"`
	Machines []struct {
		Name          string `json:"name"`
		ApprovedUntil string `json:"approved_until"`
	} `json:"machines"`
}

// fetchSSHMachines asks the server which machines it can sign logins for.
func fetchSSHMachines() (sshMachineList, error) {
	var out sshMachineList
	_, err := apiJSON("GET", "/v1/ssh/machines", nil, &out)
	return out, err
}

// printSSHMachines writes the list for a person or agent to read: one machine
// per line, with the end of this caller's approval where it has one.
func printSSHMachines(w io.Writer, l sshMachineList) {
	if !l.Enabled || len(l.Machines) == 0 {
		msg := "SSH logins are not enabled on this server"
		if l.Note != "" {
			msg = cleanServerText(l.Note)
		}
		fmt.Fprintln(w, msg+".")
		return
	}
	fmt.Fprintf(w, "Machines you can ask to log in to (as agent %s):\n", cleanServerText(l.Agent))
	for _, m := range l.Machines {
		line := "  " + cleanServerText(m.Name)
		if m.ApprovedUntil != "" {
			line += "  approved until " + cleanServerText(m.ApprovedUntil) + " (no --reason needed)"
		}
		fmt.Fprintln(w, line)
	}
}

// cmdSSHList handles "phoenix ssh --list", and plain "phoenix ssh" with the
// usage line added.
func cmdSSHList(withUsage bool) error {
	// Same identity a login uses: the agent's own token, never a session minted
	// for PHOENIX_ROLE, which would hide the approvals a login can use. A
	// phxs_ session token given directly still lists names.
	if token == "" || strings.HasPrefix(token, "phxs_") {
		if err := requireAuth(); err != nil {
			return err
		}
	}
	l, err := fetchSSHMachines()
	if err != nil {
		return err
	}
	printSSHMachines(os.Stdout, l)
	if withUsage {
		fmt.Println(sshUsage)
	}
	return nil
}

// sshSignResult is the server's answer from POST /v1/ssh/sign.
type sshSignResult struct {
	Certificate string `json:"certificate"`
	Address     string `json:"address"`
	User        string `json:"user"`
	ExpiresAt   string `json:"expires_at"`
}

// sshSign asks for a certificate. It returns the denial when the server refuses,
// so the caller can tell "needs approval" from every other failure.
func sshSign(machine, publicKey string) (sshSignResult, *serverDenial, error) {
	var out sshSignResult
	body, err := json.Marshal(map[string]string{"host": machine, "public_key": publicKey})
	if err != nil {
		return out, nil, err
	}
	resp, err := apiRequest("POST", "/v1/ssh/sign", strings.NewReader(string(body)))
	if err != nil {
		return out, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusForbidden {
			var d serverDenial
			if json.NewDecoder(resp.Body).Decode(&d) == nil && d.Code != "" {
				return out, &d, nil
			}
			return out, nil, fmt.Errorf("HTTP %d from the server", resp.StatusCode)
		}
		return out, nil, handleError(resp)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, nil, fmt.Errorf("decoding response: %w", err)
	}
	return out, nil, nil
}

// sshNeedsApproval reports whether to file a request. After a revoke only with
// --ask-again: a person said no, so the agent must ask them, not the dashboard.
func sshNeedsApproval(d *serverDenial, askAgain bool) bool {
	return d.Code == "SSH_GRANT_REQUIRED" || d.Code == "GRANT_EXPIRED" || (askAgain && d.Code == "GRANT_REVOKED")
}

// writeThrowawayKey makes the key pair the certificate is signed for and returns
// the private key's path and the public key in authorized_keys format.
func writeThrowawayKey(dir string) (keyPath, publicKey string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, "phoenix-ssh")
	if err != nil {
		return "", "", err
	}
	keyPath = filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		return "", "", err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", "", err
	}
	return keyPath, string(ssh.MarshalAuthorizedKey(sshPub)), nil
}

// sshCommandArgs builds the system ssh command line. Only the throwaway key is
// offered, so the login can only ever succeed through the certificate.
func sshCommandArgs(keyPath, certPath, user, address string, command []string) []string {
	args := []string{
		"-i", keyPath,
		"-o", "CertificateFile=" + certPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityAgent=none",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"-l", user,
		address,
	}
	return append(args, command...)
}

// cmdSSH handles "phoenix ssh <machine> [--reason ...] [--ttl 15m] [-- command...]".
func cmdSSH(args []string) error {
	a, err := parseSSHArgs(args)
	if err != nil {
		return err
	}
	if a.list {
		return cmdSSHList(!slices.Contains(args, "--list"))
	}
	if err := requireBootstrapAuth(); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "phoenix-ssh-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	keyPath, publicKey, err := writeThrowawayKey(dir)
	if err != nil {
		return err
	}
	signed, err := sshCertificate(a, publicKey)
	if err != nil {
		return err
	}
	if !sshAddressPattern.MatchString(signed.Address) || !sshUserPattern.MatchString(signed.User) {
		return errors.New("server returned an invalid address or user")
	}
	certPath := keyPath + "-cert.pub"
	if err := os.WriteFile(certPath, []byte(signed.Certificate), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Access to %s ends at %s.\n", a.machine, cleanServerText(signed.ExpiresAt))
	cmd := exec.Command("ssh", sshCommandArgs(keyPath, certPath, signed.User, signed.Address, a.command)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	// Same filter as phoenix exec: ssh (and any ProxyCommand it runs) gets
	// no Phoenix token or other Phoenix credential.
	cmd.Env = childEnv(os.Environ(), false)
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exitCodeError(exit.ExitCode())
		}
		return fmt.Errorf("running ssh: %w", err)
	}
	return nil
}

// sshCertificate gets publicKey signed for a.machine. Inside an active approval
// the first try works and no --reason is needed; only a missing or ended
// approval files a request (which needs one) and waits for a person.
func sshCertificate(a sshArgs, publicKey string) (sshSignResult, error) {
	signed, denial, err := sshSign(a.machine, publicKey)
	if err != nil {
		return signed, err
	}
	if denial != nil && sshNeedsApproval(denial, a.askAgain) {
		if strings.TrimSpace(a.reason) == "" {
			return signed, sshNoApprovalError(a.machine, denial.Code)
		}
		if err := sshRequestApproval(a); err != nil {
			return signed, err
		}
		signed, denial, err = sshSign(a.machine, publicKey)
		if err != nil {
			return signed, err
		}
	}
	if denial != nil {
		return signed, errors.New(formatDenial(*denial, "  "))
	}
	return signed, nil
}

// sshNoApprovalError explains a refused login when there is no --reason to
// file a request with. It names the agent the CLI is running as, because an
// approval belongs to one agent, token and IP. A login that fails right after
// an approval usually ran with a different PHOENIX_TOKEN from the one that
// asked (a shell wrapper that sets it, skipped by timeout, env or a script),
// or from another IP. code is the server's denial code.
func sshNoApprovalError(machine, code string) error {
	who := ""
	if l, err := fetchSSHMachines(); err == nil && l.Agent != "" {
		who = fmt.Sprintf(" for agent %s, which has no active approval for it from this IP", cleanServerText(l.Agent))
	}
	if code == "GRANT_EXPIRED" {
		return fmt.Errorf("your approval for %s has ended%s.\n"+
			"  Run again with --reason \"why you need it\" to ask a human again", machine, who)
	}
	return fmt.Errorf("%s needs a human's approval%s.\n"+
		"  If a human already approved it, check that this command uses the same PHOENIX_TOKEN\n"+
		"  and runs from the same machine (IP) as the one that asked.\n"+
		"  Otherwise run again with --reason \"why you need it\" and wait for a human to decide", machine, who)
}

// sshRequestApproval files the request and waits for a person to decide. Asking
// again while one is pending just returns that same request.
func sshRequestApproval(a sshArgs) error {
	var rq accessRequestView
	if _, err := apiJSON("POST", "/v1/access-requests", map[string]any{
		"paths": []string{"ssh/" + a.machine}, "action": "ssh_login", "reason": a.reason, "ttl": a.ttl,
	}, &rq); err != nil {
		return err
	}
	// Status goes to stderr: stdout belongs to the remote command.
	fmt.Fprintf(os.Stderr, "Asked a human for access to %s (%s).\n", a.machine, cleanServerText(rq.ID))
	return waitForDecisionTo(os.Stderr, rq)
}
