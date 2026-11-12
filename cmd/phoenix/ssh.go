package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

const sshUsage = `usage: phoenix ssh <machine> [--reason "why you need it"] [--ttl 15m] [--ask-again] [-- command...]`

// defaultSSHTTL is what an agent asks for unless it says otherwise.
const defaultSSHTTL = "15m"

type sshArgs struct {
	machine, reason, ttl string
	askAgain             bool // file a new request even after a human revoked the last one
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
		case strings.HasPrefix(args[i], "-") || a.machine != "":
			return a, errors.New(sshUsage)
		default:
			a.machine = args[i]
		}
	}
	if !sshMachinePattern.MatchString(a.machine) {
		return a, errors.New(sshUsage)
	}
	return a, nil
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
	signed, denial, err := sshSign(a.machine, publicKey)
	if err != nil {
		return err
	}
	if denial != nil && sshNeedsApproval(denial, a.askAgain) {
		if err := sshRequestApproval(a); err != nil {
			return err
		}
		signed, denial, err = sshSign(a.machine, publicKey)
		if err != nil {
			return err
		}
	}
	if denial != nil {
		return errors.New(formatDenial(*denial, "  "))
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
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exitCodeError(exit.ExitCode())
		}
		return fmt.Errorf("running ssh: %w", err)
	}
	return nil
}

// sshRequestApproval files the request and waits for a person to decide. Asking
// again while one is pending just returns that same request.
func sshRequestApproval(a sshArgs) error {
	if strings.TrimSpace(a.reason) == "" {
		return fmt.Errorf("%s needs a human's approval: run again with --reason \"why you need it\"", a.machine)
	}
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
