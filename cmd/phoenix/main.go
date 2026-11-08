// Phoenix CLI — client for the Phoenix secrets management API.
//
// Usage:
//
//	phoenix get <path>
//	phoenix set <path> [--description <desc>] [--tags <t1,t2>]   (hidden prompt)
//	phoenix set <path> --multiline [--description <desc>]        (hidden, ends with Ctrl-D)
//	phoenix set <path> --value <value> [--description <desc>] [--tags <t1,t2>]
//	phoenix set <path> --value-stdin [--description <desc>] [--tags <t1,t2>]
//	phoenix delete <path>
//	phoenix list [prefix]
//	phoenix export <prefix> --format env
//	phoenix import <file> --prefix <prefix>
//	phoenix audit [--last N] [--agent <name>] [--since <RFC3339>]
//	phoenix agent create <name> --token <token> --acl <path:actions,...> [--force]
//	phoenix agent list
//	phoenix resolve <ref> [ref...]
//	phoenix resolve --stdin-json
//	phoenix openclaw-exec-provider
//	phoenix exec --env KEY=phoenix://ns/secret [--output-env <path>] [--timeout <dur>] [--mask-env] [--redact-output] -- <command> [args...]
//	phoenix request <path>... --reason "..." [--ttl 30m] [--wait]
//	phoenix request status <req_id>
//	phoenix ssh <machine> [--reason "..."] [--ttl 15m] [-- command...]
//	phoenix whoami | pending | grants [--all] | grants revoke <gnt_id>
//	phoenix approve <req_id> | deny <req_id>
//	phoenix verify <file> [--dry-run]
//	phoenix status
//	phoenix token mint <agent>
//	phoenix policy show <path>
//	phoenix policy test --agent <name> --ip <ip> [--time <RFC3339>] <path>
//	phoenix init <dir>
//	phoenix mcp-server
package main

import (
	"bufio"
	"context"
	sha256pkg "crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/crypto"
	"github.com/phoenixsec/phoenix/internal/policy"
	"github.com/phoenixsec/phoenix/internal/store"
	"github.com/phoenixsec/phoenix/internal/transport"
	"github.com/phoenixsec/phoenix/internal/version"
)

var (
	serverURL  string
	token      string
	tokenMu    sync.RWMutex // guards token in concurrent MCP mode
	httpClient *http.Client
)

func init() {
	serverURL = os.Getenv("PHOENIX_SERVER")
	if serverURL == "" {
		serverURL = "http://127.0.0.1:9090"
	}
	token = os.Getenv("PHOENIX_TOKEN")

	httpClient = buildHTTPClient()
}

// buildHTTPClient creates an HTTP client with optional TLS configuration.
// Set PHOENIX_CA_CERT to trust the Phoenix CA for TLS connections.
func buildHTTPClient() *http.Client {
	caCertPath := os.Getenv("PHOENIX_CA_CERT")
	if os.Getenv("PHOENIX_CLIENT_CERT") != "" || os.Getenv("PHOENIX_CLIENT_KEY") != "" {
		fmt.Fprintln(os.Stderr, clientCertRemovedNote)
	}

	// No TLS config needed if no CA cert specified
	if caCertPath == "" {
		return http.DefaultClient
	}

	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot read PHOENIX_CA_CERT %q: %v\n", caCertPath, err)
		return http.DefaultClient
	}

	rootPool := x509.NewCertPool()
	if !rootPool.AppendCertsFromPEM(caCert) {
		fmt.Fprintf(os.Stderr, "warning: PHOENIX_CA_CERT contains no valid certificates\n")
		return http.DefaultClient
	}

	tlsCfg := &tls.Config{
		RootCAs:    rootPool,
		MinVersion: tls.VersionTLS12,
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	// Warn (never fail) when the configured server is plaintext HTTP on a
	// non-loopback address: bearer tokens and secret values would cross the
	// network unencrypted. Loopback plaintext is the supported default.
	// PHOENIX_ALLOW_PLAINTEXT=<host> opts out for hosts the operator knows
	// are only reached over a host-local network (see PlaintextAllowed).
	switch cmd {
	case "version", "--version", "-V", "help", "--help", "-h":
		// No server contact.
	default:
		if w := transport.ClientPlaintextWarning(serverURL, os.Getenv("PHOENIX_ALLOW_PLAINTEXT")); w != "" {
			fmt.Fprintln(os.Stderr, w)
		}
	}

	checkRemovedCommand(cmd, args)

	var err error
	switch cmd {
	case "get":
		err = cmdGet(args)
	case "set":
		err = cmdSet(args)
	case "delete":
		err = cmdDelete(args)
	case "list":
		err = cmdList(args)
	case "export":
		err = cmdExport(args)
	case "import":
		err = cmdImport(args)
	case "audit":
		err = cmdAudit(args)
	case "agent":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "usage: phoenix agent <create|list|delete>")
			os.Exit(1)
		}
		switch args[0] {
		case "create":
			err = cmdAgentCreate(args[1:])
		case "list":
			err = cmdAgentList()
		case "delete":
			err = cmdAgentDelete(args[1:])
		default:
			fmt.Fprintf(os.Stderr, "unknown agent subcommand: %s\n", args[0])
			os.Exit(1)
		}
	case "resolve":
		err = cmdResolve(args)
	case "openclaw-exec-provider":
		err = cmdOpenClawExecProvider(args)
	case "secret-provider":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "usage: phoenix secret-provider <openclaw>")
			os.Exit(1)
		}
		switch args[0] {
		case "openclaw":
			err = cmdOpenClawExecProvider(args[1:])
		default:
			fmt.Fprintf(os.Stderr, "unknown secret-provider subcommand: %s\n", args[0])
			os.Exit(1)
		}
	case "exec":
		err = cmdExec(args)
	case "verify":
		err = cmdVerify(args)
	case "status":
		err = cmdStatus(args)
	case "policy":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "usage: phoenix policy <show|test>")
			os.Exit(1)
		}
		switch args[0] {
		case "show":
			err = cmdPolicyShow(args[1:])
		case "test":
			err = cmdPolicyTest(args[1:])
		default:
			fmt.Fprintf(os.Stderr, "unknown policy subcommand: %s\n", args[0])
			os.Exit(1)
		}
	case "rotate-master":
		err = cmdRotateMaster()
	case "emergency":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "usage: phoenix emergency get <path> --data-dir <dir>")
			os.Exit(1)
		}
		switch args[0] {
		case "get":
			err = cmdEmergencyGet(args[1:])
		default:
			fmt.Fprintf(os.Stderr, "unknown emergency subcommand: %s\n", args[0])
			os.Exit(1)
		}
	case "agent-sock":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "usage: phoenix agent-sock attest")
			os.Exit(1)
		}
		switch args[0] {
		case "attest":
			err = cmdAgentSockAttest(args[1:])
		default:
			fmt.Fprintf(os.Stderr, "unknown agent-sock subcommand: %s\n", args[0])
			os.Exit(1)
		}
	case "sessions":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "usage: phoenix sessions <list|info|revoke>")
			os.Exit(1)
		}
		switch args[0] {
		case "list":
			err = cmdSessionList(args[1:])
		case "info":
			err = cmdSessionInfo(args[1:])
		case "revoke":
			err = cmdSessionRevoke(args[1:])
		default:
			fmt.Fprintf(os.Stderr, "unknown sessions subcommand: %s\n", args[0])
			os.Exit(1)
		}
	case "approve":
		err = cmdApprove(args)
	case "deny":
		err = cmdDeny(args)
	case "request":
		err = cmdRequest(args)
	case "ssh":
		err = cmdSSH(args)
	case "pending":
		err = cmdPending(args)
	case "whoami":
		err = cmdWhoami(args)
	case "grants":
		err = cmdGrants(args)
	case "mcp-server":
		if flag := removedMCPFlag(args); flag != "" {
			exitRemoved("phoenix mcp-server "+flag, removedCommands["mcp-server --http"])
		}
		err = cmdMCP(args)
	case "keypair":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "usage: phoenix keypair <generate|show>")
			os.Exit(1)
		}
		switch args[0] {
		case "generate":
			err = cmdKeypairGenerate(args[1:])
		case "show":
			err = cmdKeypairShow(args[1:])
		default:
			fmt.Fprintf(os.Stderr, "unknown keypair subcommand: %s\n", args[0])
			os.Exit(1)
		}
	case "version", "--version", "-V":
		fmt.Printf("phoenix %s\n", version.Version)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}

	var exitCode exitCodeError
	if errors.As(err, &exitCode) {
		// phoenix exec --redact-output: pass the child's exit code through.
		os.Exit(int(exitCode))
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`phoenix — secrets management CLI

Usage:
  phoenix get <path>                          Read a secret
  phoenix set <path> [-d desc]                Create/update a secret (hidden prompt)
  phoenix set <path> --multiline              Hidden multi-line paste (PEM keys), end with Ctrl-D
  phoenix set <path> --value-stdin            Read secret value from stdin
  phoenix set <path> -v <value> [-d desc]     Value on the command line (leaks to history)
  phoenix delete <path>                       Delete a secret
  phoenix list [prefix]                       List secret paths
  phoenix export <prefix> -f env              Export as .env format
  phoenix import <file> -p <prefix>           Import from .env file
  phoenix import --from 1password --vault <v> --prefix <p> [--item <name>] [--dry-run] [--skip-existing]
  phoenix audit [-n N] [-a agent] [-s time]   Query audit log
  phoenix agent create <name> -t <token> --acl <path:actions;path:actions> [--force]
                                              ACL path globs: ns/* = one level, ns/** = recursive
  phoenix agent list                          List agents
  phoenix agent delete <name>                 Delete an agent
  phoenix resolve <ref> [ref...]               Resolve phoenix:// references to values
  phoenix resolve --stdin-json                  OpenClaw SecretRef exec provider (stdin/stdout JSON)
  phoenix openclaw-exec-provider               OpenClaw SecretRef exec provider (stdin/stdout JSON)
  phoenix secret-provider openclaw             Alias for openclaw-exec-provider
  phoenix ssh <machine> -r "why" [-- cmd]     Log in to a machine with a human's temporary approval
  phoenix exec --env K=phoenix://n/s -- cmd   Run command with resolved secrets as env
  phoenix exec --output-env <file> --env ...  Write resolved env to file (no exec)
  phoenix exec --timeout 5s --env ...         Fail if resolution exceeds duration
  phoenix exec --mask-env --env ...           Strip phoenix:// refs from child env
  phoenix exec --redact-output --env ...      Replace secret values in the command's output with
                                              [REDACTED:NAME]; guards against accidental echo,
                                              not a hostile command; values under 4 bytes are not
                                              redacted; exit code is passed through
  phoenix verify <file> [--dry-run]           Check phoenix:// refs in file are resolvable
  phoenix status                              Show server health, secrets, agents, policy
  phoenix policy show <path>                  Show attestation requirements for path
  phoenix policy test -a <agent> -i <ip> [-t time] <p>  Dry-run attestation check
  phoenix rotate-master                       Rotate master encryption key
  phoenix emergency get <path> --data-dir <d> [--confirm]  Break-glass offline secret retrieval
  phoenix agent-sock attest [--socket <path>]  Attest via local Unix socket agent
  phoenix keypair generate <name> [-o path]    Generate X25519 seal key pair
  phoenix keypair show <name>                 Show public key for a seal key pair
  phoenix sessions list [--role R] [--agent A]  List active sessions
  phoenix sessions info <session-id>            Show session details
  phoenix sessions revoke <session-id>          Revoke a session
  phoenix request <path>... --reason "..." [--ttl 30m] [--wait]
                                              Ask a human for temporary use of exact secrets
  phoenix request status <req_id>              Show a request's state and what to do next
  phoenix whoami                               Show identity, ACL rules, grants, pending requests
  phoenix pending                              List access requests waiting for a human (approver)
  phoenix approve <req_id> [--ttl 15m] [--path p ...] [--yes]
                                              Approve an access request (approver; may narrow)
  phoenix deny <req_id> [--note "..."]         Deny an access request
  phoenix grants [--all] [--agent <name>]      List grants (own; approvers see all)
  phoenix grants revoke <gnt_id>               Revoke a grant now
  phoenix mcp-server                          Run MCP server (stdio JSON-RPC)
  (Initialize a server data directory with: phoenix-server --init <dir>)

Environment:
  PHOENIX_SERVER       Server URL (default: http://127.0.0.1:9090)
  PHOENIX_TOKEN        Bearer token for authentication
  PHOENIX_CA_CERT      CA certificate for TLS verification
  PHOENIX_ALLOW_PLAINTEXT Hosts (comma list) to skip the plaintext http:// warning for
  PHOENIX_SEAL_KEY     Seal private key file (enables sealed mode)
  PHOENIX_POLICY       Path to attestation policy file (JSON)
  PHOENIX_ROLE         Role name for auto-mint session identity`)
}

// requireAuth checks that an auth method is configured: PHOENIX_ROLE (a
// session minted with PHOENIX_TOKEN) or PHOENIX_TOKEN itself.
func requireAuth() error {
	// PHOENIX_ROLE takes precedence: always mint a scoped session token,
	// even when PHOENIX_TOKEN is set (the broad token is used only for bootstrap).
	if os.Getenv("PHOENIX_ROLE") != "" {
		if err := autoMintSession(); err != nil {
			return fmt.Errorf("session auto-mint: %w", err)
		}
		renewSessionIfNeeded()
		return nil
	}

	// Already have a token (bootstrap bearer or session from env)
	if token != "" {
		if strings.HasPrefix(token, "phxs_") {
			renewSessionIfNeeded()
		}
		return nil
	}

	return fmt.Errorf("no auth configured: set PHOENIX_TOKEN (and optionally PHOENIX_ROLE)")
}

func apiRequest(method, path string, body io.Reader) (*http.Response, error) {
	return apiRequestWithHeaders(method, path, body, nil)
}

func apiRequestWithHeaders(method, path string, body io.Reader, headers map[string]string) (*http.Response, error) {
	url := serverURL + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	tokenMu.RLock()
	tok := token
	tokenMu.RUnlock()
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	// Pass tool/skill attestation claim if set
	return httpClient.Do(req)
}

func cmdGet(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}
	if len(args) < 1 {
		return fmt.Errorf("usage: phoenix get <path>")
	}

	sealPrivKey, err := loadSealKeyForRequest()
	if err != nil {
		return fmt.Errorf("loading seal key: %w", err)
	}

	resp, err := apiRequestWithHeaders("GET", "/v1/secrets/"+args[0], nil, sealHeaders(sealPrivKey))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return handleErrorForPath(resp, args[0])
	}

	if sealPrivKey != nil {
		var sealed struct {
			SealedValue interface{} `json:"sealed_value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&sealed); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
		if sealed.SealedValue == nil {
			return fmt.Errorf("expected sealed_value in response but got none")
		}
		value, err := decryptSealedValue(sealed.SealedValue, sealPrivKey)
		if err != nil {
			return err
		}
		fmt.Print(value)
		return nil
	}

	var secret struct {
		Value string `json:"value"`
	}
	json.NewDecoder(resp.Body).Decode(&secret)
	fmt.Print(secret.Value)
	return nil
}

// promptSecretValue asks for a secret on the terminal with echo off, so a
// pasted value never lands in shell history, `ps`, or the scrollback.
// Surrounding whitespace is trimmed because clipboard copies often carry a
// stray newline or space. Prints the length and a masked preview to stderr
// so the user can tell they pasted the right thing. With multiline set it
// reads until Ctrl-D, for PEM keys and certs.
func promptSecretValue(path string, multiline bool) (string, error) {
	var raw string
	var err error
	if multiline {
		raw, err = crypto.PromptHiddenMultiline(fmt.Sprintf("Paste value for %s, then press Ctrl-D (input hidden): ", path))
	} else {
		raw, err = crypto.PromptPassphraseAllowEmpty(fmt.Sprintf("Value for %s (input hidden): ", path))
	}
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("no value entered")
	}
	if multiline {
		fmt.Fprintf(os.Stderr, "Received %d lines, %d chars\n", strings.Count(value, "\n")+1, len([]rune(value)))
	} else {
		fmt.Fprintf(os.Stderr, "Received %s\n", maskedPreview(value))
	}
	return value, nil
}

// maskedPreview describes a secret without revealing it: always the length,
// plus the first and last 4 characters only when the value is long enough
// (20+) that those 8 characters give little away.
func maskedPreview(v string) string {
	r := []rune(v)
	if len(r) < 20 {
		return fmt.Sprintf("%d chars", len(r))
	}
	return fmt.Sprintf("%d chars: %s…%s", len(r), string(r[:4]), string(r[len(r)-4:]))
}

func cmdSet(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}

	var path, value, desc string
	var tags []string
	var valueStdin, multiline bool

	i := 0
	if i < len(args) && !strings.HasPrefix(args[i], "-") {
		path = args[i]
		i++
	}

	for i < len(args) {
		switch args[i] {
		case "-v", "--value":
			i++
			if i < len(args) {
				value = args[i]
			}
		case "--value-stdin":
			valueStdin = true
		case "--multiline":
			multiline = true
		case "-d", "--description":
			i++
			if i < len(args) {
				desc = args[i]
			}
		case "--tags":
			i++
			if i < len(args) {
				tags = strings.Split(args[i], ",")
			}
		}
		i++
	}

	if value != "" && !valueStdin {
		fmt.Fprintln(os.Stderr, "WARNING: -v/--value is visible in process listings. Use --value-stdin instead.")
	}

	if value != "" && valueStdin {
		return fmt.Errorf("cannot combine -v/--value with --value-stdin")
	}

	if multiline && (value != "" || valueStdin) {
		return fmt.Errorf("--multiline is an interactive prompt; it cannot be combined with -v or --value-stdin")
	}

	if valueStdin {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("reading stdin: %w", err)
		}
		value = strings.TrimSuffix(string(data), "\n")
		if value == "" {
			return fmt.Errorf("stdin was empty — no secret value provided")
		}
	}

	setUsage := fmt.Errorf("usage: phoenix set <path> [-d description] [--tags t1,t2]   (hidden prompt)\n       phoenix set <path> --value-stdin [-d description] [--tags t1,t2]\n       phoenix set <path> -v <value> [-d description] [--tags t1,t2]")
	if path == "" {
		return setUsage
	}

	if multiline && !crypto.IsTerminal() {
		return fmt.Errorf("--multiline needs a terminal; scripts should use --value-stdin")
	}

	// No value given and a person is at the keyboard: ask for it with echo off.
	if value == "" && !valueStdin && crypto.IsTerminal() {
		v, err := promptSecretValue(path, multiline)
		if err != nil {
			return err
		}
		value = v
	}

	if value == "" {
		return setUsage
	}

	body := map[string]interface{}{
		"value":       value,
		"description": desc,
		"tags":        tags,
	}
	bodyBytes, _ := json.Marshal(body)

	resp, err := apiRequest("PUT", "/v1/secrets/"+path, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	fmt.Printf("ok: %s\n", path)
	return nil
}

func cmdDelete(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}
	if len(args) < 1 {
		return fmt.Errorf("usage: phoenix delete <path>")
	}

	resp, err := apiRequest("DELETE", "/v1/secrets/"+args[0], nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	fmt.Printf("deleted: %s\n", args[0])
	return nil
}

func cmdList(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}

	sealPrivKey, err := loadSealKeyForRequest()
	if err != nil {
		return fmt.Errorf("loading seal key: %w", err)
	}

	prefix := ""
	if len(args) > 0 {
		prefix = args[0]
	}

	resp, err := apiRequestWithHeaders("GET", "/v1/secrets/"+prefix, nil, sealHeaders(sealPrivKey))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	var result struct {
		Paths []string `json:"paths"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	for _, p := range result.Paths {
		fmt.Println(p)
	}
	return nil
}

func cmdExport(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}

	sealPrivKey, err := loadSealKeyForRequest()
	if err != nil {
		return fmt.Errorf("loading seal key: %w", err)
	}

	var prefix, format string
	i := 0
	if i < len(args) && !strings.HasPrefix(args[i], "-") {
		prefix = args[i]
		i++
	}
	for i < len(args) {
		switch args[i] {
		case "-f", "--format":
			i++
			if i < len(args) {
				format = args[i]
			}
		}
		i++
	}

	if format == "" {
		format = "env"
	}

	// Get list of paths
	resp, err := apiRequestWithHeaders("GET", "/v1/secrets/"+prefix, nil, sealHeaders(sealPrivKey))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	var listResult struct {
		Paths []string `json:"paths"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listResult); err != nil {
		return fmt.Errorf("decoding list response: %w", err)
	}

	for _, path := range listResult.Paths {
		resp, err := apiRequestWithHeaders("GET", "/v1/secrets/"+path, nil, sealHeaders(sealPrivKey))
		if err != nil {
			return fmt.Errorf("request failed for %q: %w", path, err)
		}
		if resp.StatusCode != 200 {
			err := handleError(resp)
			resp.Body.Close()
			return fmt.Errorf("exporting %q: %w", path, err)
		}
		var secret struct {
			Value string `json:"value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&secret); err != nil {
			resp.Body.Close()
			return fmt.Errorf("decoding secret %q: %w", path, err)
		}
		resp.Body.Close()

		// Convert path to env var name: openclaw/api-key → API_KEY
		parts := strings.SplitN(path, "/", 2)
		var envName string
		if len(parts) > 1 {
			envName = parts[1]
		} else {
			envName = parts[0]
		}
		envName = strings.ToUpper(strings.ReplaceAll(envName, "-", "_"))
		envName = strings.ToUpper(strings.ReplaceAll(envName, "/", "_"))

		switch format {
		case "env":
			fmt.Printf("%s=%s\n", envName, secret.Value)
		case "json":
			fmt.Printf("{%q: %q}\n", envName, secret.Value)
		}
	}
	return nil
}

func cmdImport(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}

	var filePath, prefix, from, vault, item string
	var dryRun, skipExisting bool

	i := 0
	// First positional arg is file path (for env import)
	if i < len(args) && !strings.HasPrefix(args[i], "-") {
		filePath = args[i]
		i++
	}
	for i < len(args) {
		switch args[i] {
		case "-p", "--prefix":
			i++
			if i < len(args) {
				prefix = args[i]
			}
		case "--from":
			i++
			if i < len(args) {
				from = args[i]
			}
		case "--vault":
			i++
			if i < len(args) {
				vault = args[i]
			}
		case "--item":
			i++
			if i < len(args) {
				item = args[i]
			}
		case "--dry-run":
			dryRun = true
		case "--skip-existing":
			skipExisting = true
		}
		i++
	}

	switch from {
	case "1password":
		if vault == "" || prefix == "" {
			return fmt.Errorf("usage: phoenix import --from 1password --vault <vault> --prefix <prefix> [--item <name>] [--dry-run] [--skip-existing]")
		}
		return import1Password(vault, item, prefix, dryRun, skipExisting)
	case "", "env":
		return importEnvFile(filePath, prefix)
	default:
		return fmt.Errorf("unknown import source %q (supported: 1password, env)", from)
	}
}

func importEnvFile(filePath, prefix string) error {
	if filePath == "" || prefix == "" {
		return fmt.Errorf("usage: phoenix import <file> -p <prefix>")
	}

	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		// Remove quotes if present
		value = strings.Trim(value, "\"'")

		secretPath := prefix + strings.ToLower(strings.ReplaceAll(key, "_", "-"))

		body, _ := json.Marshal(map[string]interface{}{
			"value":       value,
			"description": fmt.Sprintf("Imported from %s", filePath),
		})

		resp, err := apiRequest("PUT", "/v1/secrets/"+secretPath, strings.NewReader(string(body)))
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to import %s: %v\n", key, err)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			fmt.Printf("imported: %s → %s\n", key, secretPath)
			count++
		} else {
			fmt.Fprintf(os.Stderr, "warning: failed to import %s (HTTP %d)\n", key, resp.StatusCode)
		}
	}

	fmt.Printf("\nimported %d secrets\n", count)
	return nil
}

func cmdAudit(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}

	params := url.Values{}
	i := 0
	for i < len(args) {
		switch args[i] {
		case "-n", "--last":
			i++
			if i < len(args) {
				params.Set("limit", args[i])
			}
		case "-a", "--agent":
			i++
			if i < len(args) {
				params.Set("agent", args[i])
			}
		case "-s", "--since":
			i++
			if i < len(args) {
				params.Set("since", args[i])
			}
		}
		i++
	}

	path := "/v1/audit"
	if qs := params.Encode(); qs != "" {
		path += "?" + qs
	}

	resp, err := apiRequest("GET", path, nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	var result struct {
		Entries []struct {
			Timestamp string `json:"ts"`
			Agent     string `json:"agent"`
			Action    string `json:"action"`
			Path      string `json:"path"`
			Status    string `json:"status"`
			IP        string `json:"ip"`
			Reason    string `json:"reason"`
		} `json:"entries"`
		Truncated bool `json:"truncated"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	for _, e := range result.Entries {
		status := e.Status
		if e.Reason != "" {
			status += " (" + e.Reason + ")"
		}
		fmt.Printf("%s  %-10s %-8s %-40s %s  %s\n",
			e.Timestamp, e.Agent, e.Action, e.Path, status, e.IP)
	}
	if result.Truncated {
		fmt.Fprintln(os.Stderr, "note: only the newest part of the audit log was searched; older entries may match (see the archived audit-*.log files)")
	}
	return nil
}

func cmdAgentCreate(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}

	var name, agentToken, aclStr string
	var force bool
	i := 0
	if i < len(args) && !strings.HasPrefix(args[i], "-") {
		name = args[i]
		i++
	}
	for i < len(args) {
		switch args[i] {
		case "-t", "--token":
			i++
			if i < len(args) {
				agentToken = args[i]
			}
		case "--acl":
			i++
			if i < len(args) {
				aclStr = args[i]
			}
		case "--force":
			force = true
		}
		i++
	}

	if name == "" || agentToken == "" {
		return fmt.Errorf("usage: phoenix agent create <name> -t <token> [--acl <path:action,action;path:action>] [--force]")
	}

	// Parse ACL string: "openclaw/*:read,write;vector/*:read"
	// Rules separated by ";", actions within a rule separated by ","
	var permissions []map[string]interface{}
	if aclStr != "" {
		for _, rule := range strings.Split(aclStr, ";") {
			rule = strings.TrimSpace(rule)
			if rule == "" {
				continue // allow trailing semicolons
			}
			parts := strings.SplitN(rule, ":", 2)
			if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
				return fmt.Errorf("malformed ACL rule %q: expected format path:action[,action]", rule)
			}
			rawActions := strings.Split(parts[1], ",")
			actions := make([]string, 0, len(rawActions))
			for _, a := range rawActions {
				a = strings.TrimSpace(a)
				if !acl.ValidActions[acl.Action(a)] {
					return fmt.Errorf("invalid action %q in ACL rule %q (valid: list, read_value, read, write, delete, admin)", a, rule)
				}
				actions = append(actions, a)
			}
			permissions = append(permissions, map[string]interface{}{
				"path":    strings.TrimSpace(parts[0]),
				"actions": actions,
			})
		}
	}

	body, _ := json.Marshal(map[string]interface{}{
		"name":        name,
		"token":       agentToken,
		"permissions": permissions,
	})

	endpoint := "/v1/agents"
	if force {
		endpoint += "?force=true"
	}

	resp, err := apiRequest("POST", endpoint, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	if force {
		fmt.Printf("agent created/updated: %s\n", name)
	} else {
		fmt.Printf("agent created: %s\n", name)
	}
	return nil
}

func cmdAgentList() error {
	if err := requireAuth(); err != nil {
		return err
	}

	resp, err := apiRequest("GET", "/v1/agents", nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	var result struct {
		Agents []string `json:"agents"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	for _, name := range result.Agents {
		fmt.Println(name)
	}
	return nil
}

func cmdAgentDelete(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}

	if len(args) < 1 {
		return fmt.Errorf("usage: phoenix agent delete <name>")
	}
	name := args[0]

	resp, err := apiRequest("DELETE", "/v1/agents/"+name, nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	fmt.Printf("agent deleted: %s\n", name)
	return nil
}

type openClawExecProviderRequest struct {
	ProtocolVersion int      `json:"protocolVersion"`
	Provider        string   `json:"provider"`
	IDs             []string `json:"ids"`
}

type openClawExecProviderError struct {
	Message string `json:"message"`
}

type openClawExecProviderResponse struct {
	ProtocolVersion int                                  `json:"protocolVersion"`
	Values          map[string]string                    `json:"values"`
	Errors          map[string]openClawExecProviderError `json:"errors,omitempty"`
}

func parseOpenClawExecProviderRequest(r io.Reader) (*openClawExecProviderRequest, error) {
	var req openClawExecProviderRequest
	dec := json.NewDecoder(r)
	if err := dec.Decode(&req); err != nil {
		return nil, fmt.Errorf("decoding OpenClaw exec provider request: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("OpenClaw exec provider request contains trailing data")
	}
	if req.ProtocolVersion != 1 {
		return nil, fmt.Errorf("OpenClaw exec provider protocolVersion must be 1")
	}
	if req.Provider == "" {
		return nil, fmt.Errorf("OpenClaw exec provider request missing provider")
	}
	if req.Provider != "phoenix" {
		return nil, fmt.Errorf("OpenClaw exec provider request provider must be phoenix")
	}
	if req.IDs == nil {
		return nil, fmt.Errorf("OpenClaw exec provider request missing ids")
	}
	for _, id := range req.IDs {
		if strings.TrimSpace(id) == "" {
			return nil, fmt.Errorf("OpenClaw exec provider request contains empty id")
		}
	}
	return &req, nil
}

func openClawIDToPhoenixRef(id string) string {
	trimmed := strings.TrimSpace(id)
	if strings.HasPrefix(trimmed, "phoenix://") {
		return trimmed
	}
	return "phoenix://" + strings.TrimPrefix(trimmed, "/")
}

func cmdOpenClawExecProvider(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: phoenix openclaw-exec-provider")
	}
	if err := requireAuth(); err != nil {
		return err
	}

	req, err := parseOpenClawExecProviderRequest(os.Stdin)
	if err != nil {
		return err
	}

	if len(req.IDs) == 0 {
		enc := json.NewEncoder(os.Stdout)
		return enc.Encode(openClawExecProviderResponse{
			ProtocolVersion: 1,
			Values:          make(map[string]string),
		})
	}

	refs := make([]string, 0, len(req.IDs))
	seenRefs := make(map[string]bool, len(req.IDs))
	for _, id := range req.IDs {
		ref := openClawIDToPhoenixRef(id)
		if !seenRefs[ref] {
			refs = append(refs, ref)
			seenRefs[ref] = true
		}
	}

	sealPrivKey, err := loadSealKeyForRequest()
	if err != nil {
		return fmt.Errorf("loading seal key: %w", err)
	}

	body, _ := json.Marshal(map[string]interface{}{"refs": refs})
	resp, err := apiRequestWithHeaders("POST", "/v1/resolve", strings.NewReader(string(body)), sealHeaders(sealPrivKey))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	values := make(map[string]string)
	var errs map[string]string
	var errCodes map[string]refDenial
	if sealPrivKey != nil {
		var result struct {
			SealedValues map[string]interface{} `json:"sealed_values"`
			Errors       map[string]string      `json:"errors"`
			ErrorCodes   map[string]refDenial   `json:"error_codes"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
		errs = result.Errors
		errCodes = result.ErrorCodes
		for ref, raw := range result.SealedValues {
			if envMap, ok := raw.(map[string]interface{}); ok {
				if envRef, _ := envMap["ref"].(string); envRef != ref {
					return fmt.Errorf("sealed envelope ref mismatch: map key %q, envelope %q", ref, envRef)
				}
			}
			val, err := decryptSealedValue(raw, sealPrivKey)
			if err != nil {
				return fmt.Errorf("decrypting %s: %w", displayRef(ref), err)
			}
			values[ref] = val
		}
	} else {
		var result struct {
			Values     map[string]string    `json:"values"`
			Errors     map[string]string    `json:"errors"`
			ErrorCodes map[string]refDenial `json:"error_codes"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
		values = result.Values
		errs = result.Errors
		errCodes = result.ErrorCodes
	}

	out := openClawExecProviderResponse{
		ProtocolVersion: 1,
		Values:          make(map[string]string),
	}
	for _, id := range req.IDs {
		ref := openClawIDToPhoenixRef(id)
		if errMsg, ok := errs[ref]; ok {
			if out.Errors == nil {
				out.Errors = make(map[string]openClawExecProviderError)
			}
			out.Errors[id] = openClawExecProviderError{Message: formatRefError(ref, errMsg, errCodes)}
			continue
		}
		val, ok := values[ref]
		if !ok {
			if out.Errors == nil {
				out.Errors = make(map[string]openClawExecProviderError)
			}
			out.Errors[id] = openClawExecProviderError{Message: "no value returned by Phoenix"}
			continue
		}
		out.Values[id] = val
	}

	enc := json.NewEncoder(os.Stdout)
	return enc.Encode(out)
}

func cmdResolve(args []string) error {
	if len(args) == 1 && args[0] == "--stdin-json" {
		return cmdOpenClawExecProvider(nil)
	}
	for _, arg := range args {
		if arg == "--stdin-json" {
			return fmt.Errorf("usage: phoenix resolve --stdin-json")
		}
	}

	if err := requireAuth(); err != nil {
		return err
	}

	var refs []string
	for _, arg := range args {
		if arg == "--signed" {
			exitRemoved("phoenix resolve --signed", removedCommands["resolve --signed"])
		}
		refs = append(refs, arg)
	}

	if len(refs) < 1 {
		return fmt.Errorf("usage: phoenix resolve <phoenix://ns/secret> [ref...]")
	}

	sealPrivKey, err := loadSealKeyForRequest()
	if err != nil {
		return fmt.Errorf("loading seal key: %w", err)
	}

	bodyMap := map[string]interface{}{"refs": refs}
	body, _ := json.Marshal(bodyMap)
	resp, err := apiRequestWithHeaders("POST", "/v1/resolve", strings.NewReader(string(body)), sealHeaders(sealPrivKey))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	// Decode response — handle sealed or plaintext
	var values map[string]string
	var errs map[string]string
	var errCodes map[string]refDenial

	if sealPrivKey != nil {
		var result struct {
			SealedValues map[string]interface{} `json:"sealed_values"`
			Errors       map[string]string      `json:"errors"`
			ErrorCodes   map[string]refDenial   `json:"error_codes"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
		errs = result.Errors
		errCodes = result.ErrorCodes
		values = make(map[string]string)
		for ref, raw := range result.SealedValues {
			if envMap, ok := raw.(map[string]interface{}); ok {
				if envRef, _ := envMap["ref"].(string); envRef != ref {
					return fmt.Errorf("sealed envelope ref mismatch: map key %q, envelope %q", ref, envRef)
				}
			}
			val, err := decryptSealedValue(raw, sealPrivKey)
			if err != nil {
				return fmt.Errorf("decrypting %s: %w", displayRef(ref), err)
			}
			values[ref] = val
		}
	} else {
		var result struct {
			Values     map[string]string    `json:"values"`
			Errors     map[string]string    `json:"errors"`
			ErrorCodes map[string]refDenial `json:"error_codes"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
		values = result.Values
		errs = result.Errors
		errCodes = result.ErrorCodes
	}

	// Single ref: output raw value for piping
	if len(refs) == 1 {
		if errMsg, ok := errs[refs[0]]; ok {
			return fmt.Errorf("%s: %s", refs[0], formatRefError(refs[0], errMsg, errCodes))
		}
		if _, ok := values[refs[0]]; !ok {
			return fmt.Errorf("%s: no value returned by server", refs[0])
		}
		fmt.Print(values[refs[0]])
		return nil
	}

	// Multiple refs: output ref → value pairs
	var hasErr bool
	for _, ref := range refs {
		if errMsg, ok := errs[ref]; ok {
			fmt.Fprintf(os.Stderr, "%s: error: %s\n", ref, formatRefError(ref, errMsg, errCodes))
			hasErr = true
			continue
		}
		if _, ok := values[ref]; !ok {
			fmt.Fprintf(os.Stderr, "%s: error: no value returned by server\n", ref)
			hasErr = true
			continue
		}
		fmt.Printf("%s\t%s\n", ref, values[ref])
	}
	if hasErr {
		return fmt.Errorf("some references failed to resolve")
	}
	return nil
}

func cmdExec(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}

	sealPrivKey, sealErr := loadSealKeyForRequest()
	if sealErr != nil {
		return fmt.Errorf("loading seal key: %w", sealErr)
	}

	// Parse --env flags and --output-env before "--", command after "--"
	var envMappings []string
	var cmdArgs []string
	var outputEnvPath string
	var timeoutStr string
	var maskEnv, redactOutput bool
	seenSep := false

	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			cmdArgs = args[i+1:]
			seenSep = true
			break
		}
		switch args[i] {
		case "--env", "-e":
			i++
			if i < len(args) {
				envMappings = append(envMappings, args[i])
			}
		case "--output-env":
			i++
			if i < len(args) {
				outputEnvPath = args[i]
			}
		case "--timeout":
			i++
			if i >= len(args) {
				return fmt.Errorf("--timeout requires a duration value (e.g. 5s, 30s)")
			}
			timeoutStr = args[i]
		case "--mask-env":
			maskEnv = true
		case "--redact-output":
			redactOutput = true
		}
	}

	if outputEnvPath == "" && (!seenSep || len(cmdArgs) == 0) {
		return fmt.Errorf("usage: phoenix exec --env KEY=phoenix://ns/secret [--output-env <path>] [--timeout <duration>] [--mask-env] [--redact-output] -- <command> [args...]")
	}
	if redactOutput && outputEnvPath != "" {
		return fmt.Errorf("--redact-output runs a command; it cannot be combined with --output-env")
	}
	if len(envMappings) == 0 {
		return fmt.Errorf("at least one --env mapping is required")
	}

	// Parse env mappings: KEY=phoenix://ns/secret
	type envMapping struct {
		envVar string
		ref    string
	}
	var mappings []envMapping
	var refs []string

	for _, m := range envMappings {
		parts := strings.SplitN(m, "=", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("invalid env mapping %q: expected KEY=phoenix://ns/secret", m)
		}
		if !strings.HasPrefix(parts[1], "phoenix://") {
			return fmt.Errorf("invalid env mapping %q: value must be a phoenix:// reference", m)
		}
		mappings = append(mappings, envMapping{envVar: parts[0], ref: parts[1]})
		refs = append(refs, parts[1])
	}

	// Resolve all refs in one batch
	var timeout time.Duration
	if timeoutStr != "" {
		var parseErr error
		timeout, parseErr = time.ParseDuration(timeoutStr)
		if parseErr != nil {
			return fmt.Errorf("invalid --timeout value %q: %w", timeoutStr, parseErr)
		}
		if timeout <= 0 {
			return fmt.Errorf("--timeout must be a positive duration (e.g. 5s), got %s", timeout)
		}
	}

	body, _ := json.Marshal(map[string]interface{}{"refs": refs})
	hdrs := sealHeaders(sealPrivKey)
	var resp *http.Response
	var err error
	if timeout > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		url := serverURL + "/v1/resolve"
		req, reqErr := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(body)))
		if reqErr != nil {
			return fmt.Errorf("building request: %w", reqErr)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range hdrs {
			req.Header.Set(k, v)
		}
		resp, err = httpClient.Do(req)
	} else {
		resp, err = apiRequestWithHeaders("POST", "/v1/resolve", strings.NewReader(string(body)), hdrs)
	}
	if err != nil {
		return fmt.Errorf("resolve request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	// Decode response — handle sealed or plaintext
	resolvedValues := make(map[string]string)
	var resolveErrors map[string]string
	var resolveErrorCodes map[string]refDenial

	if sealPrivKey != nil {
		var result struct {
			SealedValues map[string]interface{} `json:"sealed_values"`
			Errors       map[string]string      `json:"errors"`
			ErrorCodes   map[string]refDenial   `json:"error_codes"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("decoding resolve response: %w", err)
		}
		resolveErrors = result.Errors
		resolveErrorCodes = result.ErrorCodes
		for ref, raw := range result.SealedValues {
			if envMap, ok := raw.(map[string]interface{}); ok {
				if envRef, _ := envMap["ref"].(string); envRef != ref {
					return fmt.Errorf("sealed envelope ref mismatch: map key %q, envelope %q", ref, envRef)
				}
			}
			val, err := decryptSealedValue(raw, sealPrivKey)
			if err != nil {
				return fmt.Errorf("decrypting %s: %w", displayRef(ref), err)
			}
			resolvedValues[ref] = val
		}
	} else {
		var result struct {
			Values     map[string]string    `json:"values"`
			Errors     map[string]string    `json:"errors"`
			ErrorCodes map[string]refDenial `json:"error_codes"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("decoding resolve response: %w", err)
		}
		resolvedValues = result.Values
		resolveErrors = result.Errors
		resolveErrorCodes = result.ErrorCodes
	}

	// Check for resolution errors
	if len(resolveErrors) > 0 {
		for ref, errMsg := range resolveErrors {
			fmt.Fprintf(os.Stderr, "error resolving %s: %s\n", displayRef(ref), formatRefError(ref, errMsg, resolveErrorCodes))
		}
		return fmt.Errorf("failed to resolve %d reference(s)", len(resolveErrors))
	}

	// If --output-env is set, write resolved env to file and exit
	if outputEnvPath != "" {
		var lines []string
		for _, m := range mappings {
			val, ok := resolvedValues[m.ref]
			if !ok {
				return fmt.Errorf("no value returned for %s", m.ref)
			}
			lines = append(lines, m.envVar+"="+val)
		}
		content := strings.Join(lines, "\n") + "\n"
		if err := os.WriteFile(outputEnvPath, []byte(content), 0600); err != nil {
			return fmt.Errorf("writing env file: %w", err)
		}
		fmt.Printf("wrote %d env vars to %s\n", len(mappings), outputEnvPath)
		return nil
	}

	// Build env: inherit current env but strip Phoenix credentials
	// to prevent the child from escalating access beyond mapped refs.
	env := childEnv(os.Environ(), maskEnv)
	var values []redactValue
	for _, m := range mappings {
		val, ok := resolvedValues[m.ref]
		if !ok {
			return fmt.Errorf("no value returned for %s", m.ref)
		}
		env = append(env, m.envVar+"="+val)
		values = append(values, redactValue{Name: m.envVar, Value: val})
	}

	binary, err := exec.LookPath(cmdArgs[0])
	if err != nil {
		return fmt.Errorf("command not found: %s", cmdArgs[0])
	}
	if redactOutput {
		// Stay as the parent and filter the child's output (redact.go).
		for _, v := range values {
			if len(v.Value) < minRedactLen {
				fmt.Fprintf(os.Stderr, "phoenix exec: warning: %s is shorter than %d bytes and is not redacted\n", v.Name, minRedactLen)
			}
		}
		code, runErr := runRedacted(binary, cmdArgs, env, values, os.Stdin, os.Stdout, os.Stderr)
		if runErr != nil {
			return runErr
		}
		if code != 0 {
			return exitCodeError(code)
		}
		return nil
	}
	// Exec into the child process (replaces current process)
	return syscall.Exec(binary, cmdArgs, env)
}

func cmdRotateMaster() error {
	if err := requireAuth(); err != nil {
		return err
	}

	resp, err := apiRequest("POST", "/v1/rotate-master", nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	var result struct {
		Rotated int    `json:"rotated"`
		Backup  string `json:"backup"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	fmt.Printf("Master key rotated successfully\n")
	fmt.Printf("  Namespaces re-wrapped: %d\n", result.Rotated)
	fmt.Printf("  Old key backed up to: %s\n", result.Backup)
	return nil
}

// --- Seal key helpers ---

// loadSealKey loads the seal private key from PHOENIX_SEAL_KEY env var.
// Returns nil, nil if the env var is not set (unsealed mode).
func loadSealKey() (*[32]byte, error) {
	keyPath := os.Getenv("PHOENIX_SEAL_KEY")
	if keyPath == "" {
		return nil, nil
	}
	return crypto.LoadSealPrivateKey(keyPath)
}

// loadSealKeyForRequest loads the seal private key for normal CLI requests.
//
// For role-bound sessions, this includes the per-role session key location
// (~/.phoenix/session-seal-<role>.key) so request headers match session binding.
func loadSealKeyForRequest() (*[32]byte, error) {
	if role := os.Getenv("PHOENIX_ROLE"); role != "" {
		priv, _, err := ensureSealKey(role)
		if err != nil {
			return nil, err
		}
		return priv, nil
	}
	return loadSealKey()
}

// sealHeaders returns HTTP headers for sealed requests.
// Returns nil if no seal key is loaded.
func sealHeaders(privKey *[32]byte) map[string]string {
	if privKey == nil {
		return nil
	}
	pubKey := crypto.DeriveSealPublicKey(privKey)
	return map[string]string{
		"X-Phoenix-Seal-Key": crypto.EncodeSealKey(pubKey),
	}
}

// decryptSealedValue decrypts a sealed envelope from a raw JSON object.
func decryptSealedValue(raw interface{}, privKey *[32]byte) (string, error) {
	envJSON, err := json.Marshal(raw)
	if err != nil {
		return "", fmt.Errorf("marshaling sealed envelope: %w", err)
	}
	var env crypto.SealedEnvelope
	if err := json.Unmarshal(envJSON, &env); err != nil {
		return "", fmt.Errorf("parsing sealed envelope: %w", err)
	}
	payload, err := crypto.OpenSealedEnvelope(&env, privKey)
	if err != nil {
		return "", fmt.Errorf("decrypting sealed value: %w", err)
	}
	return payload.Value, nil
}

// --- Keypair commands ---

func cmdKeypairGenerate(args []string) error {
	var name, output string
	force := false
	i := 0
	if i < len(args) && !strings.HasPrefix(args[i], "-") {
		name = args[i]
		i++
	}
	for i < len(args) {
		switch args[i] {
		case "-o", "--output":
			i++
			if i < len(args) {
				output = args[i]
			} else {
				return fmt.Errorf("usage: phoenix keypair generate <agent-name> [--output <path>] [--force]")
			}
		case "--force":
			force = true
		}
		i++
	}

	if name == "" {
		return fmt.Errorf("usage: phoenix keypair generate <agent-name> [--output <path>] [--force]")
	}
	if output != "" {
		if output == string(os.PathSeparator) || strings.HasSuffix(output, string(os.PathSeparator)) {
			return fmt.Errorf("usage: output must be a file path, not a directory: %q", output)
		}
		if fi, err := os.Stat(output); err == nil && fi.IsDir() {
			return fmt.Errorf("usage: output must be a file path, not a directory: %q", output)
		}
	}

	if err := requireAuth(); err != nil {
		return err
	}

	urlPath := "/v1/keypair"
	if force {
		urlPath += "?force=true"
	}

	body, _ := json.Marshal(map[string]string{"agent_name": name})
	resp, err := apiRequest("POST", urlPath, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	var result struct {
		AgentName      string `json:"agent_name"`
		SealPublicKey  string `json:"seal_public_key"`
		SealPrivateKey string `json:"seal_private_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	// Determine output path
	if output == "" {
		home, _ := os.UserHomeDir()
		dir := filepath.Join(home, ".config", "phoenix", "keys")
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("creating key directory: %w", err)
		}
		output = filepath.Join(dir, name+".seal.key")
	}

	// Ensure parent directory has correct permissions
	dir := filepath.Dir(output)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating key directory: %w", err)
	}

	if err := os.WriteFile(output, []byte(result.SealPrivateKey), 0600); err != nil {
		return fmt.Errorf("writing private key: %w", err)
	}
	// Harden permissions even if the file already existed with weaker mode
	if err := os.Chmod(output, 0600); err != nil {
		return fmt.Errorf("setting key file permissions: %w", err)
	}

	fmt.Printf("Seal keypair generated for agent %q\n", name)
	fmt.Printf("  private key: %s\n", output)
	fmt.Printf("  public key:  %s\n", result.SealPublicKey)
	fmt.Println()
	fmt.Printf("Set PHOENIX_SEAL_KEY=%s to enable sealed mode\n", output)
	return nil
}

func cmdKeypairShow(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}

	if len(args) < 1 {
		return fmt.Errorf("usage: phoenix keypair show <agent-name>")
	}
	name := args[0]

	resp, err := apiRequest("GET", "/v1/agents/"+name+"/seal-key", nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	var result struct {
		AgentName     string `json:"agent_name"`
		SealPublicKey string `json:"seal_public_key"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	fmt.Printf("Agent: %s\n", result.AgentName)
	if result.SealPublicKey == "" {
		fmt.Println("Seal key: (none)")
	} else {
		fmt.Printf("Seal key: %s\n", result.SealPublicKey)
	}
	return nil
}

func cmdPolicyShow(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: phoenix policy show <secret-path>")
	}
	path := args[0]

	policyPath := os.Getenv("PHOENIX_POLICY")
	if policyPath == "" {
		return fmt.Errorf("PHOENIX_POLICY environment variable not set")
	}

	data, err := os.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("reading policy file: %w", err)
	}

	pe, err := policy.Load(data)
	if err != nil {
		return fmt.Errorf("loading policy: %w", err)
	}
	if len(pe.Rules()) == 0 {
		fmt.Printf("No attestation policies configured.\n")
		return nil
	}

	rule, pattern := pe.RuleFor(path)
	if rule == nil {
		fmt.Printf("No attestation policy matches path %q\n", path)
		return nil
	}
	fmt.Printf("Pattern: %s\n", pattern)
	printPolicyRule(rule)
	return nil
}

func printPolicyRule(rule *policy.Rule) {
	if len(rule.AllowedIPs) > 0 {
		b, _ := json.Marshal(rule.AllowedIPs)
		fmt.Printf("  source_ip: %s\n", string(b))
	}
	if rule.RequireSealed {
		fmt.Printf("  require_sealed: true\n")
	}
}

func cmdPolicyTest(args []string) error {
	var agent, ip, path string
	i := 0
	for i < len(args) {
		switch args[i] {
		case "-a", "--agent":
			i++
			if i < len(args) {
				agent = args[i]
			}
		case "-i", "--ip":
			i++
			if i < len(args) {
				ip = args[i]
			}
		case "-t", "--time":
			exitRemoved("phoenix policy test --time", removedCommands["policy test --time"])
		default:
			if path == "" {
				path = args[i]
			}
		}
		i++
	}

	if path == "" {
		return fmt.Errorf("usage: phoenix policy test --agent <name> --ip <ip> <secret-path>")
	}

	policyPath := os.Getenv("PHOENIX_POLICY")
	if policyPath == "" {
		return fmt.Errorf("PHOENIX_POLICY environment variable not set")
	}

	// Load policy using the real engine for full evaluation
	pe, err := policy.LoadFile(policyPath)
	if err != nil {
		return fmt.Errorf("loading policy: %w", err)
	}

	// Show matching rule info
	rule, pattern := pe.RuleFor(path)

	fmt.Printf("Testing attestation for path %q\n", path)
	if agent != "" {
		fmt.Printf("  Agent: %s\n", agent)
	}
	if ip != "" {
		fmt.Printf("  Source IP: %s\n", ip)
	}
	fmt.Println()

	if rule == nil {
		fmt.Printf("No attestation policy matches path %q — access allowed by default.\n", path)
		return nil
	}

	fmt.Printf("Matched policy: %s\n", pattern)

	// Show rule details
	if len(rule.AllowedIPs) > 0 {
		if ip == "" {
			fmt.Printf("  [SKIP] source_ip: %v (no --ip provided)\n", rule.AllowedIPs)
		} else {
			fmt.Printf("  [INFO] source_ip: %v (evaluated by engine)\n", rule.AllowedIPs)
		}
	}

	testCtx := &policy.RequestContext{SourceIP: ip}

	err = pe.Evaluate(path, testCtx)
	if err != nil {
		fmt.Printf("  Result: FAIL — %v\n", err)
		return nil
	}

	fmt.Printf("  Result: PASS (testable checks passed)\n")
	return nil
}

const defaultAgentSocket = "/tmp/phoenix-agent.sock"

func cmdAgentSockAttest(args []string) error {
	socketPath := defaultAgentSocket
	agentName := ""

	i := 0
	for i < len(args) {
		switch args[i] {
		case "-s", "--socket":
			i++
			if i < len(args) {
				socketPath = args[i]
			}
		case "-a", "--agent":
			i++
			if i < len(args) {
				agentName = args[i]
			}
		default:
			if agentName == "" {
				agentName = args[i]
			}
		}
		i++
	}

	// Connect to the Unix socket
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("connecting to agent socket %s: %w", socketPath, err)
	}
	defer conn.Close()

	// Send attestation request
	req := struct {
		Agent string `json:"agent"`
	}{Agent: agentName}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return fmt.Errorf("sending attest request: %w", err)
	}

	// Read response
	var resp struct {
		OK   bool `json:"ok"`
		Peer *struct {
			PID        int32  `json:"pid"`
			UID        int32  `json:"uid"`
			GID        int32  `json:"gid"`
			BinaryPath string `json:"binary_path,omitempty"`
			BinaryHash string `json:"binary_hash,omitempty"`
		} `json:"peer,omitempty"`
		Error string `json:"error,omitempty"`
	}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return fmt.Errorf("reading attest response: %w", err)
	}

	if !resp.OK {
		return fmt.Errorf("attestation failed: %s", resp.Error)
	}

	if resp.Peer == nil {
		return fmt.Errorf("attestation returned no peer info")
	}

	fmt.Printf("Attestation OK\n")
	fmt.Printf("  PID:         %d\n", resp.Peer.PID)
	fmt.Printf("  UID:         %d\n", resp.Peer.UID)
	fmt.Printf("  GID:         %d\n", resp.Peer.GID)
	if resp.Peer.BinaryPath != "" {
		fmt.Printf("  Binary:      %s\n", resp.Peer.BinaryPath)
	}
	if resp.Peer.BinaryHash != "" {
		fmt.Printf("  Binary hash: %s\n", resp.Peer.BinaryHash)
	}
	return nil
}

// tokenCacheEntry is one cached session token (key: sessionCacheKey).
type tokenCacheEntry struct {
	Token     string    `json:"token"`
	Agent     string    `json:"agent"`
	ExpiresAt time.Time `json:"expires_at"`
}

// tokenCachePath returns the path to the token cache file.
func tokenCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".phoenix", "token-cache.json")
}

// loadTokenCache reads cached tokens from disk.
func loadTokenCache() (map[string]*tokenCacheEntry, error) {
	path := tokenCachePath()
	if path == "" {
		return make(map[string]*tokenCacheEntry), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return make(map[string]*tokenCacheEntry), nil
	}
	var cache map[string]*tokenCacheEntry
	if err := json.Unmarshal(data, &cache); err != nil {
		return make(map[string]*tokenCacheEntry), nil
	}
	return cache, nil
}

// saveTokenCache writes cached tokens to disk.
func saveTokenCache(cache map[string]*tokenCacheEntry) error {
	path := tokenCachePath()
	if path == "" {
		return fmt.Errorf("cannot determine home directory for token cache")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// getCachedToken returns a valid cached token for the agent, or empty string if expired/missing.
func getCachedToken(agentName string, ttlBuffer time.Duration) string {
	cache, _ := loadTokenCache()
	entry, ok := cache[agentName]
	if !ok {
		return ""
	}
	// Check if token is still valid with buffer
	if time.Now().Add(ttlBuffer).After(entry.ExpiresAt) {
		return ""
	}
	return entry.Token
}

// sessionCacheKey returns a cache key scoped to both role and server URL,
// preventing collisions when the same role name is used across different servers.
func sessionCacheKey(role string) string {
	h := sha256pkg.Sum256([]byte(serverURL))
	return fmt.Sprintf("session:%s@%.8x", role, h[:4])
}

// getCachedSessionToken returns a valid cached session token for the role, or empty string.
func getCachedSessionToken(role string, ttlBuffer time.Duration) string {
	return getCachedToken(sessionCacheKey(role), ttlBuffer)
}

// cacheSessionToken stores a session token in the cache.
func cacheSessionToken(role, tok string, expiresAt time.Time) {
	cache, _ := loadTokenCache()
	key := sessionCacheKey(role)
	cache[key] = &tokenCacheEntry{
		Token:     tok,
		Agent:     "session:" + role,
		ExpiresAt: expiresAt,
	}
	if err := saveTokenCache(cache); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not cache session token: %v\n", err)
	}
}

// ensureSealKey resolves the seal key for session binding.
// Priority: PHOENIX_SEAL_KEY env > ~/.phoenix/session-seal-<role>.key > none.
func ensureSealKey(role string) (*[32]byte, string, error) {
	// Check env first
	envPath := os.Getenv("PHOENIX_SEAL_KEY")
	if envPath != "" {
		priv, err := crypto.LoadSealPrivateKey(envPath)
		if err != nil {
			return nil, "", fmt.Errorf("loading PHOENIX_SEAL_KEY: %w", err)
		}
		pub := crypto.DeriveSealPublicKey(priv)
		return priv, crypto.EncodeSealKey(pub), nil
	}

	// Check per-role key file. If the home directory cannot be determined,
	// treat it the same as no key file: mint without seal binding.
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, "", nil
	}
	keyDir := filepath.Join(home, ".phoenix")
	keyPath := filepath.Join(keyDir, "session-seal-"+role+".key")

	if _, statErr := os.Stat(keyPath); statErr == nil {
		priv, loadErr := crypto.LoadSealPrivateKey(keyPath)
		if loadErr != nil {
			return nil, "", fmt.Errorf("loading seal key %s: %w", keyPath, loadErr)
		}
		pub := crypto.DeriveSealPublicKey(priv)
		return priv, crypto.EncodeSealKey(pub), nil
	}

	// No explicit key configured — mint without seal binding.
	// To enable sealed sessions, set PHOENIX_SEAL_KEY or place a key at
	// ~/.phoenix/session-seal-<role>.key.
	return nil, "", nil
}

// mintSessionViaAPI calls POST /v1/session/mint and returns the session token.
func mintSessionViaAPI(role, sealPubKeyB64 string) (string, time.Time, error) {
	body := map[string]string{"role": role}
	if sealPubKeyB64 != "" {
		body["seal_public_key"] = sealPubKeyB64
	}
	bodyBytes, _ := json.Marshal(body)

	resp, err := apiRequest("POST", "/v1/session/mint", strings.NewReader(string(bodyBytes)))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("session mint request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		if d, ok := parseServerDenial(respBody); ok {
			return "", time.Time{}, fmt.Errorf("session mint: %s", formatDenial(d, "  "))
		} else if d.Error != "" {
			return "", time.Time{}, fmt.Errorf("session mint: %s", cleanServerText(d.Error))
		}
		return "", time.Time{}, fmt.Errorf("session mint: HTTP %d", resp.StatusCode)
	}

	var result struct {
		SessionToken string `json:"session_token"`
		ExpiresAt    string `json:"expires_at"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", time.Time{}, fmt.Errorf("parsing mint response: %w", err)
	}
	exp, err := time.Parse(time.RFC3339, result.ExpiresAt)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("parsing expires_at: %w", err)
	}
	return result.SessionToken, exp, nil
}

// autoMintSession checks PHOENIX_ROLE and auto-mints a session token.
func autoMintSession() error {
	role := os.Getenv("PHOENIX_ROLE")
	if role == "" {
		return fmt.Errorf("PHOENIX_ROLE not set")
	}

	// Check cache first. Keep a valid cached session token as long as it is still
	// valid; renewal is handled separately when remaining lifetime is low.
	if cached := getCachedSessionToken(role, 0); cached != "" {
		tokenMu.Lock()
		token = cached
		tokenMu.Unlock()
		return nil
	}

	// Need bootstrap auth to mint
	tokenMu.RLock()
	noToken := token == ""
	tokenMu.RUnlock()
	if noToken {
		return fmt.Errorf("PHOENIX_ROLE=%s set but no bootstrap auth available (set PHOENIX_TOKEN)", role)
	}

	// Load or generate seal key
	_, sealPubB64, err := ensureSealKey(role)
	if err != nil {
		// Non-fatal: mint without seal key
		fmt.Fprintf(os.Stderr, "warning: seal key unavailable: %v\n", err)
		sealPubB64 = ""
	}

	sessionToken, expiresAt, err := mintSessionViaAPI(role, sealPubB64)
	if err != nil {
		return err
	}

	cacheSessionToken(role, sessionToken, expiresAt)
	tokenMu.Lock()
	token = sessionToken
	tokenMu.Unlock()
	return nil
}

// renewSessionViaAPI calls POST /v1/session/renew with the current session token.
func renewSessionViaAPI() (string, time.Time, error) {
	resp, err := apiRequest("POST", "/v1/session/renew", strings.NewReader("{}"))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("session renew request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		if d, ok := parseServerDenial(respBody); ok {
			return "", time.Time{}, fmt.Errorf("session renew: %s", formatDenial(d, "  "))
		}
		return "", time.Time{}, fmt.Errorf("session renew: HTTP %d", resp.StatusCode)
	}

	var result struct {
		SessionToken string `json:"session_token"`
		ExpiresAt    string `json:"expires_at"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", time.Time{}, fmt.Errorf("parsing renew response: %w", err)
	}
	exp, err := time.Parse(time.RFC3339, result.ExpiresAt)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("parsing expires_at: %w", err)
	}
	return result.SessionToken, exp, nil
}

// renewSessionIfNeeded checks if the current session token is nearing expiry
// and renews it if so (within 10 minutes of expiry).
func renewSessionIfNeeded() {
	if !strings.HasPrefix(token, "phxs_") {
		return
	}
	role := os.Getenv("PHOENIX_ROLE")
	if role == "" {
		return
	}

	// Check if cached token is nearing expiry
	cache, _ := loadTokenCache()
	entry, ok := cache[sessionCacheKey(role)]
	if !ok {
		return
	}
	if time.Until(entry.ExpiresAt) > 10*time.Minute {
		return // still plenty of time
	}

	newToken, newExpiry, err := renewSessionViaAPI()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: session renewal failed: %v\n", err)
		return
	}

	cacheSessionToken(role, newToken, newExpiry)
	tokenMu.Lock()
	token = newToken
	tokenMu.Unlock()
}

// emergencyAuditEntry is the structured audit log entry for emergency access.
type emergencyAuditEntry struct {
	Timestamp string `json:"ts"`
	Agent     string `json:"agent"`
	Action    string `json:"action"`
	Path      string `json:"path"`
	Status    string `json:"status"`
	IP        string `json:"ip"`
}

func cmdEmergencyGet(args []string) error {
	var dataDir, secretPath string
	var passphraseStdin, confirmed bool

	i := 0
	for i < len(args) {
		switch args[i] {
		case "--data-dir":
			i++
			if i < len(args) {
				dataDir = args[i]
			}
		case "--passphrase-stdin":
			passphraseStdin = true
		case "--confirm":
			confirmed = true
		default:
			if secretPath == "" {
				secretPath = args[i]
			}
		}
		i++
	}

	if secretPath == "" || dataDir == "" {
		return fmt.Errorf("usage: phoenix emergency get <path> --data-dir <dir> [--confirm] [--passphrase-stdin]")
	}

	// Reject wildcards / batch patterns
	if strings.Contains(secretPath, "*") || strings.HasSuffix(secretPath, "/") {
		return fmt.Errorf("emergency access is single-secret only — no wildcards or prefixes")
	}

	// Confirmation is always required — either via TTY prompt or --confirm flag
	fmt.Fprintf(os.Stderr, "\n*** EMERGENCY ACCESS ***\n")
	fmt.Fprintf(os.Stderr, "Secret:   %s\n", secretPath)
	fmt.Fprintf(os.Stderr, "Data dir: %s\n", dataDir)
	fmt.Fprintf(os.Stderr, "This bypasses the server and will be logged to the audit trail.\n")

	if !confirmed {
		fmt.Fprintf(os.Stderr, "Continue? [y/N] ")
		reader := bufio.NewReader(os.Stdin)
		confirmStr, _ := reader.ReadString('\n')
		confirmStr = strings.TrimSpace(strings.ToLower(confirmStr))
		if confirmStr != "y" && confirmStr != "yes" {
			return fmt.Errorf("aborted")
		}
	} else {
		fmt.Fprintln(os.Stderr, "Confirmed via --confirm flag.")
	}

	keyPath := filepath.Join(dataDir, "master.key")
	storePath := filepath.Join(dataDir, "store.json")
	auditPath := filepath.Join(dataDir, "audit.log")

	// Load master key
	key, err := crypto.LoadMasterKey(keyPath)
	if err == crypto.ErrPassphraseRequired {
		passphrase, ppErr := crypto.ReadPassphrase(passphraseStdin)
		if ppErr != nil {
			return fmt.Errorf("master key is passphrase-protected: %w", ppErr)
		}
		key, err = crypto.LoadMasterKeyWithPassphrase(keyPath, passphrase)
		if err != nil {
			return fmt.Errorf("decrypting master key: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("loading master key: %w", err)
	}

	// Open store directly
	provider, err := crypto.NewFileKeyProvider(key)
	if err != nil {
		return fmt.Errorf("creating key provider: %w", err)
	}

	s, err := store.NewWithProvider(storePath, provider)
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}

	secret, err := s.Get(secretPath)
	if err != nil {
		return fmt.Errorf("reading secret: %w", err)
	}

	// Append structured audit entry
	entry := emergencyAuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Agent:     "emergency-local",
		Action:    "read",
		Path:      secretPath,
		Status:    "allowed",
		IP:        "local",
	}
	auditJSON, _ := json.Marshal(entry)
	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write audit log: %v\n", err)
	} else {
		f.Write(auditJSON)
		f.Write([]byte("\n"))
		f.Close()
	}

	fmt.Fprintf(os.Stderr, "\n*** Access logged to %s ***\n", auditPath)

	// Print secret value to stdout
	fmt.Print(secret.Value)
	return nil
}

func handleError(resp *http.Response) error {
	return handleErrorForPath(resp, "")
}

// handleErrorForPath is handleError for a request about one secret path:
// a request_use denial then names the exact phoenix request command.
func handleErrorForPath(resp *http.Response, path string) error {
	body, _ := io.ReadAll(resp.Body)

	structured, ok := parseServerDenial(body)
	if ok {
		return fmt.Errorf("HTTP %d %s", resp.StatusCode, formatDenialForPath(structured, "  ", path))
	}
	if structured.Error != "" {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, cleanServerText(structured.Error))
	}
	return fmt.Errorf("HTTP %d", resp.StatusCode)
}

func cmdSessionList(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}

	queryParams := ""
	for i := 0; i < len(args); i++ {
		switch {
		case (args[i] == "--role" || args[i] == "-r") && i+1 < len(args):
			if queryParams == "" {
				queryParams = "?"
			} else {
				queryParams += "&"
			}
			queryParams += "role=" + url.QueryEscape(args[i+1])
			i++
		case (args[i] == "--agent" || args[i] == "-a") && i+1 < len(args):
			if queryParams == "" {
				queryParams = "?"
			} else {
				queryParams += "&"
			}
			queryParams += "agent=" + url.QueryEscape(args[i+1])
			i++
		}
	}

	resp, err := apiRequest("GET", "/v1/sessions"+queryParams, nil)
	if err != nil {
		return fmt.Errorf("listing sessions: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	var result struct {
		Sessions []struct {
			SessionID       string `json:"session_id"`
			Role            string `json:"role"`
			Agent           string `json:"agent"`
			BootstrapMethod string `json:"bootstrap_method"`
			SourceIP        string `json:"source_ip"`
			CreatedAt       string `json:"created_at"`
			ExpiresAt       string `json:"expires_at"`
		} `json:"sessions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	if len(result.Sessions) == 0 {
		fmt.Println("No active sessions.")
		return nil
	}

	fmt.Printf("%-36s  %-10s  %-12s  %-20s  %-20s  %-15s\n",
		"SESSION_ID", "ROLE", "AGENT", "CREATED", "EXPIRES", "SOURCE_IP")
	for _, s := range result.Sessions {
		fmt.Printf("%-36s  %-10s  %-12s  %-20s  %-20s  %-15s\n",
			s.SessionID, s.Role, s.Agent, s.CreatedAt, s.ExpiresAt, s.SourceIP)
	}
	return nil
}

func cmdSessionInfo(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: phoenix sessions info <session-id>")
	}
	if err := requireAuth(); err != nil {
		return err
	}

	sessionID := args[0]
	resp, err := apiRequest("GET", "/v1/sessions/"+sessionID, nil)
	if err != nil {
		return fmt.Errorf("fetching session: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	var sess struct {
		SessionID       string   `json:"session_id"`
		Role            string   `json:"role"`
		Agent           string   `json:"agent"`
		Namespaces      []string `json:"namespaces"`
		Actions         []string `json:"actions"`
		BootstrapMethod string   `json:"bootstrap_method"`
		SourceIP        string   `json:"source_ip"`
		CreatedAt       string   `json:"created_at"`
		ExpiresAt       string   `json:"expires_at"`
		Revoked         bool     `json:"revoked"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&sess); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	fmt.Printf("Session ID:       %s\n", sess.SessionID)
	fmt.Printf("Role:             %s\n", sess.Role)
	fmt.Printf("Agent:            %s\n", sess.Agent)
	fmt.Printf("Namespaces:       %s\n", strings.Join(sess.Namespaces, ", "))
	fmt.Printf("Actions:          %s\n", strings.Join(sess.Actions, ", "))
	fmt.Printf("Bootstrap Method: %s\n", sess.BootstrapMethod)
	fmt.Printf("Source IP:        %s\n", sess.SourceIP)
	fmt.Printf("Created At:       %s\n", sess.CreatedAt)
	fmt.Printf("Expires At:       %s\n", sess.ExpiresAt)
	fmt.Printf("Revoked:          %v\n", sess.Revoked)
	return nil
}

func cmdSessionRevoke(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: phoenix sessions revoke <session-id>")
	}
	if err := requireAuth(); err != nil {
		return err
	}

	sessionID := args[0]
	resp, err := apiRequest("POST", "/v1/sessions/"+sessionID+"/revoke", strings.NewReader("{}"))
	if err != nil {
		return fmt.Errorf("revoking session: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	var result struct {
		Status    string `json:"status"`
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	fmt.Printf("Session %s revoked.\n", result.SessionID)
	return nil
}

// readFromTTY reads a line from /dev/tty (works even when stdin is piped).
func readFromTTY() (string, error) {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		// Fallback to stdin
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			return scanner.Text(), nil
		}
		return "", fmt.Errorf("no input available")
	}
	defer tty.Close()
	scanner := bufio.NewScanner(tty)
	if scanner.Scan() {
		return scanner.Text(), nil
	}
	return "", fmt.Errorf("no input from /dev/tty")
}
