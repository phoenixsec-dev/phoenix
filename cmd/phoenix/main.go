// Phoenix CLI — client for the Phoenix secrets management API.
//
// Usage:
//
//	phoenix get <path>
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
//	phoenix exec --env KEY=phoenix://ns/secret [--output-env <path>] [--timeout <dur>] [--mask-env] -- <command> [args...]
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
	"crypto/ecdsa"
	cryptorand "crypto/rand"
	sha256pkg "crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/crypto"
	"github.com/phoenixsec/phoenix/internal/policy"
	"github.com/phoenixsec/phoenix/internal/store"
	"github.com/phoenixsec/phoenix/internal/version"
)

var (
	serverURL  string
	token      string
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
// Set PHOENIX_CLIENT_CERT and PHOENIX_CLIENT_KEY for mTLS client auth.
func buildHTTPClient() *http.Client {
	caCertPath := os.Getenv("PHOENIX_CA_CERT")
	clientCertPath := os.Getenv("PHOENIX_CLIENT_CERT")
	clientKeyPath := os.Getenv("PHOENIX_CLIENT_KEY")

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

	// Load client cert for mTLS if both cert and key are provided
	if clientCertPath != "" && clientKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: cannot load client cert: %v\n", err)
		} else {
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
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
			fmt.Fprintln(os.Stderr, "usage: phoenix agent <create|list>")
			os.Exit(1)
		}
		switch args[0] {
		case "create":
			err = cmdAgentCreate(args[1:])
		case "list":
			err = cmdAgentList()
		default:
			fmt.Fprintf(os.Stderr, "unknown agent subcommand: %s\n", args[0])
			os.Exit(1)
		}
	case "resolve":
		err = cmdResolve(args)
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
	case "token":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "usage: phoenix token <mint>")
			os.Exit(1)
		}
		switch args[0] {
		case "mint":
			err = cmdTokenMint(args[1:])
		default:
			fmt.Fprintf(os.Stderr, "unknown token subcommand: %s\n", args[0])
			os.Exit(1)
		}
	case "cert":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "usage: phoenix cert <issue>")
			os.Exit(1)
		}
		switch args[0] {
		case "issue":
			err = cmdCertIssue(args[1:])
		default:
			fmt.Fprintf(os.Stderr, "unknown cert subcommand: %s\n", args[0])
			os.Exit(1)
		}
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
			fmt.Fprintln(os.Stderr, "usage: phoenix agent-sock <attest|token|resolve>")
			os.Exit(1)
		}
		switch args[0] {
		case "attest":
			err = cmdAgentSockAttest(args[1:])
		case "token":
			err = cmdAgentSockToken(args[1:])
		case "resolve":
			err = cmdAgentSockResolve(args[1:])
		default:
			fmt.Fprintf(os.Stderr, "unknown agent-sock subcommand: %s\n", args[0])
			os.Exit(1)
		}
	case "mcp-server":
		httpAddr := ""
		mcpToken := os.Getenv("PHOENIX_MCP_TOKEN")
		for i := 0; i < len(args); i++ {
			switch {
			case args[i] == "--http" && i+1 < len(args):
				httpAddr = args[i+1]
				i++
			case strings.HasPrefix(args[i], "--http="):
				httpAddr = strings.TrimPrefix(args[i], "--http=")
			case args[i] == "--mcp-token" && i+1 < len(args):
				mcpToken = args[i+1]
				i++
			case strings.HasPrefix(args[i], "--mcp-token="):
				mcpToken = strings.TrimPrefix(args[i], "--mcp-token=")
			}
		}
		if httpAddr != "" {
			err = cmdMCPHTTP(httpAddr, mcpToken)
		} else {
			err = cmdMCP(args)
		}
	case "init":
		err = cmdInit(args)
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

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`phoenix — secrets management CLI

Usage:
  phoenix get <path>                          Read a secret
  phoenix set <path> -v <value> [-d desc]     Create/update a secret
  phoenix set <path> --value-stdin            Read secret value from stdin
  phoenix delete <path>                       Delete a secret
  phoenix list [prefix]                       List secret paths
  phoenix export <prefix> -f env              Export as .env format
  phoenix import <file> -p <prefix>           Import from .env file
  phoenix import --from 1password --vault <v> --prefix <p> [--item <name>] [--dry-run] [--skip-existing]
  phoenix audit [-n N] [-a agent] [-s time]   Query audit log
  phoenix agent create <name> -t <token> --acl <path:actions;path:actions> [--force]
  phoenix agent list                          List agents
  phoenix resolve [--signed] <ref> [ref...]     Resolve phoenix:// references to values
  phoenix exec --env K=phoenix://n/s -- cmd   Run command with resolved secrets as env
  phoenix exec --output-env <file> --env ...  Write resolved env to file (no exec)
  phoenix exec --timeout 5s --env ...         Fail if resolution exceeds duration
  phoenix exec --mask-env --env ...           Strip phoenix:// refs from child env
  phoenix verify <file> [--dry-run]           Check phoenix:// refs in file are resolvable
  phoenix status                              Show server health, secrets, agents, policy
  phoenix policy show <path>                  Show attestation requirements for path
  phoenix policy test -a <agent> -i <ip> [-t time] <p>  Dry-run attestation check
  phoenix token mint <agent>                   Mint a short-lived token for an agent
  phoenix rotate-master                       Rotate master encryption key
  phoenix cert issue <name> [-o dir]          Issue mTLS client certificate
  phoenix emergency get <path> --data-dir <d> [--confirm]  Break-glass offline secret retrieval
  phoenix agent-sock attest [--socket <path>]  Attest via local Unix socket agent
  phoenix agent-sock token --agent <name>      Mint/cache short-lived token via socket
  phoenix agent-sock resolve <ref...>          Resolve refs using cached socket token
  phoenix keypair generate <name> [-o dir]     Generate X25519 seal key pair
  phoenix keypair show <name>                 Show public key for a seal key pair
  phoenix mcp-server                          Run MCP server (stdio JSON-RPC)
  phoenix mcp-server --http :8080             Run MCP server (Streamable HTTP)
  phoenix init <dir>                          Initialize data directory

Environment:
  PHOENIX_SERVER       Server URL (default: http://127.0.0.1:9090)
  PHOENIX_TOKEN        Bearer token for authentication
  PHOENIX_CA_CERT      CA certificate for TLS verification
  PHOENIX_CLIENT_CERT  Client certificate for mTLS authentication
  PHOENIX_CLIENT_KEY   Client key for mTLS authentication
  PHOENIX_SEAL_KEY     Seal private key file (enables sealed mode)
  PHOENIX_POLICY       Path to attestation policy file (JSON)
  PHOENIX_TOOL         Tool/skill name for attestation (X-Phoenix-Tool header)
  PHOENIX_MCP_TOKEN    Bearer token for MCP HTTP client auth (--http mode)`)
}

// requireAuth checks that at least one auth method is configured
// (bearer token or mTLS client cert).
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

	// Check if mTLS client cert is configured
	if os.Getenv("PHOENIX_CLIENT_CERT") != "" && os.Getenv("PHOENIX_CLIENT_KEY") != "" {
		return nil
	}
	return fmt.Errorf("no auth configured: set PHOENIX_TOKEN, PHOENIX_ROLE, or PHOENIX_CLIENT_CERT + PHOENIX_CLIENT_KEY")
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
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	// Pass tool/skill attestation claim if set
	if tool := os.Getenv("PHOENIX_TOOL"); tool != "" {
		req.Header.Set("X-Phoenix-Tool", tool)
	}
	return httpClient.Do(req)
}

func cmdGet(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}
	if len(args) < 1 {
		return fmt.Errorf("usage: phoenix get <path>")
	}

	sealPrivKey, err := loadSealKey()
	if err != nil {
		return fmt.Errorf("loading seal key: %w", err)
	}

	resp, err := apiRequestWithHeaders("GET", "/v1/secrets/"+args[0], nil, sealHeaders(sealPrivKey))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return handleError(resp)
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

func cmdSet(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}

	var path, value, desc string
	var tags []string
	var valueStdin bool

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

	if path == "" || value == "" {
		return fmt.Errorf("usage: phoenix set <path> -v <value> [-d description] [--tags t1,t2]\n       phoenix set <path> --value-stdin [-d description] [--tags t1,t2]")
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

	prefix := ""
	if len(args) > 0 {
		prefix = args[0]
	}

	resp, err := apiRequest("GET", "/v1/secrets/"+prefix, nil)
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
	resp, err := apiRequest("GET", "/v1/secrets/"+prefix, nil)
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
		resp, err := apiRequest("GET", "/v1/secrets/"+path, nil)
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

func cmdResolve(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}

	var refs []string
	signed := false

	for i := 0; i < len(args); i++ {
		if args[i] == "--signed" {
			signed = true
		} else {
			refs = append(refs, args[i])
		}
	}

	if len(refs) < 1 {
		return fmt.Errorf("usage: phoenix resolve [--signed] <phoenix://ns/secret> [ref...]")
	}

	sealPrivKey, err := loadSealKey()
	if err != nil {
		return fmt.Errorf("loading seal key: %w", err)
	}

	var bodyMap map[string]interface{}

	if signed {
		// Signed resolve flow:
		// 1. Get nonce from /v1/challenge
		// 2. Build canonical payload
		// 3. Sign with client key
		// 4. Send signed resolve request
		challengeResp, err := apiRequest("POST", "/v1/challenge", nil)
		if err != nil {
			return fmt.Errorf("challenge request failed: %w", err)
		}
		defer challengeResp.Body.Close()
		if challengeResp.StatusCode != 200 {
			return fmt.Errorf("challenge failed: %w", handleError(challengeResp))
		}

		var challenge struct {
			Nonce string `json:"nonce"`
		}
		json.NewDecoder(challengeResp.Body).Decode(&challenge)

		timestamp := time.Now().UTC().Format(time.RFC3339)

		// Build canonical payload (sorted keys, sorted refs)
		sortedRefs := make([]string, len(refs))
		copy(sortedRefs, refs)
		sort.Strings(sortedRefs)
		canonical, _ := json.Marshal(map[string]interface{}{
			"nonce":     challenge.Nonce,
			"refs":      sortedRefs,
			"timestamp": timestamp,
		})

		// Sign with client key
		clientKeyPath := os.Getenv("PHOENIX_CLIENT_KEY")
		if clientKeyPath == "" {
			return fmt.Errorf("--signed requires PHOENIX_CLIENT_KEY for signing")
		}
		sig, err := signPayload(clientKeyPath, canonical)
		if err != nil {
			return fmt.Errorf("signing payload: %w", err)
		}

		bodyMap = map[string]interface{}{
			"refs":      refs,
			"nonce":     challenge.Nonce,
			"timestamp": timestamp,
			"signature": base64.StdEncoding.EncodeToString(sig),
		}
	} else {
		bodyMap = map[string]interface{}{
			"refs": refs,
		}
	}

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

	if sealPrivKey != nil {
		var result struct {
			SealedValues map[string]interface{} `json:"sealed_values"`
			Errors       map[string]string      `json:"errors"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
		errs = result.Errors
		values = make(map[string]string)
		for ref, raw := range result.SealedValues {
			if envMap, ok := raw.(map[string]interface{}); ok {
				if envRef, _ := envMap["ref"].(string); envRef != ref {
					return fmt.Errorf("sealed envelope ref mismatch: map key %q, envelope %q", ref, envRef)
				}
			}
			val, err := decryptSealedValue(raw, sealPrivKey)
			if err != nil {
				return fmt.Errorf("decrypting %s: %w", ref, err)
			}
			values[ref] = val
		}
	} else {
		var result struct {
			Values map[string]string `json:"values"`
			Errors map[string]string `json:"errors"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
		values = result.Values
		errs = result.Errors
	}

	// Single ref: output raw value for piping
	if len(refs) == 1 {
		if errMsg, ok := errs[refs[0]]; ok {
			return fmt.Errorf("%s: %s", refs[0], errMsg)
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
			fmt.Fprintf(os.Stderr, "%s: error: %s\n", ref, errMsg)
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

// signPayload signs data with the ECDSA private key at the given PEM path.
func signPayload(keyPath string, data []byte) ([]byte, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading key: %w", err)
	}

	key, err := parseECDSAPrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}

	hash := sha256Digest(data)
	return ecdsa.SignASN1(cryptorand.Reader, key, hash)
}

// sha256Digest returns the SHA-256 hash of data.
func sha256Digest(data []byte) []byte {
	h := sha256pkg.Sum256(data)
	return h[:]
}

// parseECDSAPrivateKey parses a PEM-encoded ECDSA private key.
func parseECDSAPrivateKey(pemData []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in key file")
	}

	// Try PKCS8 first (newer format), then EC (older format)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is not ECDSA")
		}
		return ecKey, nil
	}

	ecKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing ECDSA private key: %w", err)
	}
	return ecKey, nil
}

func cmdExec(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}

	sealPrivKey, sealErr := loadSealKey()
	if sealErr != nil {
		return fmt.Errorf("loading seal key: %w", sealErr)
	}

	// Parse --env flags and --output-env before "--", command after "--"
	var envMappings []string
	var cmdArgs []string
	var outputEnvPath string
	var timeoutStr string
	var maskEnv bool
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
		}
	}

	if outputEnvPath == "" && (!seenSep || len(cmdArgs) == 0) {
		return fmt.Errorf("usage: phoenix exec --env KEY=phoenix://ns/secret [--output-env <path>] [--timeout <duration>] [--mask-env] -- <command> [args...]")
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

	if sealPrivKey != nil {
		var result struct {
			SealedValues map[string]interface{} `json:"sealed_values"`
			Errors       map[string]string      `json:"errors"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("decoding resolve response: %w", err)
		}
		resolveErrors = result.Errors
		for ref, raw := range result.SealedValues {
			if envMap, ok := raw.(map[string]interface{}); ok {
				if envRef, _ := envMap["ref"].(string); envRef != ref {
					return fmt.Errorf("sealed envelope ref mismatch: map key %q, envelope %q", ref, envRef)
				}
			}
			val, err := decryptSealedValue(raw, sealPrivKey)
			if err != nil {
				return fmt.Errorf("decrypting %s: %w", ref, err)
			}
			resolvedValues[ref] = val
		}
	} else {
		var result struct {
			Values map[string]string `json:"values"`
			Errors map[string]string `json:"errors"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("decoding resolve response: %w", err)
		}
		resolvedValues = result.Values
		resolveErrors = result.Errors
	}

	// Check for resolution errors
	if len(resolveErrors) > 0 {
		for ref, errMsg := range resolveErrors {
			fmt.Fprintf(os.Stderr, "error resolving %s: %s\n", ref, errMsg)
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
	var env []string
	for _, e := range os.Environ() {
		key := e[:strings.IndexByte(e, '=')]
		switch key {
		case "PHOENIX_TOKEN", "PHOENIX_CLIENT_CERT", "PHOENIX_CLIENT_KEY",
			"PHOENIX_CA_CERT", "PHOENIX_SERVER", "PHOENIX_POLICY",
			"PHOENIX_SEAL_KEY":
			continue // strip broker credentials
		}
		if maskEnv {
			val := e[strings.IndexByte(e, '=')+1:]
			if strings.Contains(val, "phoenix://") {
				continue // strip env vars containing phoenix:// refs
			}
		}
		env = append(env, e)
	}
	for _, m := range mappings {
		val, ok := resolvedValues[m.ref]
		if !ok {
			return fmt.Errorf("no value returned for %s", m.ref)
		}
		env = append(env, m.envVar+"="+val)
	}

	// Exec into the child process (replaces current process)
	binary, err := exec.LookPath(cmdArgs[0])
	if err != nil {
		return fmt.Errorf("command not found: %s", cmdArgs[0])
	}
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

func cmdCertIssue(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}

	var name, outDir string
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
				outDir = args[i]
			}
		}
		i++
	}

	if name == "" {
		return fmt.Errorf("usage: phoenix cert issue <agent-name> [-o output-dir]")
	}
	if outDir == "" {
		outDir = "."
	}

	body, _ := json.Marshal(map[string]string{"agent_name": name})
	resp, err := apiRequest("POST", "/v1/certs/issue", strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	var result struct {
		Cert   string `json:"cert"`
		Key    string `json:"key"`
		CACert string `json:"ca_cert"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	// Write cert files
	certPath := filepath.Join(outDir, name+".crt")
	keyPath := filepath.Join(outDir, name+".key")
	caPath := filepath.Join(outDir, "ca.crt")

	if err := os.WriteFile(certPath, []byte(result.Cert), 0644); err != nil {
		return fmt.Errorf("writing cert: %w", err)
	}
	if err := os.WriteFile(keyPath, []byte(result.Key), 0600); err != nil {
		return fmt.Errorf("writing key: %w", err)
	}
	if err := os.WriteFile(caPath, []byte(result.CACert), 0644); err != nil {
		return fmt.Errorf("writing CA cert: %w", err)
	}

	fmt.Printf("Certificate issued for agent %q\n", name)
	fmt.Printf("  cert: %s\n", certPath)
	fmt.Printf("  key:  %s\n", keyPath)
	fmt.Printf("  CA:   %s\n", caPath)
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
	if err := requireAuth(); err != nil {
		return err
	}

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
			}
		case "--force":
			force = true
		}
		i++
	}

	if name == "" {
		return fmt.Errorf("usage: phoenix keypair generate <agent-name> [--output <path>] [--force]")
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
	if rule.RequireMTLS {
		fmt.Printf("  require_mtls: true\n")
	}
	if len(rule.AllowedIPs) > 0 {
		b, _ := json.Marshal(rule.AllowedIPs)
		fmt.Printf("  source_ip: %s\n", string(b))
	}
	if rule.CertFingerprint != "" {
		b, _ := json.Marshal(rule.CertFingerprint)
		fmt.Printf("  cert_fingerprint: %s\n", string(b))
	}
	if rule.DenyBearer {
		fmt.Printf("  deny_bearer: true\n")
	}
	if len(rule.AllowedTools) > 0 {
		b, _ := json.Marshal(rule.AllowedTools)
		fmt.Printf("  allowed_tools: %s\n", string(b))
	}
	if len(rule.DenyTools) > 0 {
		b, _ := json.Marshal(rule.DenyTools)
		fmt.Printf("  deny_tools: %s\n", string(b))
	}
	if rule.Process != nil {
		b, _ := json.Marshal(rule.Process)
		fmt.Printf("  process: %s\n", string(b))
	}
	if rule.TimeWindow != "" {
		b, _ := json.Marshal(rule.TimeWindow)
		fmt.Printf("  time_window: %s\n", string(b))
	}
	if rule.TimeZone != "" {
		b, _ := json.Marshal(rule.TimeZone)
		fmt.Printf("  time_zone: %s\n", string(b))
	}
	if rule.CredentialTTL != "" {
		b, _ := json.Marshal(rule.CredentialTTL)
		fmt.Printf("  credential_ttl: %s\n", string(b))
	}
	if rule.RequireFreshAttestation {
		fmt.Printf("  require_fresh_attestation: true\n")
	}
	if rule.RequireNonce {
		fmt.Printf("  require_nonce: true\n")
	}
	if rule.NonceMaxAge != "" {
		b, _ := json.Marshal(rule.NonceMaxAge)
		fmt.Printf("  nonce_max_age: %s\n", string(b))
	}
	if rule.RequireSigned {
		fmt.Printf("  require_signed: true\n")
	}
}

func cmdPolicyTest(args []string) error {
	var agent, ip, path, timeStr string
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
			i++
			if i < len(args) {
				timeStr = args[i]
			}
		default:
			if path == "" {
				path = args[i]
			}
		}
		i++
	}

	if path == "" {
		return fmt.Errorf("usage: phoenix policy test --agent <name> --ip <ip> [--time <RFC3339>] <secret-path>")
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

	// Build request context from CLI flags
	ctx := &policy.RequestContext{
		SourceIP:   ip,
		UsedBearer: true, // CLI test assumes bearer unless overridden
	}

	// Parse --time for time-window evaluation
	if timeStr != "" {
		evalTime, parseErr := time.Parse(time.RFC3339, timeStr)
		if parseErr != nil {
			return fmt.Errorf("invalid --time value %q (expected RFC3339): %w", timeStr, parseErr)
		}
		ctx.EvalTime = evalTime
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
	if timeStr != "" {
		fmt.Printf("  Eval time: %s\n", timeStr)
	} else {
		fmt.Printf("  Eval time: %s (now)\n", time.Now().Format(time.RFC3339))
	}
	fmt.Println()

	if rule == nil {
		fmt.Printf("No attestation policy matches path %q — access allowed by default.\n", path)
		return nil
	}

	fmt.Printf("Matched policy: %s\n", pattern)

	// Show rule details
	if rule.DenyBearer {
		fmt.Printf("  [INFO] deny_bearer: bearer tokens are blocked\n")
	}
	if rule.RequireMTLS {
		fmt.Printf("  [WARN] require_mtls: mTLS client cert required (not testable from CLI)\n")
	}
	if len(rule.AllowedIPs) > 0 {
		if ip == "" {
			fmt.Printf("  [SKIP] source_ip: %v (no --ip provided)\n", rule.AllowedIPs)
		} else {
			fmt.Printf("  [INFO] source_ip: %v (evaluated by engine)\n", rule.AllowedIPs)
		}
	}
	if rule.CertFingerprint != "" {
		fmt.Printf("  [INFO] cert_fingerprint: %s (not testable from CLI)\n", rule.CertFingerprint)
	}
	if rule.TimeWindow != "" {
		tz := rule.TimeZone
		if tz == "" {
			tz = "UTC"
		}
		fmt.Printf("  [TEST] time_window: %s (%s)\n", rule.TimeWindow, tz)
	}
	if rule.RequireNonce {
		fmt.Printf("  [INFO] require_nonce: nonce challenge required\n")
	}
	if rule.RequireSigned {
		fmt.Printf("  [INFO] require_signed: signed resolve required\n")
	}

	// Run engine evaluation (skip checks we can't test: mTLS, nonce, signature, cert)
	// We override the context to mark untestable items as passed to isolate testable checks
	testCtx := &policy.RequestContext{
		UsedMTLS:          true, // assume mTLS for testing purposes
		UsedBearer:        false,
		SourceIP:          ip,
		NonceValidated:    true, // assume nonce passed
		SignatureVerified: true, // assume signed
		EvalTime:          ctx.EvalTime,
	}

	err = pe.Evaluate(path, testCtx)
	if err != nil {
		fmt.Printf("  Result: FAIL — %v\n", err)
		return nil
	}

	fmt.Printf("  Result: PASS (testable checks passed)\n")
	return nil
}

func cmdTokenMint(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}

	var agent string
	i := 0
	if i < len(args) && !strings.HasPrefix(args[i], "-") {
		agent = args[i]
	}

	if agent == "" {
		return fmt.Errorf("usage: phoenix token mint <agent-name>")
	}

	body, _ := json.Marshal(map[string]string{"agent": agent})
	resp, err := apiRequest("POST", "/v1/token/mint", strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	var result struct {
		Token     string `json:"token"`
		Agent     string `json:"agent"`
		IssuedAt  string `json:"issued_at"`
		ExpiresAt string `json:"expires_at"`
		TTL       string `json:"ttl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	fmt.Printf("Token minted for agent %q\n", result.Agent)
	fmt.Printf("  Token:      %s\n", result.Token)
	fmt.Printf("  Issued at:  %s\n", result.IssuedAt)
	fmt.Printf("  Expires at: %s\n", result.ExpiresAt)
	fmt.Printf("  TTL:        %s\n", result.TTL)
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

// tokenCacheEntry represents a cached short-lived token.
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

// getCachedSessionToken returns a valid cached session token for the role, or empty string.
func getCachedSessionToken(role string, ttlBuffer time.Duration) string {
	return getCachedToken("session:"+role, ttlBuffer)
}

// cacheSessionToken stores a session token in the cache.
func cacheSessionToken(role, tok string, expiresAt time.Time) {
	cache, _ := loadTokenCache()
	cache["session:"+role] = &tokenCacheEntry{
		Token:     tok,
		Agent:     "session:" + role,
		ExpiresAt: expiresAt,
	}
	if err := saveTokenCache(cache); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not cache session token: %v\n", err)
	}
}

// ensureSealKey loads or generates a seal key for session use.
// Priority: PHOENIX_SEAL_KEY env > ~/.phoenix/session-seal-<role>.key > generate new.
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

	// Check per-role key file
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, "", fmt.Errorf("cannot determine home directory: %w", err)
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

	// Generate new key
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, "", fmt.Errorf("creating key directory: %w", err)
	}
	kp, err := crypto.GenerateSealKeyPair()
	if err != nil {
		return nil, "", fmt.Errorf("generating seal key: %w", err)
	}
	privKey := kp.PrivateKey
	pubKey := kp.PublicKey
	encoded := crypto.EncodeSealKey(&privKey)
	if err := os.WriteFile(keyPath, []byte(encoded+"\n"), 0600); err != nil {
		return nil, "", fmt.Errorf("saving seal key: %w", err)
	}
	return &privKey, crypto.EncodeSealKey(&pubKey), nil
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
		var errResp struct {
			Error       string `json:"error"`
			Code        string `json:"code"`
			Detail      string `json:"detail"`
			Remediation string `json:"remediation"`
		}
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Code != "" {
			return "", time.Time{}, fmt.Errorf("[%s] %s\n  hint: %s", errResp.Code, errResp.Detail, errResp.Remediation)
		}
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			return "", time.Time{}, fmt.Errorf("session mint: %s", errResp.Error)
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

	// Check cache first
	if cached := getCachedSessionToken(role, 5*time.Minute); cached != "" {
		token = cached
		return nil
	}

	// Need bootstrap auth to mint
	if token == "" {
		if os.Getenv("PHOENIX_CLIENT_CERT") == "" || os.Getenv("PHOENIX_CLIENT_KEY") == "" {
			return fmt.Errorf("PHOENIX_ROLE=%s set but no bootstrap auth available (set PHOENIX_TOKEN or mTLS certs)", role)
		}
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
	token = sessionToken
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
		var errResp struct {
			Error       string `json:"error"`
			Code        string `json:"code"`
			Detail      string `json:"detail"`
			Remediation string `json:"remediation"`
		}
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Code != "" {
			return "", time.Time{}, fmt.Errorf("[%s] %s", errResp.Code, errResp.Detail)
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
	entry, ok := cache["session:"+role]
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
	token = newToken
}

// attestViaSocket connects to the agent socket and returns peer info.
func attestViaSocket(socketPath string, agentName string) (peerUID int, binaryHash string, err error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return 0, "", fmt.Errorf("connecting to agent socket %s: %w", socketPath, err)
	}
	defer conn.Close()

	req := struct {
		Agent string `json:"agent"`
	}{Agent: agentName}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return 0, "", fmt.Errorf("sending attest request: %w", err)
	}

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
		return 0, "", fmt.Errorf("reading attest response: %w", err)
	}

	if !resp.OK {
		return 0, "", fmt.Errorf("attestation failed: %s", resp.Error)
	}
	if resp.Peer == nil {
		return 0, "", fmt.Errorf("attestation returned no peer info")
	}

	return int(resp.Peer.UID), resp.Peer.BinaryHash, nil
}

// mintTokenViaAPI mints a short-lived token via the Phoenix API.
func mintTokenViaAPI(agentName string, procUID *int, binaryHash string) (string, time.Time, error) {
	body := map[string]interface{}{"agent": agentName}
	if procUID != nil {
		body["process_uid"] = *procUID
	}
	if binaryHash != "" {
		body["binary_hash"] = binaryHash
	}
	bodyBytes, _ := json.Marshal(body)

	resp, err := apiRequest("POST", "/v1/token/mint", strings.NewReader(string(bodyBytes)))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("mint request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", time.Time{}, handleError(resp)
	}

	var result struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", time.Time{}, fmt.Errorf("decoding mint response: %w", err)
	}

	expiresAt, _ := time.Parse(time.RFC3339, result.ExpiresAt)
	return result.Token, expiresAt, nil
}

func cmdAgentSockToken(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}

	socketPath := defaultAgentSocket
	agentName := ""
	ttlBuffer := 30 * time.Second

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
		case "--ttl-buffer":
			i++
			if i < len(args) {
				var parseErr error
				ttlBuffer, parseErr = time.ParseDuration(args[i])
				if parseErr != nil {
					return fmt.Errorf("invalid --ttl-buffer %q: %w", args[i], parseErr)
				}
			}
		default:
			if agentName == "" {
				agentName = args[i]
			}
		}
		i++
	}

	if agentName == "" {
		return fmt.Errorf("usage: phoenix agent-sock token --agent <name> [--socket <path>] [--ttl-buffer <dur>]")
	}

	// Check cache first
	if cached := getCachedToken(agentName, ttlBuffer); cached != "" {
		fmt.Printf("Token (cached): %s\n", cached)
		return nil
	}

	// Attest via socket
	peerUID, binaryHash, err := attestViaSocket(socketPath, agentName)
	if err != nil {
		return err
	}

	// Mint via API with process claims
	tok, expiresAt, err := mintTokenViaAPI(agentName, &peerUID, binaryHash)
	if err != nil {
		return err
	}

	// Cache the token
	cache, _ := loadTokenCache()
	cache[agentName] = &tokenCacheEntry{
		Token:     tok,
		Agent:     agentName,
		ExpiresAt: expiresAt,
	}
	if err := saveTokenCache(cache); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not cache token: %v\n", err)
	}

	fmt.Printf("Token minted for agent %q\n", agentName)
	fmt.Printf("  Token:      %s\n", tok)
	fmt.Printf("  Expires at: %s\n", expiresAt.Format(time.RFC3339))
	return nil
}

func cmdAgentSockResolve(args []string) error {
	socketPath := defaultAgentSocket
	agentName := ""
	ttlBuffer := 30 * time.Second
	var refs []string

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
		case "--ttl-buffer":
			i++
			if i < len(args) {
				var parseErr error
				ttlBuffer, parseErr = time.ParseDuration(args[i])
				if parseErr != nil {
					return fmt.Errorf("invalid --ttl-buffer %q: %w", args[i], parseErr)
				}
			}
		default:
			refs = append(refs, args[i])
		}
		i++
	}

	if len(refs) == 0 || agentName == "" {
		return fmt.Errorf("usage: phoenix agent-sock resolve --agent <name> <ref...> [--socket <path>]")
	}

	// Get or mint token
	tok := getCachedToken(agentName, ttlBuffer)
	if tok == "" {
		// Attest and mint
		peerUID, binaryHash, err := attestViaSocket(socketPath, agentName)
		if err != nil {
			return err
		}

		// Need admin auth to mint — use existing PHOENIX_TOKEN
		if token == "" {
			return fmt.Errorf("PHOENIX_TOKEN required to mint initial token via agent-sock resolve")
		}

		var expiresAt time.Time
		var mintErr error
		tok, expiresAt, mintErr = mintTokenViaAPI(agentName, &peerUID, binaryHash)
		if mintErr != nil {
			return fmt.Errorf("auto-minting token: %w", mintErr)
		}

		// Cache it
		cache, _ := loadTokenCache()
		cache[agentName] = &tokenCacheEntry{
			Token:     tok,
			Agent:     agentName,
			ExpiresAt: expiresAt,
		}
		saveTokenCache(cache)
	}

	// Load seal key for sealed mode
	sealPrivKey, sealErr := loadSealKey()
	if sealErr != nil {
		return fmt.Errorf("loading seal key: %w", sealErr)
	}

	// Resolve using the short-lived token
	body, _ := json.Marshal(map[string]interface{}{"refs": refs})
	reqURL := serverURL + "/v1/resolve"
	req, err := http.NewRequest("POST", reqURL, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range sealHeaders(sealPrivKey) {
		req.Header.Set(k, v)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("resolve request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	// Decode response — handle sealed or plaintext
	var values map[string]string
	var errs map[string]string

	if sealPrivKey != nil {
		var result struct {
			SealedValues map[string]interface{} `json:"sealed_values"`
			Errors       map[string]string      `json:"errors"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
		errs = result.Errors
		values = make(map[string]string)
		for ref, raw := range result.SealedValues {
			if envMap, ok := raw.(map[string]interface{}); ok {
				if envRef, _ := envMap["ref"].(string); envRef != ref {
					return fmt.Errorf("sealed envelope ref mismatch: map key %q, envelope %q", ref, envRef)
				}
			}
			val, err := decryptSealedValue(raw, sealPrivKey)
			if err != nil {
				return fmt.Errorf("decrypting %s: %w", ref, err)
			}
			values[ref] = val
		}
	} else {
		var result struct {
			Values map[string]string `json:"values"`
			Errors map[string]string `json:"errors"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
		values = result.Values
		errs = result.Errors
	}

	// Single ref: output raw value
	if len(refs) == 1 {
		if errMsg, ok := errs[refs[0]]; ok {
			return fmt.Errorf("%s: %s", refs[0], errMsg)
		}
		fmt.Print(values[refs[0]])
		return nil
	}

	// Multiple refs
	var hasErr bool
	for _, ref := range refs {
		if errMsg, ok := errs[ref]; ok {
			fmt.Fprintf(os.Stderr, "%s: error: %s\n", ref, errMsg)
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

func cmdInit(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: phoenix init <dir>")
	}
	// Delegate to server's init
	fmt.Println("Use phoenix-server --init", args[0])
	return nil
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
	body, _ := io.ReadAll(resp.Body)

	var structured struct {
		Error       string `json:"error"`
		Code        string `json:"code"`
		Detail      string `json:"detail"`
		Remediation string `json:"remediation"`
	}
	if json.Unmarshal(body, &structured) == nil && structured.Code != "" {
		msg := fmt.Sprintf("HTTP %d [%s]: %s", resp.StatusCode, structured.Code, structured.Detail)
		if structured.Remediation != "" {
			msg += "\n  hint: " + structured.Remediation
		}
		return fmt.Errorf("%s", msg)
	}

	if json.Unmarshal(body, &structured) == nil && structured.Error != "" {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, structured.Error)
	}
	return fmt.Errorf("HTTP %d", resp.StatusCode)
}
