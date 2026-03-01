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
//	phoenix agent create <name> --token <token> --acl <path:actions,...>
//	phoenix agent list
//	phoenix resolve <ref> [ref...]
//	phoenix exec --env KEY=phoenix://ns/secret [--output-env <path>] [--timeout <dur>] [--mask-env] -- <command> [args...]
//	phoenix verify <file> [--dry-run]
//	phoenix status
//	phoenix token mint <agent>
//	phoenix policy show <path>
//	phoenix policy test --agent <name> --ip <ip> <path>
//	phoenix init <dir>
//	phoenix mcp-server
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"git.home/vector/phoenix/internal/crypto"
	"git.home/vector/phoenix/internal/store"
	"git.home/vector/phoenix/internal/version"
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
		err = cmdMCP(args)
	case "init":
		err = cmdInit(args)
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
  phoenix agent create <name> -t <token> --acl <path:actions;path:actions>
  phoenix agent list                          List agents
  phoenix resolve <ref> [ref...]               Resolve phoenix:// references to values
  phoenix exec --env K=phoenix://n/s -- cmd   Run command with resolved secrets as env
  phoenix exec --output-env <file> --env ...  Write resolved env to file (no exec)
  phoenix exec --timeout 5s --env ...         Fail if resolution exceeds duration
  phoenix exec --mask-env --env ...           Strip phoenix:// refs from child env
  phoenix verify <file> [--dry-run]           Check phoenix:// refs in file are resolvable
  phoenix status                              Show server health, secrets, agents, policy
  phoenix policy show <path>                  Show attestation requirements for path
  phoenix policy test -a <agent> -i <ip> <p>  Dry-run attestation check
  phoenix token mint <agent>                   Mint a short-lived token for an agent
  phoenix rotate-master                       Rotate master encryption key
  phoenix cert issue <name> [-o dir]          Issue mTLS client certificate
  phoenix emergency get <path> --data-dir <d> [--confirm]  Break-glass offline secret retrieval
  phoenix agent-sock attest [--socket <path>]  Attest via local Unix socket agent
  phoenix agent-sock token --agent <name>      Mint/cache short-lived token via socket
  phoenix agent-sock resolve <ref...>          Resolve refs using cached socket token
  phoenix mcp-server                          Run MCP server (stdio JSON-RPC)
  phoenix init <dir>                          Initialize data directory

Environment:
  PHOENIX_SERVER       Server URL (default: http://127.0.0.1:9090)
  PHOENIX_TOKEN        Bearer token for authentication
  PHOENIX_CA_CERT      CA certificate for TLS verification
  PHOENIX_CLIENT_CERT  Client certificate for mTLS authentication
  PHOENIX_CLIENT_KEY   Client key for mTLS authentication
  PHOENIX_POLICY       Path to attestation policy file (JSON)`)
}

// requireAuth checks that at least one auth method is configured
// (bearer token or mTLS client cert).
func requireAuth() error {
	if token != "" {
		return nil
	}
	// Check if mTLS client cert is configured
	if os.Getenv("PHOENIX_CLIENT_CERT") != "" && os.Getenv("PHOENIX_CLIENT_KEY") != "" {
		return nil
	}
	return fmt.Errorf("no auth configured: set PHOENIX_TOKEN or PHOENIX_CLIENT_CERT + PHOENIX_CLIENT_KEY")
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
	return httpClient.Do(req)
}

func cmdGet(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}
	if len(args) < 1 {
		return fmt.Errorf("usage: phoenix get <path>")
	}

	resp, err := apiRequest("GET", "/v1/secrets/"+args[0], nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return handleError(resp)
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
		return err
	}
	defer resp.Body.Close()

	var listResult struct {
		Paths []string `json:"paths"`
	}
	json.NewDecoder(resp.Body).Decode(&listResult)

	for _, path := range listResult.Paths {
		resp, err := apiRequest("GET", "/v1/secrets/"+path, nil)
		if err != nil {
			continue
		}
		var secret struct {
			Value string `json:"value"`
		}
		json.NewDecoder(resp.Body).Decode(&secret)
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

	var params []string
	i := 0
	for i < len(args) {
		switch args[i] {
		case "-n", "--last":
			i++
			if i < len(args) {
				params = append(params, "limit="+args[i])
			}
		case "-a", "--agent":
			i++
			if i < len(args) {
				params = append(params, "agent="+args[i])
			}
		case "-s", "--since":
			i++
			if i < len(args) {
				params = append(params, "since="+args[i])
			}
		}
		i++
	}

	path := "/v1/audit"
	if len(params) > 0 {
		path += "?" + strings.Join(params, "&")
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
		}
		i++
	}

	if name == "" || agentToken == "" {
		return fmt.Errorf("usage: phoenix agent create <name> -t <token> [--acl <path:action,action;path:action>]")
	}

	// Parse ACL string: "openclaw/*:read,write;vector/*:read"
	// Rules separated by ";", actions within a rule separated by ","
	var permissions []map[string]interface{}
	if aclStr != "" {
		for _, rule := range strings.Split(aclStr, ";") {
			parts := strings.SplitN(rule, ":", 2)
			if len(parts) != 2 {
				continue
			}
			actions := strings.Split(parts[1], ",")
			permissions = append(permissions, map[string]interface{}{
				"path":    parts[0],
				"actions": actions,
			})
		}
	}

	body, _ := json.Marshal(map[string]interface{}{
		"name":        name,
		"token":       agentToken,
		"permissions": permissions,
	})

	resp, err := apiRequest("POST", "/v1/agents", strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	fmt.Printf("agent created: %s\n", name)
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
	if len(args) < 1 {
		return fmt.Errorf("usage: phoenix resolve <phoenix://ns/secret> [ref...]")
	}

	body, _ := json.Marshal(map[string]interface{}{
		"refs": args,
	})

	resp, err := apiRequest("POST", "/v1/resolve", strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	var result struct {
		Values map[string]string `json:"values"`
		Errors map[string]string `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	// Single ref: output raw value for piping
	if len(args) == 1 {
		if errMsg, ok := result.Errors[args[0]]; ok {
			return fmt.Errorf("%s: %s", args[0], errMsg)
		}
		fmt.Print(result.Values[args[0]])
		return nil
	}

	// Multiple refs: output ref → value pairs
	var hasErr bool
	for _, ref := range args {
		if errMsg, ok := result.Errors[ref]; ok {
			fmt.Fprintf(os.Stderr, "%s: error: %s\n", ref, errMsg)
			hasErr = true
			continue
		}
		fmt.Printf("%s\t%s\n", ref, result.Values[ref])
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
		resp, err = httpClient.Do(req)
	} else {
		resp, err = apiRequest("POST", "/v1/resolve", strings.NewReader(string(body)))
	}
	if err != nil {
		return fmt.Errorf("resolve request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	var result struct {
		Values map[string]string `json:"values"`
		Errors map[string]string `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding resolve response: %w", err)
	}

	// Check for resolution errors
	if len(result.Errors) > 0 {
		for ref, errMsg := range result.Errors {
			fmt.Fprintf(os.Stderr, "error resolving %s: %s\n", ref, errMsg)
		}
		return fmt.Errorf("failed to resolve %d reference(s)", len(result.Errors))
	}

	// If --output-env is set, write resolved env to file and exit
	if outputEnvPath != "" {
		var lines []string
		for _, m := range mappings {
			val, ok := result.Values[m.ref]
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
			"PHOENIX_CA_CERT", "PHOENIX_SERVER", "PHOENIX_POLICY":
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
		val, ok := result.Values[m.ref]
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

	// Parse the policy to find matching rule
	var pf struct {
		Attestation map[string]json.RawMessage `json:"attestation"`
	}
	if err := json.Unmarshal(data, &pf); err != nil {
		return fmt.Errorf("parsing policy: %w", err)
	}

	if len(pf.Attestation) == 0 {
		fmt.Printf("No attestation policies configured.\n")
		return nil
	}

	// Find matching patterns (simple display)
	found := false
	for pattern, raw := range pf.Attestation {
		if matchesPattern(pattern, path) {
			fmt.Printf("Pattern: %s\n", pattern)
			var rule map[string]interface{}
			json.Unmarshal(raw, &rule)
			for k, v := range rule {
				formatted, _ := json.Marshal(v)
				fmt.Printf("  %s: %s\n", k, string(formatted))
			}
			found = true
		}
	}

	if !found {
		fmt.Printf("No attestation policy matches path %q\n", path)
	}
	return nil
}

// matchesPattern does simple glob matching for CLI display.
func matchesPattern(pattern, path string) bool {
	if pattern == "*" || pattern == "**" {
		return true
	}
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return strings.HasPrefix(path, prefix+"/") || path == prefix
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		if !strings.HasPrefix(path, prefix+"/") {
			return false
		}
		rest := strings.TrimPrefix(path, prefix+"/")
		return !strings.Contains(rest, "/")
	}
	return pattern == path
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

	data, err := os.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("reading policy file: %w", err)
	}

	// Use a simple evaluation (no full policy.Engine import in CLI binary)
	var pf struct {
		Attestation map[string]struct {
			RequireMTLS     bool     `json:"require_mtls"`
			AllowedIPs      []string `json:"source_ip"`
			CertFingerprint string   `json:"cert_fingerprint"`
			DenyBearer      bool     `json:"deny_bearer"`
		} `json:"attestation"`
	}
	if err := json.Unmarshal(data, &pf); err != nil {
		return fmt.Errorf("parsing policy: %w", err)
	}

	fmt.Printf("Testing attestation for path %q\n", path)
	if agent != "" {
		fmt.Printf("  Agent: %s\n", agent)
	}
	if ip != "" {
		fmt.Printf("  Source IP: %s\n", ip)
	}
	fmt.Println()

	matched := false
	for pattern, rule := range pf.Attestation {
		if !matchesPattern(pattern, path) {
			continue
		}
		matched = true
		fmt.Printf("Matched policy: %s\n", pattern)

		allPass := true
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
				found := false
				for _, allowed := range rule.AllowedIPs {
					if allowed == ip {
						found = true
					}
				}
				if found {
					fmt.Printf("  [PASS] source_ip: %s is in allowed list\n", ip)
				} else {
					fmt.Printf("  [FAIL] source_ip: %s is NOT in allowed list %v\n", ip, rule.AllowedIPs)
					allPass = false
				}
			}
		}
		if rule.CertFingerprint != "" {
			fmt.Printf("  [INFO] cert_fingerprint: %s (not testable from CLI)\n", rule.CertFingerprint)
		}

		if allPass {
			fmt.Printf("  Result: PASS (testable checks passed)\n")
		} else {
			fmt.Printf("  Result: FAIL\n")
		}
	}

	if !matched {
		fmt.Printf("No attestation policy matches path %q — access allowed by default.\n", path)
	}
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

	// Resolve using the short-lived token
	body, _ := json.Marshal(map[string]interface{}{"refs": refs})
	url := serverURL + "/v1/resolve"
	req, err := http.NewRequest("POST", url, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("resolve request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	var result struct {
		Values map[string]string `json:"values"`
		Errors map[string]string `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	// Single ref: output raw value
	if len(refs) == 1 {
		if errMsg, ok := result.Errors[refs[0]]; ok {
			return fmt.Errorf("%s: %s", refs[0], errMsg)
		}
		fmt.Print(result.Values[refs[0]])
		return nil
	}

	// Multiple refs
	var hasErr bool
	for _, ref := range refs {
		if errMsg, ok := result.Errors[ref]; ok {
			fmt.Fprintf(os.Stderr, "%s: error: %s\n", ref, errMsg)
			hasErr = true
			continue
		}
		fmt.Printf("%s\t%s\n", ref, result.Values[ref])
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
	var errResp struct {
		Error string `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp.Error != "" {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, errResp.Error)
	}
	return fmt.Errorf("HTTP %d", resp.StatusCode)
}
