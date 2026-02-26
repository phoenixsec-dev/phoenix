// Phoenix CLI — client for the Phoenix secrets management API.
//
// Usage:
//
//	phoenix get <path>
//	phoenix set <path> --value <value> [--description <desc>] [--tags <t1,t2>]
//	phoenix delete <path>
//	phoenix list [prefix]
//	phoenix export <prefix> --format env
//	phoenix import <file> --prefix <prefix>
//	phoenix audit [--last N] [--agent <name>] [--since <RFC3339>]
//	phoenix agent create <name> --token <token> --acl <path:actions,...>
//	phoenix agent list
//	phoenix init <dir>
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	case "init":
		err = cmdInit(args)
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
  phoenix delete <path>                       Delete a secret
  phoenix list [prefix]                       List secret paths
  phoenix export <prefix> -f env              Export as .env format
  phoenix import <file> -p <prefix>           Import from .env file
  phoenix audit [-n N] [-a agent] [-s time]   Query audit log
  phoenix agent create <name> -t <token> --acl <path:actions;path:actions>
  phoenix agent list                          List agents
  phoenix cert issue <name> [-o dir]          Issue mTLS client certificate
  phoenix init <dir>                          Initialize data directory

Environment:
  PHOENIX_SERVER       Server URL (default: http://127.0.0.1:9090)
  PHOENIX_TOKEN        Bearer token for authentication
  PHOENIX_CA_CERT      CA certificate for TLS verification
  PHOENIX_CLIENT_CERT  Client certificate for mTLS authentication
  PHOENIX_CLIENT_KEY   Client key for mTLS authentication`)
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

	if path == "" || value == "" {
		return fmt.Errorf("usage: phoenix set <path> -v <value> [-d description] [--tags t1,t2]")
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

	var filePath, prefix string
	i := 0
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
		}
		i++
	}

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

func cmdInit(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: phoenix init <dir>")
	}
	// Delegate to server's init
	fmt.Println("Use phoenix-server --init", args[0])
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
