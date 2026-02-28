package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

func cmdStatus(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}

	// Gather data from existing endpoints in sequence.
	// A future /v1/status endpoint will consolidate this server-side.

	fmt.Println("Phoenix Status")
	fmt.Println(strings.Repeat("─", 60))

	// Server health
	printServerHealth()

	// Secret summary
	printSecretSummary()

	// Agent summary
	printAgentSummary()

	// Policy summary
	printPolicySummary()

	// Recent audit
	printAuditSummary()

	return nil
}

func printServerHealth() {
	resp, err := apiRequest("GET", "/v1/health", nil)
	if err != nil {
		fmt.Printf("  Server: unreachable (%v)\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		fmt.Printf("  Server: running (%s)\n", serverURL)
	} else {
		fmt.Printf("  Server: unhealthy (HTTP %d)\n", resp.StatusCode)
	}
}

func printSecretSummary() {
	resp, err := apiRequest("GET", "/v1/secrets/", nil)
	if err != nil {
		fmt.Printf("  Store: unavailable\n")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("  Store: access denied (HTTP %d)\n", resp.StatusCode)
		return
	}

	var result struct {
		Paths []string `json:"paths"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Printf("  Store: error reading response (%v)\n", err)
		return
	}

	namespaces := make(map[string]int)
	for _, p := range result.Paths {
		parts := strings.SplitN(p, "/", 2)
		if len(parts) > 0 {
			namespaces[parts[0]]++
		}
	}

	fmt.Printf("  Store: %d secrets across %d namespaces\n", len(result.Paths), len(namespaces))
	for ns, count := range namespaces {
		fmt.Printf("    %s: %d secrets\n", ns, count)
	}
}

func printAgentSummary() {
	resp, err := apiRequest("GET", "/v1/agents", nil)
	if err != nil {
		fmt.Printf("  Agents: unavailable\n")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("  Agents: access denied (HTTP %d)\n", resp.StatusCode)
		return
	}

	var result struct {
		Agents []string `json:"agents"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Printf("  Agents: error reading response (%v)\n", err)
		return
	}

	fmt.Printf("  Agents: %d registered\n", len(result.Agents))
	for _, name := range result.Agents {
		fmt.Printf("    - %s\n", name)
	}
}

func printPolicySummary() {
	policyPath := os.Getenv("PHOENIX_POLICY")
	if policyPath == "" {
		fmt.Printf("  Policy: not configured (PHOENIX_POLICY not set)\n")
		return
	}

	data, err := os.ReadFile(policyPath)
	if err != nil {
		fmt.Printf("  Policy: cannot read %s\n", policyPath)
		return
	}

	var pf struct {
		Attestation map[string]json.RawMessage `json:"attestation"`
	}
	if err := json.Unmarshal(data, &pf); err != nil {
		fmt.Printf("  Policy: invalid JSON\n")
		return
	}

	fmt.Printf("  Policy: %d attestation rules active\n", len(pf.Attestation))
	for pattern, raw := range pf.Attestation {
		var rule map[string]interface{}
		json.Unmarshal(raw, &rule)

		var checks []string
		if v, ok := rule["require_mtls"]; ok && v == true {
			checks = append(checks, "mTLS")
		}
		if v, ok := rule["deny_bearer"]; ok && v == true {
			checks = append(checks, "deny-bearer")
		}
		if _, ok := rule["source_ip"]; ok {
			checks = append(checks, "IP-bound")
		}
		if _, ok := rule["cert_fingerprint"]; ok {
			checks = append(checks, "cert-pinned")
		}

		desc := "open"
		if len(checks) > 0 {
			desc = strings.Join(checks, " + ")
		}
		fmt.Printf("    %-30s → %s\n", pattern, desc)
	}
}

func printAuditSummary() {
	resp, err := apiRequest("GET", "/v1/audit?limit=5", nil)
	if err != nil {
		fmt.Printf("  Audit: unavailable\n")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("  Audit: access denied (HTTP %d)\n", resp.StatusCode)
		return
	}

	var result struct {
		Entries []struct {
			Timestamp string `json:"ts"`
			Agent     string `json:"agent"`
			Action    string `json:"action"`
			Path      string `json:"path"`
			Status    string `json:"status"`
			Reason    string `json:"reason"`
		} `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Printf("  Audit: error reading response (%v)\n", err)
		return
	}

	if len(result.Entries) == 0 {
		fmt.Printf("  Audit: no events recorded\n")
		return
	}

	// Find last denial
	var lastDenial string
	for _, e := range result.Entries {
		if e.Status == "denied" {
			lastDenial = e.Timestamp
			break
		}
	}

	fmt.Printf("  Audit: recent activity\n")
	if len(result.Entries) > 0 {
		latest := result.Entries[0]
		ago := formatTimeAgo(latest.Timestamp)
		fmt.Printf("    Last event: %s (%s %s %s — %s)\n",
			ago, latest.Agent, latest.Action, latest.Path, latest.Status)
	}
	if lastDenial != "" {
		fmt.Printf("    Last denial: %s\n", formatTimeAgo(lastDenial))
	}
}

func formatTimeAgo(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		// Try other common formats
		t, err = time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return ts
		}
	}

	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}
