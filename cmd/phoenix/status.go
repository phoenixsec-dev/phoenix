package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func cmdStatus(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("usage: phoenix status (no arguments expected)")
	}
	if err := requireAuth(); err != nil {
		return err
	}

	// Use consolidated /v1/status endpoint.
	resp, err := apiRequest("GET", "/v1/status", nil)
	if err != nil {
		return fmt.Errorf("status request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return handleError(resp)
	}

	var status struct {
		Status       string                       `json:"status"`
		Uptime       string                       `json:"uptime"`
		Secrets      int                          `json:"secrets"`
		Agents       int                          `json:"agents"`
		Time         string                       `json:"time"`
		MTLS         string                       `json:"mtls"`
		PolicyRules  int                          `json:"policy_rules"`
		Policy       map[string]string            `json:"policy"`
		NoncePending int                          `json:"nonce_pending"`
		RecentAudit  []map[string]json.RawMessage `json:"recent_audit"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return fmt.Errorf("decoding status: %w", err)
	}

	fmt.Println("Phoenix Status")
	fmt.Println(strings.Repeat("─", 60))

	// Server
	fmt.Printf("  Server: %s (%s)\n", status.Status, serverURL)
	if status.Uptime != "" {
		fmt.Printf("  Uptime: %s\n", status.Uptime)
	}
	if status.Time != "" {
		fmt.Printf("  Time:   %s\n", status.Time)
	}

	// Store
	fmt.Printf("  Secrets: %d\n", status.Secrets)

	// Agents
	fmt.Printf("  Agents: %d registered\n", status.Agents)

	// mTLS
	fmt.Printf("  mTLS: %s\n", status.MTLS)

	// Policy
	if status.PolicyRules > 0 {
		fmt.Printf("  Policy: %d attestation rules\n", status.PolicyRules)
		for pattern, checks := range status.Policy {
			if checks == "" {
				checks = "open"
			}
			fmt.Printf("    %-30s → %s\n", pattern, checks)
		}
	} else {
		fmt.Printf("  Policy: no attestation rules\n")
	}

	// Nonce store
	if status.NoncePending > 0 {
		fmt.Printf("  Nonce challenges pending: %d\n", status.NoncePending)
	}

	// Recent audit
	if len(status.RecentAudit) > 0 {
		fmt.Printf("  Audit: recent activity\n")
		for _, entry := range status.RecentAudit {
			ts := rawString(entry["ts"])
			agent := rawString(entry["agent"])
			action := rawString(entry["action"])
			path := rawString(entry["path"])
			entryStatus := rawString(entry["status"])
			ago := formatTimeAgo(ts)
			fmt.Printf("    %s  %-10s %-8s %-30s %s\n", ago, agent, action, path, entryStatus)
		}
	}

	return nil
}

func rawString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return strings.Trim(string(raw), `"`)
}

func formatTimeAgo(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
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
