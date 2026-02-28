package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// phoenixRefPattern matches phoenix:// references in any file format.
var phoenixRefPattern = regexp.MustCompile(`phoenix://[a-zA-Z0-9._-]+/[a-zA-Z0-9._/-]+`)

func cmdVerify(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}

	var filePath string
	var dryRun bool

	i := 0
	for i < len(args) {
		switch args[i] {
		case "--dry-run":
			dryRun = true
		default:
			if filePath == "" {
				filePath = args[i]
			}
		}
		i++
	}

	if filePath == "" {
		return fmt.Errorf("usage: phoenix verify <file> [--dry-run]")
	}

	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()

	// Scan file for phoenix:// references
	refs := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		matches := phoenixRefPattern.FindAllString(scanner.Text(), -1)
		for _, m := range matches {
			refs[m] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	if len(refs) == 0 {
		fmt.Printf("No phoenix:// references found in %s\n", filePath)
		return nil
	}

	// Collect unique refs
	refList := make([]string, 0, len(refs))
	for ref := range refs {
		refList = append(refList, ref)
	}

	var okCount, failCount int

	if dryRun {
		// Dry-run: check that each ref's path exists and is accessible
		// via the list endpoint, without resolving any secret values.
		// TODO: When the server supports a dry_run parameter on POST /v1/resolve,
		// switch to that so we can also verify attestation policies without
		// returning plaintext values.
		fmt.Printf("Dry-run: checking path accessibility for %d references in %s\n", len(refList), filePath)
		fmt.Printf("(Note: list-based check — attestation policies are only enforced on resolve)\n\n")

		resp, err := apiRequest("GET", "/v1/secrets/", nil)
		if err != nil {
			return fmt.Errorf("list request failed: %w", err)
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

		accessible := make(map[string]bool, len(listResult.Paths))
		for _, p := range listResult.Paths {
			accessible[p] = true
		}

		for _, ref := range refList {
			path := strings.TrimPrefix(ref, "phoenix://")
			if accessible[path] {
				fmt.Printf("%-50s OK\n", ref)
				okCount++
			} else {
				fmt.Printf("%-50s FAIL (path not found or not accessible)\n", ref)
				failCount++
			}
		}
	} else {
		// Full verify: resolves each ref, checking ACL + attestation.
		body, _ := json.Marshal(map[string]interface{}{"refs": refList})
		resp, err := apiRequest("POST", "/v1/resolve", strings.NewReader(string(body)))
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

		for _, ref := range refList {
			if errMsg, ok := result.Errors[ref]; ok {
				fmt.Printf("%-50s FAIL (%s)\n", ref, errMsg)
				failCount++
			} else {
				fmt.Printf("%-50s OK\n", ref)
				okCount++
			}
		}
	}

	fmt.Printf("\n%d refs found, %d OK, %d FAIL\n", len(refList), okCount, failCount)

	if failCount > 0 {
		// Return an error to trigger exit code 1
		return fmt.Errorf("%d reference(s) failed verification", failCount)
	}
	return nil
}
