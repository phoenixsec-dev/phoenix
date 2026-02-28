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
		// Dry-run: use server-side dry_run on POST /v1/resolve to verify
		// ref format, ACL, attestation, and path existence without returning
		// plaintext secret values.
		fmt.Printf("Dry-run: verifying %d references in %s (no secret values returned)\n\n", len(refList), filePath)

		body, _ := json.Marshal(map[string]interface{}{"refs": refList})
		resp, err := apiRequest("POST", "/v1/resolve?dry_run=true", strings.NewReader(string(body)))
		if err != nil {
			return fmt.Errorf("dry-run resolve request failed: %w", err)
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
