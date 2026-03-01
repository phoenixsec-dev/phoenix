package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/phoenixsec/phoenix/internal/op"
)

// import1Password imports secrets from a 1Password vault into Phoenix.
func import1Password(vault, itemFilter, prefix string, dryRun, skipExisting bool) error {
	tokenEnv := os.Getenv("PHOENIX_OP_TOKEN_ENV")
	if tokenEnv == "" {
		tokenEnv = "OP_SERVICE_ACCOUNT_TOKEN"
	}

	client := op.New(tokenEnv)
	if err := client.Available(); err != nil {
		return fmt.Errorf("1Password CLI: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Connecting to 1Password vault %q...\n", vault)

	var items []op.Item
	if itemFilter != "" {
		// Fetch single item by title/ID
		it, err := client.GetItem(vault, itemFilter)
		if err != nil {
			return fmt.Errorf("getting item %q: %w", itemFilter, err)
		}
		items = []op.Item{*it}
	} else {
		// List all items in vault
		listed, err := client.ListItems(vault)
		if err != nil {
			return fmt.Errorf("listing items: %w", err)
		}
		items = listed
	}

	fmt.Fprintf(os.Stderr, "Found %d items\n\n", len(items))

	imported := 0
	skipped := 0

	for _, item := range items {
		if skipCategory(item.Category) {
			fmt.Fprintf(os.Stderr, "skipped:  %s (category: %s, not supported)\n", item.Title, item.Category)
			skipped++
			continue
		}

		// ListItems returns metadata only — need to fetch full item for fields.
		// If we already have fields (single-item mode via GetItem), skip re-fetch.
		full := &item
		if len(item.Fields) == 0 {
			var err error
			full, err = client.GetItem(vault, item.ID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to fetch item %q: %v\n", item.Title, err)
				continue
			}
		}

		for _, field := range full.Fields {
			if field.Label == "" || !isImportableField(field.Type) {
				continue
			}

			secretPath := prefix + slugify(full.Title) + "/" + slugify(field.Label)

			if dryRun {
				fmt.Printf("would import: %s/%s → %s\n", full.Title, field.Label, secretPath)
				imported++
				continue
			}

			if skipExisting {
				resp, err := apiRequest("GET", "/v1/secrets/"+secretPath, nil)
				if err == nil {
					resp.Body.Close()
					if resp.StatusCode == 200 {
						fmt.Fprintf(os.Stderr, "exists:   %s (skipped)\n", secretPath)
						skipped++
						continue
					}
				}
			}

			body, _ := json.Marshal(map[string]interface{}{
				"value":       field.Value,
				"description": fmt.Sprintf("Imported from 1Password: %s/%s", vault, full.Title),
			})

			resp, err := apiRequest("PUT", "/v1/secrets/"+secretPath, strings.NewReader(string(body)))
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to import %s: %v\n", secretPath, err)
				continue
			}
			resp.Body.Close()

			if resp.StatusCode == 200 {
				fmt.Printf("imported: %s/%s → %s\n", full.Title, field.Label, secretPath)
				imported++
			} else {
				fmt.Fprintf(os.Stderr, "warning: failed to import %s (HTTP %d)\n", secretPath, resp.StatusCode)
			}
		}
	}

	if dryRun {
		fmt.Fprintf(os.Stderr, "\nDry run: %d secrets would be imported\n", imported)
	} else {
		fmt.Fprintf(os.Stderr, "\nImported %d secrets", imported)
		if skipped > 0 {
			fmt.Fprintf(os.Stderr, " (%d skipped)", skipped)
		}
		fmt.Fprintln(os.Stderr)
	}

	return nil
}

// skipCategory returns true for 1Password categories that shouldn't
// be imported as secrets.
func skipCategory(category string) bool {
	switch strings.ToUpper(category) {
	case "SSH_KEY", "DOCUMENT", "CREDIT_CARD", "BANK_ACCOUNT":
		return true
	}
	return false
}

// isImportableField returns true for field types that contain importable values.
func isImportableField(fieldType string) bool {
	switch strings.ToUpper(fieldType) {
	case "CONCEALED", "STRING", "PASSWORD", "EMAIL", "URL":
		return true
	}
	return false
}

// slugify converts a string to a Phoenix-compatible path segment:
// lowercase, spaces to hyphens, strip non-alphanumeric except -_/.
func slugify(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "-")
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
