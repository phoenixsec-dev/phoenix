// Package ref handles phoenix:// secret reference parsing and formatting.
//
// References are opaque identifiers that point to secrets in the Phoenix
// store without exposing their values. The format is:
//
//	phoenix://namespace/secret-name
//
// References can appear in config files, environment variables, and agent
// tool calls. They are resolved to actual values only through the
// authenticated /v1/resolve endpoint.
package ref

import (
	"fmt"
	"strings"

	"git.home/vector/phoenix/internal/store"
)

// Scheme is the prefix for all Phoenix secret references.
const Scheme = "phoenix://"

// Parse extracts the secret path from a phoenix:// reference.
// Returns an error if the reference is malformed or the path is invalid.
func Parse(reference string) (string, error) {
	if !strings.HasPrefix(reference, Scheme) {
		return "", fmt.Errorf("invalid reference %q: must start with %s", reference, Scheme)
	}
	path := strings.TrimPrefix(reference, Scheme)
	if path == "" {
		return "", fmt.Errorf("invalid reference %q: empty path", reference)
	}
	if err := store.ValidatePath(path); err != nil {
		return "", fmt.Errorf("invalid reference %q: %w", reference, err)
	}
	return path, nil
}

// Format creates a phoenix:// reference from a secret path.
func Format(path string) string {
	return Scheme + path
}

// IsRef checks whether a string is a phoenix:// reference.
func IsRef(s string) bool {
	return strings.HasPrefix(s, Scheme)
}
