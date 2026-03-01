package store

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/phoenixsec/phoenix/internal/op"
)

// OPBackend reads secrets from 1Password via the op CLI.
// It is read-only — Set and Delete return ErrReadOnly.
type OPBackend struct {
	client   *op.Client
	vault    string
	cacheTTL time.Duration

	mu    sync.RWMutex
	cache map[string]*cachedEntry

	listMu    sync.RWMutex
	listCache *cachedList
}

type cachedEntry struct {
	secret  *Secret
	expires time.Time
}

type cachedList struct {
	paths   []string
	expires time.Time
}

// NewOPBackend creates a 1Password backend.
// vault is the 1Password vault name. cacheTTL controls how long read
// results are cached (0 disables caching).
func NewOPBackend(client *op.Client, vault string, cacheTTL time.Duration) *OPBackend {
	return &OPBackend{
		client:   client,
		vault:    vault,
		cacheTTL: cacheTTL,
		cache:    make(map[string]*cachedEntry),
	}
}

// Get retrieves a secret from 1Password.
// Phoenix path "ns/secret-name" maps to op://vault/ns/secret-name.
func (b *OPBackend) Get(path string) (*Secret, error) {
	if err := ValidatePath(path); err != nil {
		return nil, err
	}

	// Check cache
	if b.cacheTTL > 0 {
		b.mu.RLock()
		if entry, ok := b.cache[path]; ok && time.Now().Before(entry.expires) {
			s := entry.secret
			b.mu.RUnlock()
			return s, nil
		}
		b.mu.RUnlock()
	}

	ref := fmt.Sprintf("op://%s/%s", b.vault, path)
	value, err := b.client.Read(ref)
	if err != nil {
		return nil, b.mapError(path, err)
	}

	secret := &Secret{
		Path:  path,
		Value: value,
		Metadata: SecretMetadata{
			Description: "1Password: " + ref,
		},
	}

	// Populate cache
	if b.cacheTTL > 0 {
		b.mu.Lock()
		b.cache[path] = &cachedEntry{
			secret:  secret,
			expires: time.Now().Add(b.cacheTTL),
		}
		b.mu.Unlock()
	}

	return secret, nil
}

// List returns secret paths from 1Password items in the configured vault.
// Since `op item list` returns metadata only (no field values/labels),
// this method fetches each item individually via GetItem to discover
// field labels. Results are cached for cacheTTL to avoid repeated
// expensive listing operations.
func (b *OPBackend) List(prefix string) ([]string, error) {
	// Check list cache (unfiltered)
	if b.cacheTTL > 0 {
		b.listMu.RLock()
		if b.listCache != nil && time.Now().Before(b.listCache.expires) {
			all := b.listCache.paths
			b.listMu.RUnlock()
			return filterPrefix(all, prefix), nil
		}
		b.listMu.RUnlock()
	}

	allPaths, err := b.fetchAllPaths()
	if err != nil {
		return nil, err
	}

	// Cache the full unfiltered list
	if b.cacheTTL > 0 {
		b.listMu.Lock()
		b.listCache = &cachedList{
			paths:   allPaths,
			expires: time.Now().Add(b.cacheTTL),
		}
		b.listMu.Unlock()
	}

	return filterPrefix(allPaths, prefix), nil
}

// fetchAllPaths lists items then fetches each to discover fields.
func (b *OPBackend) fetchAllPaths() ([]string, error) {
	items, err := b.client.ListItems(b.vault)
	if err != nil {
		return nil, fmt.Errorf("listing 1Password items: %w", err)
	}

	var paths []string
	for _, item := range items {
		if skipCategory(item.Category) {
			continue
		}

		// ListItems returns metadata only — fetch full item for fields.
		full, err := b.client.GetItem(b.vault, item.ID)
		if err != nil {
			// Log but skip items we can't fetch rather than failing the whole list.
			continue
		}

		for _, field := range full.Fields {
			if field.Label == "" || !isSecretField(field.Type) {
				continue
			}
			paths = append(paths, slugify(full.Title)+"/"+slugify(field.Label))
		}
	}

	return paths, nil
}

// filterPrefix returns only paths matching the given prefix.
func filterPrefix(paths []string, prefix string) []string {
	if prefix == "" {
		return paths
	}
	var filtered []string
	for _, p := range paths {
		if strings.HasPrefix(p, prefix) {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// Set is not supported — 1Password backend is read-only.
func (b *OPBackend) Set(path, value, createdBy, description string, tags []string) error {
	return ErrReadOnly
}

// Delete is not supported — 1Password backend is read-only.
func (b *OPBackend) Delete(path string) error {
	return ErrReadOnly
}

// Count returns -1 (unknown) for 1Password backend since counting
// requires listing all items which may be expensive.
func (b *OPBackend) Count() int {
	return -1
}

// ReadOnly returns true.
func (b *OPBackend) ReadOnly() bool {
	return true
}

// Name returns "1password".
func (b *OPBackend) Name() string {
	return "1password"
}

// mapError translates op client errors to store errors.
func (b *OPBackend) mapError(path string, err error) error {
	if isNotFound(err) {
		return ErrSecretNotFound
	}
	return fmt.Errorf("1password backend: reading %q: %w", path, err)
}

// isNotFound checks if the error wraps op.ErrNotFound.
func isNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), op.ErrNotFound.Error())
}

// skipCategory returns true for 1Password categories that shouldn't
// be treated as secrets.
func skipCategory(category string) bool {
	switch strings.ToUpper(category) {
	case "SSH_KEY", "DOCUMENT", "CREDIT_CARD", "BANK_ACCOUNT":
		return true
	}
	return false
}

// isSecretField returns true for field types that contain secret values.
func isSecretField(fieldType string) bool {
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
