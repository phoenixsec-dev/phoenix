// Package op wraps the 1Password CLI for secret retrieval.
//
// All interaction is via exec.Command("op", ...) — no Go SDK exists.
// The service account token is passed via subprocess environment only
// and is never logged or returned in error messages.
package op

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

var (
	ErrNotFound     = errors.New("item not found")
	ErrPermission   = errors.New("permission denied")
	ErrTimeout      = errors.New("op command timed out")
	ErrNotAvailable = errors.New("op CLI not available")
	ErrTokenMissing = errors.New("service account token not set")
)

// DefaultTimeout is the per-command timeout for op CLI calls.
const DefaultTimeout = 10 * time.Second

// Item represents a 1Password item (metadata + fields).
type Item struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Vault    VaultRef `json:"vault"`
	Category string   `json:"category"`
	Fields   []Field  `json:"fields"`
}

// VaultRef is an item's vault reference.
type VaultRef struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// Vault represents a 1Password vault.
type Vault struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Field represents a single field within a 1Password item.
type Field struct {
	ID    string `json:"id"`
	Type  string `json:"type"` // STRING, CONCEALED, EMAIL, URL, OTP, etc.
	Label string `json:"label"`
	Value string `json:"value"`
}

// Client wraps the 1Password CLI.
type Client struct {
	tokenEnv string        // env var name holding OP_SERVICE_ACCOUNT_TOKEN
	timeout  time.Duration // per-command timeout
	opPath   string        // path to op binary (empty = find in PATH)
}

// Option configures a Client.
type Option func(*Client)

// WithTimeout sets the per-command timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.timeout = d }
}

// WithOPPath overrides the op binary path (for testing).
func WithOPPath(path string) Option {
	return func(c *Client) { c.opPath = path }
}

// New creates a Client. tokenEnv is the env var name holding the service
// account token (default: OP_SERVICE_ACCOUNT_TOKEN).
func New(tokenEnv string, opts ...Option) *Client {
	if tokenEnv == "" {
		tokenEnv = "OP_SERVICE_ACCOUNT_TOKEN"
	}
	c := &Client{
		tokenEnv: tokenEnv,
		timeout:  DefaultTimeout,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Available checks if the op binary is in PATH and the token env var is set.
func (c *Client) Available() error {
	opBin := c.opBinary()
	if _, err := exec.LookPath(opBin); err != nil {
		return fmt.Errorf("%w: %s not found in PATH", ErrNotAvailable, opBin)
	}
	if os.Getenv(c.tokenEnv) == "" {
		return fmt.Errorf("%w: %s environment variable is empty", ErrTokenMissing, c.tokenEnv)
	}
	return nil
}

// Read fetches a single secret value by op:// reference.
// Example: "op://Vault/Item/Field"
func (c *Client) Read(ref string) (string, error) {
	out, err := c.run("read", ref)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// ListVaults returns all accessible vaults.
func (c *Client) ListVaults() ([]Vault, error) {
	out, err := c.run("vault", "list", "--format", "json")
	if err != nil {
		return nil, err
	}
	var vaults []Vault
	if err := json.Unmarshal(out, &vaults); err != nil {
		return nil, fmt.Errorf("parsing vault list: %w", err)
	}
	return vaults, nil
}

// ListItems returns all items in a vault (metadata only, no field values).
func (c *Client) ListItems(vault string) ([]Item, error) {
	out, err := c.run("item", "list", "--vault", vault, "--format", "json")
	if err != nil {
		return nil, err
	}
	var items []Item
	if err := json.Unmarshal(out, &items); err != nil {
		return nil, fmt.Errorf("parsing item list: %w", err)
	}
	return items, nil
}

// GetItem returns a single item with all fields populated.
func (c *Client) GetItem(vault, titleOrID string) (*Item, error) {
	out, err := c.run("item", "get", titleOrID, "--vault", vault, "--format", "json")
	if err != nil {
		return nil, err
	}
	var item Item
	if err := json.Unmarshal(out, &item); err != nil {
		return nil, fmt.Errorf("parsing item: %w", err)
	}
	return &item, nil
}

// opBinary returns the op binary name or path.
func (c *Client) opBinary() string {
	if c.opPath != "" {
		return c.opPath
	}
	return "op"
}

// run executes an op CLI command with timeout and token env.
func (c *Client) run(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.opBinary(), args...)
	// Pass token via environment only — never as argument.
	cmd.Env = append(os.Environ(), c.tokenEnv+"="+os.Getenv(c.tokenEnv))

	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, c.mapError(ctx, err, out)
	}
	return out, nil
}

// mapError converts op CLI errors to typed errors.
func (c *Client) mapError(ctx context.Context, err error, stderr []byte) error {
	if ctx.Err() == context.DeadlineExceeded {
		return ErrTimeout
	}

	msg := strings.TrimSpace(string(stderr))

	// Sanitize: never include the token value in error messages.
	tokenVal := os.Getenv(c.tokenEnv)
	if tokenVal != "" {
		msg = strings.ReplaceAll(msg, tokenVal, "[REDACTED]")
	}

	if strings.Contains(msg, "isn't an item") ||
		strings.Contains(msg, "not found") ||
		strings.Contains(msg, "could not be found") {
		return fmt.Errorf("%w: %s", ErrNotFound, msg)
	}

	if strings.Contains(msg, "unauthorized") ||
		strings.Contains(msg, "permission") ||
		strings.Contains(msg, "Authentication") {
		return fmt.Errorf("%w: %s", ErrPermission, msg)
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return fmt.Errorf("op command failed (exit %d): %s", exitErr.ExitCode(), msg)
	}

	return fmt.Errorf("op command failed: %w", err)
}
