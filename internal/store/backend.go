package store

import "errors"

// ErrReadOnly is returned by Set/Delete on read-only backends.
var ErrReadOnly = errors.New("backend is read-only")

// SecretBackend abstracts secret storage for the API layer.
// Implementations: FileBackend (Phoenix's own store), OPBackend (1Password).
type SecretBackend interface {
	// Get retrieves a decrypted secret by path.
	Get(path string) (*Secret, error)

	// List returns secret paths matching a prefix.
	List(prefix string) ([]string, error)

	// Set creates or updates a secret. Returns ErrReadOnly for read-only backends.
	Set(path, value, createdBy, description string, tags []string) error

	// Delete removes a secret. Returns ErrReadOnly for read-only backends.
	Delete(path string) error

	// Count returns the number of secrets (may be approximate for external backends).
	Count() int

	// ReadOnly returns true if Set/Delete are not supported.
	ReadOnly() bool

	// Name returns the backend name for logging/status.
	Name() string
}
