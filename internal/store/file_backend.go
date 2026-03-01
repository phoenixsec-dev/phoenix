package store

import "git.home/vector/phoenix/internal/crypto"

// FileBackend wraps the existing *Store to satisfy SecretBackend.
// This is a mechanical adapter — zero behavior change from direct Store use.
type FileBackend struct {
	store *Store
}

// NewFileBackend creates a FileBackend wrapping an existing Store.
func NewFileBackend(s *Store) *FileBackend {
	return &FileBackend{store: s}
}

func (b *FileBackend) Get(path string) (*Secret, error) {
	return b.store.Get(path)
}

func (b *FileBackend) List(prefix string) ([]string, error) {
	return b.store.List(prefix), nil
}

func (b *FileBackend) Set(path, value, createdBy, description string, tags []string) error {
	return b.store.Set(path, value, createdBy, description, tags)
}

func (b *FileBackend) Delete(path string) error {
	return b.store.Delete(path)
}

func (b *FileBackend) Count() int {
	return b.store.Count()
}

func (b *FileBackend) ReadOnly() bool {
	return false
}

func (b *FileBackend) Name() string {
	return "file"
}

// Store returns the underlying *Store for file-specific operations
// (e.g., master key rotation, metadata access).
func (b *FileBackend) Store() *Store {
	return b.store
}

// Provider returns the underlying Store's KeyProvider for rotation.
func (b *FileBackend) Provider() crypto.KeyProvider {
	return b.store.Provider()
}
