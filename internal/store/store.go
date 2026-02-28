// Package store implements the encrypted secret storage engine.
//
// Secrets are organized by path (e.g., "openclaw/api-key") and stored in
// an encrypted JSON file on disk. Each secret's value is encrypted with a
// per-namespace DEK, which is itself wrapped by the master key (KEK).
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"git.home/vector/phoenix/internal/crypto"
)

var (
	ErrSecretNotFound = errors.New("secret not found")
	ErrInvalidPath    = errors.New("invalid secret path")
)

// SecretMetadata holds non-sensitive metadata about a secret.
type SecretMetadata struct {
	Created     time.Time `json:"created"`
	Updated     time.Time `json:"updated"`
	CreatedBy   string    `json:"created_by"`
	Description string    `json:"description,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	RotationDue string    `json:"rotation_due,omitempty"`
}

// encryptedSecret is the on-disk representation of a secret.
type encryptedSecret struct {
	Path      string               `json:"path"`
	Value     crypto.EncryptedBlob `json:"value"`
	Namespace string               `json:"namespace"`
	Metadata  SecretMetadata       `json:"metadata"`
}

// namespaceDEK is a wrapped data encryption key for a namespace.
type namespaceDEK struct {
	Wrapped crypto.WrappedDEK `json:"wrapped"`
}

// storeData is the top-level on-disk structure.
type storeData struct {
	Version    int                       `json:"version"`
	Secrets    map[string]encryptedSecret `json:"secrets"`
	Namespaces map[string]namespaceDEK   `json:"namespaces"`
}

// Secret is the decrypted representation returned to callers.
type Secret struct {
	Path     string         `json:"path"`
	Value    string         `json:"value"`
	Metadata SecretMetadata `json:"metadata"`
}

// Store is the main secret storage engine.
type Store struct {
	mu       sync.RWMutex
	provider crypto.KeyProvider
	data     *storeData
	filePath string
}

// NewWithProvider creates a new Store using a KeyProvider for all key operations.
// This is the preferred constructor for Phase 2+.
func NewWithProvider(filePath string, provider crypto.KeyProvider) (*Store, error) {
	s := &Store{
		provider: provider,
		filePath: filePath,
	}

	if err := s.load(); err != nil {
		return nil, err
	}

	return s, nil
}

// New creates a new Store backed by the given file, using the provided master key.
// This wraps the key in a FileKeyProvider for backward compatibility.
func New(filePath string, masterKey []byte) (*Store, error) {
	provider, err := crypto.NewFileKeyProvider(masterKey)
	if err != nil {
		return nil, fmt.Errorf("creating file key provider: %w", err)
	}
	return NewWithProvider(filePath, provider)
}

// load reads the store from disk, or initializes an empty store if the file doesn't exist.
func (s *Store) load() error {
	data, err := os.ReadFile(s.filePath)
	if errors.Is(err, os.ErrNotExist) {
		s.data = &storeData{
			Version:    1,
			Secrets:    make(map[string]encryptedSecret),
			Namespaces: make(map[string]namespaceDEK),
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading store file: %w", err)
	}

	var sd storeData
	if err := json.Unmarshal(data, &sd); err != nil {
		return fmt.Errorf("parsing store file: %w", err)
	}

	if sd.Secrets == nil {
		sd.Secrets = make(map[string]encryptedSecret)
	}
	if sd.Namespaces == nil {
		sd.Namespaces = make(map[string]namespaceDEK)
	}

	s.data = &sd
	return nil
}

// save writes the store to disk atomically (write-tmp + rename).
func (s *Store) save() error {
	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling store: %w", err)
	}

	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating store directory: %w", err)
	}

	tmp := s.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}

	if err := os.Rename(tmp, s.filePath); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("renaming temp file: %w", err)
	}

	return nil
}

// namespace extracts the namespace from a secret path (first segment).
func namespace(path string) string {
	parts := strings.SplitN(path, "/", 2)
	return parts[0]
}

// ValidatePath checks that a secret path is well-formed.
func ValidatePath(path string) error {
	if path == "" {
		return ErrInvalidPath
	}
	if strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") {
		return ErrInvalidPath
	}
	if !strings.Contains(path, "/") {
		return ErrInvalidPath
	}
	// Reject double slashes, dots
	if strings.Contains(path, "//") || strings.Contains(path, "..") {
		return ErrInvalidPath
	}
	return nil
}

// getDEK returns the DEK for a namespace, creating one if it doesn't exist.
func (s *Store) getDEK(ns string) ([]byte, error) {
	if wrapped, ok := s.data.Namespaces[ns]; ok {
		return s.provider.UnwrapKey(&wrapped.Wrapped)
	}

	// Generate new DEK for this namespace
	dek, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating DEK for namespace %q: %w", ns, err)
	}

	wrapped, err := s.provider.WrapKey(dek)
	if err != nil {
		return nil, fmt.Errorf("wrapping DEK for namespace %q: %w", ns, err)
	}

	s.data.Namespaces[ns] = namespaceDEK{Wrapped: *wrapped}
	return dek, nil
}

// Set creates or updates a secret.
func (s *Store) Set(path, value, createdBy, description string, tags []string) error {
	if err := ValidatePath(path); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ns := namespace(path)
	dek, err := s.getDEK(ns)
	if err != nil {
		return err
	}

	blob, err := crypto.Encrypt(dek, []byte(value))
	if err != nil {
		return fmt.Errorf("encrypting secret: %w", err)
	}

	now := time.Now().UTC()
	existing, exists := s.data.Secrets[path]

	meta := SecretMetadata{
		Created:     now,
		Updated:     now,
		CreatedBy:   createdBy,
		Description: description,
		Tags:        tags,
	}

	if exists {
		meta.Created = existing.Metadata.Created
		if description == "" {
			meta.Description = existing.Metadata.Description
		}
		if tags == nil {
			meta.Tags = existing.Metadata.Tags
		}
	}

	s.data.Secrets[path] = encryptedSecret{
		Path:      path,
		Value:     *blob,
		Namespace: ns,
		Metadata:  meta,
	}

	return s.save()
}

// Get retrieves a secret by path.
func (s *Store) Get(path string) (*Secret, error) {
	if err := ValidatePath(path); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	enc, ok := s.data.Secrets[path]
	if !ok {
		return nil, ErrSecretNotFound
	}

	dek, err := s.getDEKReadOnly(enc.Namespace)
	if err != nil {
		return nil, err
	}

	plaintext, err := crypto.Decrypt(dek, &enc.Value)
	if err != nil {
		return nil, fmt.Errorf("decrypting secret: %w", err)
	}

	return &Secret{
		Path:     enc.Path,
		Value:    string(plaintext),
		Metadata: enc.Metadata,
	}, nil
}

// getDEKReadOnly returns an existing DEK without creating new ones.
func (s *Store) getDEKReadOnly(ns string) ([]byte, error) {
	wrapped, ok := s.data.Namespaces[ns]
	if !ok {
		return nil, fmt.Errorf("no DEK for namespace %q", ns)
	}
	return s.provider.UnwrapKey(&wrapped.Wrapped)
}

// Delete removes a secret by path.
func (s *Store) Delete(path string) error {
	if err := ValidatePath(path); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.data.Secrets[path]; !ok {
		return ErrSecretNotFound
	}

	delete(s.data.Secrets, path)
	return s.save()
}

// List returns all secret paths, optionally filtered by prefix.
func (s *Store) List(prefix string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var paths []string
	for path := range s.data.Secrets {
		if prefix == "" || strings.HasPrefix(path, prefix) {
			paths = append(paths, path)
		}
	}

	sort.Strings(paths)
	return paths
}

// Count returns the number of secrets in the store.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data.Secrets)
}

// RotateMasterKey re-wraps all namespace DEKs under a new master key.
//
// The afterSave callback, if non-nil, runs after the store is persisted
// but before the store lock is released. This lets the caller atomically
// write the key file while no concurrent reads can observe partial state.
// If afterSave returns an error, the store file is restored from a
// pre-rotation backup (atomic rename), and the provider's pending key
// is rolled back.
//
// When afterSave is nil (e.g. in unit tests), the provider's rotation is
// auto-committed after a successful save.
//
// This operation is O(namespaces), not O(secrets), because only the
// DEK wrappers change — secret ciphertext remains untouched.
func (s *Store) RotateMasterKey(afterSave func() error) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Collect namespace names and their wrapped DEKs in stable order
	nsNames := make([]string, 0, len(s.data.Namespaces))
	for name := range s.data.Namespaces {
		nsNames = append(nsNames, name)
	}
	sort.Strings(nsNames)

	if len(nsNames) == 0 {
		return 0, nil
	}

	// Snapshot old namespace entries for in-memory rollback
	oldEntries := make([]namespaceDEK, len(nsNames))
	wrappedDEKs := make([]*crypto.WrappedDEK, len(nsNames))
	for i, name := range nsNames {
		oldEntries[i] = s.data.Namespaces[name]
		w := s.data.Namespaces[name].Wrapped
		wrappedDEKs[i] = &w
	}

	// Backup the store file before mutation. On callback failure we
	// restore via atomic rename instead of re-marshaling, which
	// eliminates the double-failure path where both callback and
	// rollback-save fail.
	preRotatePath := s.filePath + ".pre-rotate"
	if afterSave != nil {
		if err := copyFile(s.filePath, preRotatePath); err != nil {
			return 0, fmt.Errorf("backing up store before rotation: %w", err)
		}
		defer os.Remove(preRotatePath)
	}

	// Rotate: unwrap all with old key, generate new key, re-wrap all.
	// The provider stages the new key (does not swap yet).
	newWrapped, err := s.provider.RotateMaster(wrappedDEKs)
	if err != nil {
		return 0, fmt.Errorf("rotating master key: %w", err)
	}

	// Replace namespace entries with re-wrapped DEKs
	for i, name := range nsNames {
		s.data.Namespaces[name] = namespaceDEK{Wrapped: *newWrapped[i]}
	}

	// Persist the updated store atomically
	if err := s.save(); err != nil {
		// Rollback: restore old namespace entries + discard staged key.
		// The store file on disk is unchanged (save() uses tmp+rename;
		// if rename failed, the old file is still intact).
		for i, name := range nsNames {
			s.data.Namespaces[name] = oldEntries[i]
		}
		s.provider.RollbackRotation()
		return 0, fmt.Errorf("saving store after rotation: %w", err)
	}

	// Run post-save callback (e.g. write key file) while still under lock.
	// No concurrent reads can see the new DEKs until we release the lock.
	if afterSave != nil {
		if err := afterSave(); err != nil {
			// Restore in-memory state
			for i, name := range nsNames {
				s.data.Namespaces[name] = oldEntries[i]
			}

			// Restore store file from pre-rotation backup via atomic rename.
			// This is more reliable than re-marshaling + re-saving because
			// it's a single rename syscall on the same filesystem.
			if restoreErr := os.Rename(preRotatePath, s.filePath); restoreErr != nil {
				// CRITICAL: store on disk has new DEKs but key file has
				// old key, and we cannot restore the old store. Persist the
				// pending key to an emergency file so an operator can
				// forward-recover using the new key + on-disk store.
				s.emergencyPersistPendingKey()
				s.provider.RollbackRotation()
				return 0, fmt.Errorf("CRITICAL: callback failed: %w; store restore failed: %v; "+
					"check for %s.emergency-key or use .prev backup", err, restoreErr, s.filePath)
			}

			s.provider.RollbackRotation()
			return 0, fmt.Errorf("post-save callback: %w", err)
		}
	}

	// Both writes succeeded — commit the provider key swap
	s.provider.CommitRotation()
	return len(nsNames), nil
}

// emergencyPersistPendingKey saves the provider's staged key to an
// emergency recovery file as a last resort. This is called only in the
// double-failure path where both the afterSave callback and the store
// file restore fail, to prevent the new key from being lost.
func (s *Store) emergencyPersistPendingKey() {
	fkp, ok := s.provider.(*crypto.FileKeyProvider)
	if !ok || fkp.PendingMasterKey() == nil {
		return
	}
	emergencyPath := s.filePath + ".emergency-key"
	var err error
	if fkp.Passphrase() != "" {
		err = crypto.SaveProtectedMasterKey(emergencyPath, fkp.PendingMasterKey(), fkp.Passphrase())
	} else {
		err = crypto.SaveMasterKeyAtomic(emergencyPath, fkp.PendingMasterKey())
	}
	if err != nil {
		log.Printf("CRITICAL: failed to save emergency key to %s: %v", emergencyPath, err)
		return
	}
	log.Printf("CRITICAL: emergency recovery key saved to %s — "+
		"use this key with the current store file to recover, "+
		"or restore store from .pre-rotate backup with the old key", emergencyPath)
}

// copyFile copies src to dst with 0600 permissions.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0600)
}

// Provider returns the store's KeyProvider.
// Used by the server to access the provider after rotation (e.g., to persist
// the new master key via FileKeyProvider.MasterKey()).
func (s *Store) Provider() crypto.KeyProvider {
	return s.provider
}

// GetMetadata returns just the metadata for a secret (no decryption needed).
func (s *Store) GetMetadata(path string) (*SecretMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	enc, ok := s.data.Secrets[path]
	if !ok {
		return nil, ErrSecretNotFound
	}

	meta := enc.Metadata
	return &meta, nil
}
