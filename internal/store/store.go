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

	"github.com/phoenixsec/phoenix/internal/crypto"
	"github.com/phoenixsec/phoenix/internal/fsutil"
)

var (
	ErrSecretNotFound = errors.New("secret not found")
	ErrInvalidPath    = errors.New("invalid secret path")
)

// SecretMetadata holds non-sensitive metadata about a secret.
type SecretMetadata struct {
	Created   time.Time `json:"created"`
	Updated   time.Time `json:"updated"`
	CreatedBy string    `json:"created_by"`
	// UpdatedBy is who wrote the current value. Empty on secrets last
	// written before it existed; then CreatedBy is the last writer, because
	// older versions overwrote CreatedBy on every update.
	UpdatedBy   string   `json:"updated_by,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	RotationDue string   `json:"rotation_due,omitempty"`
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
	Version    int                        `json:"version"`
	Secrets    map[string]encryptedSecret `json:"secrets"`
	Namespaces map[string]namespaceDEK    `json:"namespaces"`
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
		// The real file: rotation renames its backup over this path, which
		// must not replace a symlink.
		filePath: fsutil.RealPath(filePath),
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
			Version:    storeVersion,
			Secrets:    make(map[string]encryptedSecret),
			Namespaces: make(map[string]namespaceDEK),
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading store file: %w", err)
	}

	if err := s.parse(data); err != nil {
		return err
	}
	return s.checkKeyOpens()
}

// storeVersion is the format version of the store file, the only one so far.
const storeVersion = 1

// parse makes data, the contents of a store file, the in-memory store. Every
// store ever written has the three keys checked here. Anything else may be
// another file configured at this path by mistake (the ACL, the config, a
// protected key); loaded as an empty store, it would be replaced by the first
// write.
func (s *Store) parse(data []byte) error {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		return fmt.Errorf("parsing store file: %w", err)
	}
	if keys["version"] == nil || keys["secrets"] == nil || keys["namespaces"] == nil {
		return fmt.Errorf("%s is not a Phoenix store file; it was not changed. Check store.path; "+
			"if you meant to start with an empty store, move that file away", s.filePath)
	}
	var sd storeData
	if err := json.Unmarshal(data, &sd); err != nil {
		return fmt.Errorf("parsing store file: %w", err)
	}
	if sd.Version != storeVersion {
		return fmt.Errorf("%s is a version %d store file and this Phoenix reads version %d; it was not changed. "+
			"Run the Phoenix version that wrote it, or a newer one", s.filePath, sd.Version, storeVersion)
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

// checkKeyOpens refuses a store that the master key cannot open at all: the
// wrong key, or a rotation cut off between saving the store and saving the
// key. Nothing in such a store can be read anyway, and running on it makes
// things worse: new namespaces would be written under the other key. If only
// some namespaces are unreadable the server must still serve the rest, so
// that is logged instead.
func (s *Store) checkKeyOpens() error {
	var bad []string
	for name, entry := range s.data.Namespaces {
		dek, err := s.provider.UnwrapKey(&entry.Wrapped)
		if err != nil {
			bad = append(bad, name)
			continue
		}
		crypto.ZeroBytes(dek)
	}
	switch {
	case len(bad) == 0:
		return nil
	case len(bad) < len(s.data.Namespaces):
		sort.Strings(bad)
		log.Printf("WARNING: the master key does not open these namespaces in %s, their secrets cannot be read: %s",
			s.filePath, strings.Join(bad, ", "))
		return nil
	}
	hint := "check that store.master_key is the key this store was written with"
	if s.fileOpens(s.filePath + preRotateSuffix) {
		hint = fmt.Sprintf("a key rotation was cut off, and %[1]s%[2]s opens with the current key: "+
			"copy the data directory somewhere safe, then move %[1]s%[2]s over %[1]s", s.filePath, preRotateSuffix)
	}
	return fmt.Errorf("the master key does not open %s, so no secret in it can be read; nothing was changed. "+
		"Next: %s (docs/key-management.md, \"If rotation fails\")", s.filePath, hint)
}

// preRotateSuffix names the backup a rotation makes next to the store file.
const preRotateSuffix = ".pre-rotate"

// save writes the store to disk crash-safely: fsynced write-tmp + rename +
// directory fsync (fsutil.WriteFileAtomic). The whole store is one file, so
// a torn write here would lose every secret at once.
func (s *Store) save() error {
	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating store directory: %w", err)
	}
	if err := s.writeSnapshot(s.filePath); err != nil {
		return fmt.Errorf("saving store file: %w", err)
	}
	return nil
}

// Test seams: the store's file writer and the rotation-restore rename.
// Tests swap them to simulate a failing disk without chmod tricks.
var (
	writeFileAtomic = fsutil.WriteFileAtomic
	renameFile      = os.Rename
)

// writeSnapshot writes the in-memory store to path (crash-safe, mode 0600).
// Used for the live store file and the pre-rotation backup.
func (s *Store) writeSnapshot(path string) error {
	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling store: %w", err)
	}
	return writeFileAtomic(path, data, 0600)
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
		UpdatedBy:   createdBy,
		Description: description,
		Tags:        tags,
	}

	if exists {
		meta.Created = existing.Metadata.Created
		meta.CreatedBy = existing.Metadata.CreatedBy
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
// afterSave must return an error only when it did NOT persist the new key
// (the key file still holds the old key) — the rollback relies on that.
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

	// Back up the store before mutation. On callback failure we restore
	// via atomic rename instead of re-marshaling, which eliminates the
	// double-failure path where both callback and rollback-save fail.
	//
	// The backup is written from memory, not copied from the store file.
	// Memory always matches the active key; the file may not, because a
	// previous rotation that failed totally can leave abandoned new-key
	// wrappers on disk. Copying that file would overwrite the good backup
	// kept from that failure, and a second failure would then "restore"
	// a store no key on disk can open.
	preRotatePath := s.filePath + preRotateSuffix
	keepBackup := false // set when the backup is the operator's recovery path

	// failEarly handles a failure before this rotation replaced the store
	// file. An untouched file is not necessarily a readable one: a previous
	// rotation that failed totally can have left abandoned new-key wrappers
	// on disk, and then the backup is the only copy the key
	// file can open (review F1 R2, 2026-10-25). So the backup is deleted
	// only when the store file is checked to open with the current key.
	failEarly := func(err error) (int, error) {
		if afterSave == nil || s.fileOpens(s.filePath) {
			return 0, err
		}
		keepBackup = true
		recovery := "see docs/key-management.md"
		if s.fileOpens(preRotatePath) {
			recovery = fmt.Sprintf("restore %s over %s and keep the current key file", preRotatePath, s.filePath)
		}
		logUnreadableStore(recovery)
		return 0, fmt.Errorf("CRITICAL: %w; the store file on disk does not open with the current key "+
			"(left by an earlier failed rotation); recovery: %s", err, recovery)
	}

	// Rotate: unwrap all with old key, generate new key, re-wrap all.
	// The provider stages the new key (does not swap yet). This comes before
	// the backup: if memory does not open with the current key, a backup of
	// it is worthless and would replace an earlier one that may be good.
	newWrapped, err := s.provider.RotateMaster(wrappedDEKs)
	if err != nil {
		return failEarly(fmt.Errorf("rotating master key: %w", err))
	}
	if afterSave != nil {
		if err := s.writeSnapshot(preRotatePath); err != nil {
			s.provider.RollbackRotation()
			return failEarly(fmt.Errorf("backing up store before rotation: %w", err))
		}
		defer func() {
			if !keepBackup {
				os.Remove(preRotatePath)
			}
		}()
	}

	// Replace namespace entries with re-wrapped DEKs
	for i, name := range nsNames {
		s.data.Namespaces[name] = namespaceDEK{Wrapped: *newWrapped[i]}
	}

	// Persist the updated store atomically
	if err := s.save(); err != nil {
		// Rollback: restore old namespace entries + discard staged key.
		// The store file on disk is unchanged (save() uses tmp+rename;
		// if rename failed, the old file is still intact). failEarly
		// checks whether that old file is actually readable.
		for i, name := range nsNames {
			s.data.Namespaces[name] = oldEntries[i]
		}
		s.provider.RollbackRotation()
		return failEarly(fmt.Errorf("saving store after rotation: %w", err))
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
			restoreErr := renameFile(preRotatePath, s.filePath)
			if restoreErr == nil {
				// Without this the restore could be undone by a crash,
				// leaving new-key DEKs on disk next to the old key file.
				if syncErr := fsutil.SyncDir(filepath.Dir(s.filePath)); syncErr != nil {
					log.Printf("WARNING: store restored from backup but directory sync failed: %v", syncErr)
				}
				s.provider.RollbackRotation()
				return 0, fmt.Errorf("post-save callback: %w", err)
			}

			// Restore failed: the store on disk has new-key DEKs but the
			// key file still has the old key. Memory holds the old DEKs
			// again, so rewrite the store from memory to match the key file.
			if healErr := s.save(); healErr == nil {
				log.Printf("WARNING: rotation callback failed and backup restore failed (%v); "+
					"store rewritten from memory under the old key", restoreErr)
				s.provider.RollbackRotation()
				return 0, fmt.Errorf("post-save callback: %w (backup restore failed: %v; "+
					"store rewritten under the old key)", err, restoreErr)
			}

			// CRITICAL: nothing on disk could be repaired. Keep the
			// pre-rotate backup (old DEKs, matches the old key file) and
			// try the passphrase-encrypted emergency key.
			keepBackup = true
			var options []string
			if _, statErr := os.Stat(preRotatePath); statErr == nil {
				options = append(options, fmt.Sprintf("restore %s over %s and keep the current key file", preRotatePath, s.filePath))
			}
			if emergencyPath, emErr := s.emergencyPersistPendingKey(); emErr == nil {
				options = append(options, fmt.Sprintf("keep %s and put %s in place of the master key file (same passphrase)", s.filePath, emergencyPath))
			} else {
				log.Printf("CRITICAL: new master key not saved: %v", emErr)
			}
			recovery := "none on disk"
			if len(options) > 0 {
				recovery = strings.Join(options, ", or ")
			}
			s.provider.RollbackRotation()
			logUnreadableStore(recovery)
			return 0, fmt.Errorf("CRITICAL: callback failed: %w; store restore failed: %v; "+
				"store rewrite failed; recovery: %s", err, restoreErr, recovery)
		}
	}

	// Both writes succeeded — commit the provider key swap
	s.provider.CommitRotation()
	return len(nsNames), nil
}

// fileOpens reports whether the store file at path opens with the provider's
// active key: it parses and every namespace DEK unwraps. Any read or parse
// error counts as "does not open". RotateMasterKey uses it to decide whether
// the pre-rotate backup is still needed.
func (s *Store) fileOpens(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var sd storeData
	if err := json.Unmarshal(data, &sd); err != nil {
		return false
	}
	for _, entry := range sd.Namespaces {
		dek, err := s.provider.UnwrapKey(&entry.Wrapped)
		if err != nil {
			return false
		}
		crypto.ZeroBytes(dek)
	}
	return true
}

// logUnreadableStore logs the CRITICAL message for a failed rotation that
// left a store file the current key file cannot open. recovery lists the
// manual recovery steps that are actually available on disk.
func logUnreadableStore(recovery string) {
	log.Printf("CRITICAL: master key rotation failed and the store on disk may be unreadable. "+
		"The running server still has a working key and DEKs in memory; the next successful "+
		"write repairs the store, so do not restart before then. Manual recovery: %s", recovery)
}

// emergencyPersistPendingKey saves the provider's staged (new) master key
// to <store>.emergency-key and returns that path. It runs only in the
// rotation path where the callback, the backup restore, and the store
// rewrite all failed, so the store on disk may hold new-key DEKs.
//
// The key is written ONLY when a passphrase is configured, and then only
// passphrase-encrypted. With no passphrase it refuses and returns an error:
// Phoenix never writes an unprotected master key to a side file (review
// finding M2, 2026-07-19). The .pre-rotate backup covers recovery instead.
// The operator deletes the file once recovery is done.
func (s *Store) emergencyPersistPendingKey() (string, error) {
	fkp, ok := s.provider.(*crypto.FileKeyProvider)
	if !ok {
		return "", fmt.Errorf("provider %T does not expose key material", s.provider)
	}
	pending := fkp.PendingMasterKey()
	if pending == nil {
		return "", errors.New("no pending key")
	}
	defer crypto.ZeroBytes(pending)
	if fkp.Passphrase() == "" {
		return "", errors.New("no passphrase configured; refusing to write an unprotected master key")
	}
	emergencyPath := s.filePath + ".emergency-key"
	if err := crypto.SaveProtectedMasterKey(emergencyPath, pending, fkp.Passphrase()); err != nil {
		return "", fmt.Errorf("saving emergency key to %s: %w", emergencyPath, err)
	}
	return emergencyPath, nil
}

// Path returns the store file's real path (symlinks followed).
func (s *Store) Path() string { return s.filePath }

// Provider returns the store's KeyProvider.
// Used by the server to access the provider after rotation (e.g., to persist
// the new master key via FileKeyProvider.MasterKey()).
func (s *Store) Provider() crypto.KeyProvider {
	return s.provider
}

// GetMetadata returns just the metadata for a secret (no decryption needed).
func (s *Store) GetMetadata(path string) (*SecretMetadata, error) {
	if err := ValidatePath(path); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	enc, ok := s.data.Secrets[path]
	if !ok {
		return nil, ErrSecretNotFound
	}

	meta := enc.Metadata
	meta.Tags = append([]string(nil), enc.Metadata.Tags...)
	return &meta, nil
}
