package crypto

import (
	"fmt"
)

// KeyProvider abstracts master key operations for envelope encryption.
//
// The Store uses a KeyProvider to wrap/unwrap DEKs instead of holding a
// raw master key directly. This allows swapping the key storage backend
// (file, KMS, HSM) without changing any Store or API code.
//
// Rotation follows a two-phase commit protocol:
//  1. RotateMaster re-wraps DEKs but does NOT swap the active key.
//  2. CommitRotation atomically swaps the pending key into active use.
//  3. RollbackRotation discards the pending key on failure.
//
// This lets callers persist both the store and key file before committing
// the in-memory key swap, preventing inconsistency on partial failure.
type KeyProvider interface {
	// WrapKey encrypts a DEK using the provider's master key material.
	WrapKey(dek []byte) (*WrappedDEK, error)

	// UnwrapKey decrypts a wrapped DEK using the provider's master key material.
	UnwrapKey(wrapped *WrappedDEK) ([]byte, error)

	// RotateMaster re-wraps all provided DEKs under a new master key.
	// Returns the new wrapped DEKs in the same order as the input.
	// The new key is staged (not yet active) until CommitRotation is called.
	RotateMaster(wrappedDEKs []*WrappedDEK) ([]*WrappedDEK, error)

	// CommitRotation atomically promotes the staged key to active use.
	// No-op if no rotation is pending.
	CommitRotation()

	// RollbackRotation discards the staged key without affecting the active key.
	// No-op if no rotation is pending.
	RollbackRotation()

	// Name returns a human-readable provider name for logging/config.
	Name() string
}

// FileKeyProvider implements KeyProvider using a raw 256-bit key loaded from disk.
// This is the Phase 1 compatible implementation — same crypto, just behind an interface.
type FileKeyProvider struct {
	masterKey  []byte
	pendingKey []byte // non-nil during two-phase rotation
	passphrase string // set if master key is passphrase-protected
}

// NewFileKeyProvider creates a provider from a raw master key (already loaded).
func NewFileKeyProvider(masterKey []byte) (*FileKeyProvider, error) {
	if len(masterKey) != KeySize {
		return nil, ErrInvalidKey
	}
	return &FileKeyProvider{masterKey: masterKey}, nil
}

// NewFileKeyProviderFromPath loads the master key from a file and creates a provider.
func NewFileKeyProviderFromPath(keyPath string) (*FileKeyProvider, error) {
	key, err := LoadMasterKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("loading master key for file provider: %w", err)
	}
	return NewFileKeyProvider(key)
}

func (p *FileKeyProvider) WrapKey(dek []byte) (*WrappedDEK, error) {
	return WrapDEK(p.masterKey, dek)
}

func (p *FileKeyProvider) UnwrapKey(wrapped *WrappedDEK) ([]byte, error) {
	return UnwrapDEK(p.masterKey, wrapped)
}

func (p *FileKeyProvider) RotateMaster(wrappedDEKs []*WrappedDEK) ([]*WrappedDEK, error) {
	// 1. Unwrap all DEKs with current master key
	deks := make([][]byte, len(wrappedDEKs))
	for i, w := range wrappedDEKs {
		dek, err := UnwrapDEK(p.masterKey, w)
		if err != nil {
			return nil, fmt.Errorf("unwrapping DEK %d during rotation: %w", i, err)
		}
		deks[i] = dek
	}

	// 2. Generate new master key
	newKey, err := GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating new master key: %w", err)
	}

	// 3. Re-wrap all DEKs with new master key
	result := make([]*WrappedDEK, len(deks))
	for i, dek := range deks {
		wrapped, err := WrapDEK(newKey, dek)
		if err != nil {
			return nil, fmt.Errorf("re-wrapping DEK %d during rotation: %w", i, err)
		}
		result[i] = wrapped
	}

	// 4. Stage new key — do NOT swap masterKey yet (two-phase commit).
	// Caller must call CommitRotation() after persisting both the store
	// and the key file, or RollbackRotation() on failure.
	p.pendingKey = newKey

	return result, nil
}

// CommitRotation promotes the staged key to active use.
// Must be called after both the store and key file are persisted.
func (p *FileKeyProvider) CommitRotation() {
	if p.pendingKey != nil {
		p.masterKey = p.pendingKey
		p.pendingKey = nil
	}
}

// RollbackRotation discards the staged key.
// Call this if the store save or key file write fails.
func (p *FileKeyProvider) RollbackRotation() {
	p.pendingKey = nil
}

func (p *FileKeyProvider) Name() string {
	return "file"
}

// MasterKey returns the raw active master key bytes. This is needed for writing
// the key back to disk during rotation. Only FileKeyProvider exposes this —
// other providers (KMS, HSM) would never expose raw key material.
func (p *FileKeyProvider) MasterKey() []byte {
	return p.masterKey
}

// PendingMasterKey returns the staged (not yet committed) master key bytes.
// Returns nil if no rotation is pending.
func (p *FileKeyProvider) PendingMasterKey() []byte {
	return p.pendingKey
}

// SetPassphrase stores the passphrase used to protect the master key on disk.
// This is used during rotation to re-encrypt the new key file.
func (p *FileKeyProvider) SetPassphrase(pp string) {
	p.passphrase = pp
}

// Passphrase returns the passphrase, or "" if the key is unprotected.
func (p *FileKeyProvider) Passphrase() string {
	return p.passphrase
}
