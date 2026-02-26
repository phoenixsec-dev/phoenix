package crypto

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestFileKeyProviderWrapUnwrap(t *testing.T) {
	masterKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	provider, err := NewFileKeyProvider(masterKey)
	if err != nil {
		t.Fatal(err)
	}

	if provider.Name() != "file" {
		t.Fatalf("expected name 'file', got %q", provider.Name())
	}

	// Generate a DEK and wrap/unwrap it
	dek, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	wrapped, err := provider.WrapKey(dek)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}

	unwrapped, err := provider.UnwrapKey(wrapped)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}

	if !bytes.Equal(dek, unwrapped) {
		t.Fatal("unwrapped DEK does not match original")
	}
}

func TestFileKeyProviderFromPath(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")

	masterKey, err := GenerateAndSaveMasterKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	provider, err := NewFileKeyProviderFromPath(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the loaded key matches
	if !bytes.Equal(provider.MasterKey(), masterKey) {
		t.Fatal("provider key does not match generated key")
	}
}

func TestFileKeyProviderInvalidKey(t *testing.T) {
	_, err := NewFileKeyProvider([]byte("too-short"))
	if err != ErrInvalidKey {
		t.Fatalf("expected ErrInvalidKey, got %v", err)
	}
}

func TestFileKeyProviderRotateMaster(t *testing.T) {
	masterKey, _ := GenerateKey()
	provider, _ := NewFileKeyProvider(masterKey)

	// Create several DEKs and wrap them
	numDEKs := 5
	originalDEKs := make([][]byte, numDEKs)
	wrappedDEKs := make([]*WrappedDEK, numDEKs)
	for i := 0; i < numDEKs; i++ {
		dek, _ := GenerateKey()
		originalDEKs[i] = dek
		wrapped, err := provider.WrapKey(dek)
		if err != nil {
			t.Fatalf("wrapping DEK %d: %v", i, err)
		}
		wrappedDEKs[i] = wrapped
	}

	oldKey := make([]byte, len(provider.MasterKey()))
	copy(oldKey, provider.MasterKey())

	// Rotate
	newWrapped, err := provider.RotateMaster(wrappedDEKs)
	if err != nil {
		t.Fatalf("RotateMaster: %v", err)
	}

	// Master key should have changed
	if bytes.Equal(oldKey, provider.MasterKey()) {
		t.Fatal("master key did not change after rotation")
	}

	// All DEKs should unwrap to the same values under the new master key
	for i, w := range newWrapped {
		dek, err := provider.UnwrapKey(w)
		if err != nil {
			t.Fatalf("unwrapping rotated DEK %d: %v", i, err)
		}
		if !bytes.Equal(dek, originalDEKs[i]) {
			t.Fatalf("rotated DEK %d does not match original", i)
		}
	}

	// Old wrapped DEKs should NOT unwrap with new master key
	for i, w := range wrappedDEKs {
		_, err := provider.UnwrapKey(w)
		if err == nil {
			t.Fatalf("old wrapped DEK %d should not unwrap with new master key", i)
		}
	}
}

func TestFileKeyProviderCompatibility(t *testing.T) {
	// Verify that FileKeyProvider produces the same results as raw WrapDEK/UnwrapDEK
	masterKey, _ := GenerateKey()
	provider, _ := NewFileKeyProvider(masterKey)

	dek, _ := GenerateKey()

	// Wrap with provider
	wrapped, _ := provider.WrapKey(dek)

	// Unwrap with raw function using same key
	unwrapped, err := UnwrapDEK(masterKey, wrapped)
	if err != nil {
		t.Fatalf("raw UnwrapDEK: %v", err)
	}
	if !bytes.Equal(dek, unwrapped) {
		t.Fatal("provider and raw function are not compatible")
	}

	// Wrap with raw function, unwrap with provider
	rawWrapped, _ := WrapDEK(masterKey, dek)
	unwrapped2, err := provider.UnwrapKey(rawWrapped)
	if err != nil {
		t.Fatalf("provider UnwrapKey from raw wrap: %v", err)
	}
	if !bytes.Equal(dek, unwrapped2) {
		t.Fatal("raw wrap + provider unwrap are not compatible")
	}
}

// Verify KeyProvider interface is satisfied at compile time
var _ KeyProvider = (*FileKeyProvider)(nil)
