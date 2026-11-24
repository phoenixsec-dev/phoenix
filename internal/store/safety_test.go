package store

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phoenixsec/phoenix/internal/crypto"
)

// crashMidRotation returns a store path as a power cut between saving the
// store and saving the new key leaves it: the store under the new key, the
// pre-rotate backup under the old one, and the old key still in master.key.
func crashMidRotation(t *testing.T) (storePath string, oldKey []byte) {
	t.Helper()
	s, live, oldKey := rotationFailureStore(t, "")
	storePath = filepath.Join(t.TempDir(), "store.json")
	if _, err := s.RotateMasterKey(func() error {
		for _, suffix := range []string{"", ".pre-rotate"} {
			b, err := os.ReadFile(live + suffix)
			if err != nil {
				return err
			}
			if err := os.WriteFile(storePath+suffix, b, 0600); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return storePath, oldKey
}

// A store the key cannot open is refused at start, with the recovery that is
// really there. Serving it would let a write under the old key mix two keys in
// one file, and a retried rotation overwrite the one good copy.
func TestStoreLeftByInterruptedRotationIsRefused(t *testing.T) {
	storePath, oldKey := crashMidRotation(t)
	before, _ := os.ReadFile(storePath)
	_, err := New(storePath, oldKey)
	if err == nil || !strings.Contains(err.Error(), storePath+".pre-rotate") {
		t.Fatalf("New = %v, want a refusal naming the backup", err)
	}
	if after, _ := os.ReadFile(storePath); !bytes.Equal(before, after) {
		t.Error("the refused store file was changed")
	}
	if err := os.Rename(storePath+".pre-rotate", storePath); err != nil {
		t.Fatal(err)
	}
	assertOpensWithKey(t, storePath, oldKey)
}

// With the wrong key and no backup the refusal must not promise one.
func TestWrongMasterKeyIsRefusedWithoutFalseRecovery(t *testing.T) {
	_, storePath, _ := rotationFailureStore(t, "")
	wrong, _ := crypto.GenerateKey()
	if _, err := New(storePath, wrong); err == nil || strings.Contains(err.Error(), ".pre-rotate") {
		t.Fatalf("New = %v, want a refusal that names no backup", err)
	}
}

// One unreadable namespace among good ones does not stop the server: the rest
// must stay reachable. It is logged.
func TestOneUnreadableNamespaceStillStarts(t *testing.T) {
	s, storePath, key := rotationFailureStore(t, "")
	other, _ := crypto.GenerateKey()
	dek, _ := crypto.GenerateKey()
	w, err := crypto.WrapDEK(other, dek)
	if err != nil {
		t.Fatal(err)
	}
	s.data.Namespaces["odd"] = namespaceDEK{Wrapped: *w}
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	assertOpensWithKey(t, storePath, key)
	if !strings.Contains(buf.String(), "odd") {
		t.Errorf("log = %q, want the namespace named", buf.String())
	}
}

// A rotation that cannot even read the store with the current key must leave
// an earlier pre-rotate backup alone: it may be the only good copy.
func TestRotationThatCannotUnwrapKeepsEarlierBackup(t *testing.T) {
	storePath, oldKey := crashMidRotation(t)
	good, err := os.ReadFile(storePath + ".pre-rotate")
	if err != nil {
		t.Fatal(err)
	}
	// Built by hand: New refuses this store (above), older versions did not.
	provider, _ := crypto.NewFileKeyProvider(oldKey)
	s := &Store{provider: provider, filePath: storePath}
	raw, _ := os.ReadFile(storePath)
	if err := s.parse(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RotateMasterKey(func() error { return nil }); err == nil {
		t.Fatal("rotation should fail")
	}
	if now, _ := os.ReadFile(storePath + ".pre-rotate"); !bytes.Equal(now, good) {
		t.Error("the good backup was overwritten")
	}
}

// A rotation that has to restore the store puts it back where the store's
// symlink points, not over the link.
func TestRotationRestoresThroughSymlink(t *testing.T) {
	_, realPath, key := rotationFailureStore(t, "")
	link := filepath.Join(t.TempDir(), "store.json")
	if err := os.Symlink(realPath, link); err != nil {
		t.Fatal(err)
	}
	s, err := New(link, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RotateMasterKey(func() error { return os.ErrPermission }); err == nil {
		t.Fatal("rotation should fail")
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link is gone: %v %v", fi, err)
	}
	assertOpensWithKey(t, realPath, key)
}
