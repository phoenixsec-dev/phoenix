package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/phoenixsec/phoenix/internal/crypto"
	"github.com/phoenixsec/phoenix/internal/fsutil"
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
	raw, _ := os.ReadFile(storePath)
	sd, err := parseStore(storePath, raw)
	if err != nil {
		t.Fatal(err)
	}
	s := &Store{provider: provider, filePath: storePath, data: sd}
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

// store.path pointing at some other JSON file (the ACL, the config, a
// protected master key) must not load as an empty store: the first write
// would replace that file.
func TestForeignFileIsRefusedAsStore(t *testing.T) {
	key, _ := crypto.GenerateKey()
	for name, content := range map[string]string{
		"acl":           `{"agents":{"admin":{"name":"admin","token_hash":"sha256:x","permissions":[]}}}`,
		"config":        `{"server":{"listen":"127.0.0.1:9090"},"store":{"path":"/data/store.json"}}`,
		"protected key": `{"phoenix_protected_key":1,"kdf":"argon2id","salt":"x"}`,
		"grants":        `{"version":1,"requests":{},"grants":{}}`,
		"sessions":      `{"version":1,"roles":{},"sessions":[]}`,
		"empty object":  `{}`,
		"null":          `null`,
		"empty file":    ``,
		"list":          `[]`,
		"newer format":  `{"version":2,"secrets":{},"namespaces":{}}`,
		"cut off":       `{"version":1,"secrets":{"ns/a":{`,
		"two documents": `{"version":1,"secrets":{},"namespaces":{}}{"ts":"2026-01-01T00:00:00Z"}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "store.json")
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := New(path, key); err == nil {
				t.Error("want a refusal")
			}
			if after, _ := os.ReadFile(path); string(after) != content {
				t.Error("the file was changed")
			}
		})
	}
}

// A Set or Delete whose save failed changed nothing: not what is read now, and
// not what the next save that works writes to disk.
func TestFailedSaveIsNotSavedLater(t *testing.T) {
	s, storePath, key := rotationFailureStore(t, "")
	if err := s.Set("ns1/gone", "first", "courier", "", nil); err != nil {
		t.Fatal(err)
	}
	repair := breakStoreDisk(t)
	for what, err := range map[string]error{
		"update": s.Set("ns1/key1", "half-done", "courier", "", nil),
		"create": s.Set("new/key", "half-done", "courier", "", nil),
		"delete": s.Delete("ns2/key2"),
	} {
		if err == nil {
			t.Fatalf("%s should fail", what)
		}
	}
	check := func(when string, st *Store) {
		t.Helper()
		for p, want := range map[string]string{"ns1/key1": "value1", "ns2/key2": "value2"} {
			if sec, err := st.Get(p); err != nil || sec.Value != want {
				t.Errorf("%s: %s = %v %v, want %q", when, p, sec, err, want)
			}
		}
		if _, err := st.Get("new/key"); err != ErrSecretNotFound {
			t.Errorf("%s: new/key: %v, want not found", when, err)
		}
	}
	check("after the failures", s)
	repair()
	if err := s.Delete("ns1/gone"); err != nil {
		t.Fatal(err)
	}
	again, err := New(storePath, key)
	if err != nil {
		t.Fatal(err)
	}
	check("after the next save", again)
}

// A file that is not a store with something in it is never offered as a
// recovery: following that advice would replace the store with it.
func TestForeignBackupIsNotRecommended(t *testing.T) {
	_, storePath, _ := rotationFailureStore(t, "")
	raw, _ := os.ReadFile(storePath)
	noKeys := regexp.MustCompile(`(?s)"namespaces": \{.*`).ReplaceAllString(string(raw), `"namespaces": {}}`)
	wrong, _ := crypto.GenerateKey()
	for name, content := range map[string]string{
		"empty object": `{}`, "null": `null`, "acl": `{"agents":{}}`,
		"empty store":    `{"version":1,"secrets":{},"namespaces":{}}`,
		"keys missing":   noKeys,
		"same wrong key": string(raw),
	} {
		if err := os.WriteFile(storePath+".pre-rotate", []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := New(storePath, wrong); err == nil || strings.Contains(err.Error(), ".pre-rotate") {
			t.Errorf("%s: %v, want a refusal that does not recommend it", name, err)
		}
	}
}

// A damaged namespace key is an unreadable namespace, not a crash at start.
func TestDamagedNamespaceKeyDoesNotPanic(t *testing.T) {
	s, storePath, key := rotationFailureStore(t, "")
	for name, nonce := range map[string]string{"short": "AAAA", "empty": "", "long": strings.Repeat("A", 32)} {
		w := s.data.Namespaces["ns1"].Wrapped
		w.Nonce = nonce
		s.data.Namespaces["odd"] = namespaceDEK{Wrapped: w}
		if err := s.save(); err != nil {
			t.Fatal(err)
		}
		t.Run(name, func(t *testing.T) { assertOpensWithKey(t, storePath, key) })
	}
}

// If the new key file is in place but may not survive a power cut, the
// rotation is done and the backup that opens with the old key is kept.
func TestRotationKeepsBackupWhenKeyMayNotSurvive(t *testing.T) {
	s, storePath, oldKey := rotationFailureStore(t, "")
	p := s.Provider().(*crypto.FileKeyProvider)
	if _, err := s.RotateMasterKey(func() error { return fmt.Errorf("saving: %w", fsutil.ErrDirSyncFailed) }); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(p.MasterKey(), oldKey) {
		t.Fatal("the new key was not taken into use")
	}
	assertOpensWithKey(t, storePath, p.MasterKey())
	assertOpensWithKey(t, storePath+".pre-rotate", oldKey) // after the power cut
}

// A backup name that is a link to the store must not lead a rotation into the
// store, whether it works or fails.
func TestRotationIgnoresLinkAtBackupName(t *testing.T) {
	for _, fails := range []bool{false, true} {
		s, storePath, oldKey := rotationFailureStore(t, "")
		if err := os.Symlink(storePath, storePath+".pre-rotate"); err != nil {
			t.Fatal(err)
		}
		_, err := s.RotateMasterKey(func() error {
			if fails {
				return os.ErrPermission
			}
			return nil
		})
		if (err != nil) != fails {
			t.Fatalf("rotate: %v", err)
		}
		key := oldKey
		if !fails {
			key = s.Provider().(*crypto.FileKeyProvider).MasterKey()
		}
		assertOpensWithKey(t, storePath, key)
		if fi, err := os.Lstat(storePath); err != nil || !fi.Mode().IsRegular() {
			t.Errorf("fails=%v: the store is not a file any more: %v", fails, err)
		}
	}
}

// A backup that opens but whose secrets are not the store's is not a recovery,
// and a store with a missing namespace key is not rotated over a backup.
func TestIncompleteStoresAreNotTrusted(t *testing.T) {
	storePath, oldKey := crashMidRotation(t)
	good, _ := os.ReadFile(storePath + ".pre-rotate")
	for what, change := range map[string]func(sd *storeData){
		"one missing": func(sd *storeData) { delete(sd.Secrets, "ns1/key1") },
		"all missing": func(sd *storeData) { sd.Secrets = map[string]encryptedSecret{} },
		"one extra":   func(sd *storeData) { sd.Secrets["ns1/deleted"] = sd.Secrets["ns1/key1"] },
		"one damaged": func(sd *storeData) {
			sec := sd.Secrets["ns1/key1"]
			sec.Value.Ciphertext = ""
			sd.Secrets["ns1/key1"] = sec
		},
		"one older": func(sd *storeData) {
			sec := sd.Secrets["ns1/key1"]
			sec.Value = sd.Secrets["ns2/key2"].Value
			sd.Secrets["ns1/key1"] = sec
		},
	} {
		sd, err := parseStore("", good)
		if err != nil {
			t.Fatal(err)
		}
		change(sd)
		b, _ := json.Marshal(sd)
		if err := os.WriteFile(storePath+".pre-rotate", b, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := New(storePath, oldKey); err == nil || strings.Contains(err.Error(), ".pre-rotate") {
			t.Errorf("%s: %v, want a refusal that does not recommend it", what, err)
		}
	}

	s, live, _ := rotationFailureStore(t, "")
	if err := s.writeSnapshot(live + ".pre-rotate"); err != nil {
		t.Fatal(err)
	}
	whole, _ := os.ReadFile(live + ".pre-rotate")
	delete(s.data.Namespaces, "ns1")
	if _, err := s.RotateMasterKey(func() error { return nil }); err == nil || !strings.Contains(err.Error(), "ns1") {
		t.Errorf("rotate = %v, want a refusal naming ns1", err)
	}
	if now, _ := os.ReadFile(live + ".pre-rotate"); !bytes.Equal(now, whole) {
		t.Error("the complete backup was overwritten")
	}
}
