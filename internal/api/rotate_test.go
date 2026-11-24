package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phoenixsec/phoenix/internal/crypto"
	"github.com/phoenixsec/phoenix/internal/fsutil"
	"github.com/phoenixsec/phoenix/internal/store"
)

func rotateMaster(srv *Server) int {
	req := httptest.NewRequest("POST", "/v1/rotate-master", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w.Code
}

// The key file changed under the running server (phoenix-server --protect-key,
// or another key put there). Rotating would save the new key with the old
// passphrase, or none, over a file it never read. It is refused and nothing
// changes.
func TestRotateRefusedWhenKeyFileChanged(t *testing.T) {
	changes := map[string]func(path string, key []byte) error{
		"passphrase added": func(path string, key []byte) error { return crypto.SaveProtectedMasterKey(path, key, "fake-pass") },
		"another key": func(path string, _ []byte) error {
			_, err := crypto.GenerateAndSaveMasterKey(path)
			return err
		},
		"missing": func(path string, _ []byte) error { return os.Remove(path) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			srv, _ := setupTestServer(t)
			seedSecret(t, srv, "admin-token", "test/a", "synthetic-value")
			key := srv.fileBackend.Provider().(*crypto.FileKeyProvider).MasterKey()
			if err := change(srv.masterKeyPath, key); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(srv.masterKeyPath)
			if code := rotateMaster(srv); code != http.StatusConflict {
				t.Errorf("rotate = %d, want 409", code)
			}
			if after, _ := os.ReadFile(srv.masterKeyPath); !bytes.Equal(before, after) {
				t.Error("the key file was changed")
			}
			if _, err := os.Stat(srv.masterKeyPath + ".prev"); !os.IsNotExist(err) {
				t.Errorf(".prev was written: %v", err)
			}
			if _, err := store.New(srv.fileBackend.Store().Path(), key); err != nil {
				t.Errorf("store no longer opens with the key it had: %v", err)
			}
		})
	}
}

// A protected key is rotated under its passphrase, and .prev always holds the
// key before the last rotation that worked: a failed one leaves it alone.
func TestRotateKeepsPassphraseAndPrev(t *testing.T) {
	srv, _ := setupTestServer(t)
	seedSecret(t, srv, "admin-token", "test/a", "synthetic-value")
	p := srv.fileBackend.Provider().(*crypto.FileKeyProvider)
	first := p.MasterKey()
	if err := crypto.SaveProtectedMasterKey(srv.masterKeyPath, first, "fake-pass"); err != nil {
		t.Fatal(err)
	}
	p.SetPassphrase("fake-pass")
	prevIsFirst := func(when string) {
		t.Helper()
		if got, err := crypto.LoadMasterKeyWithPassphrase(srv.masterKeyPath+".prev", "fake-pass"); err != nil || !bytes.Equal(got, first) {
			t.Errorf("%s: .prev does not hold the first key: %v", when, err)
		}
	}
	if code := rotateMaster(srv); code != http.StatusOK {
		t.Fatalf("rotate = %d", code)
	}
	prevIsFirst("after a rotation")
	if got, err := crypto.LoadMasterKeyWithPassphrase(srv.masterKeyPath, "fake-pass"); err != nil || !bytes.Equal(got, p.MasterKey()) {
		t.Errorf("new key file: %v", err)
	}
	// A rotation that cannot back up the store fails before it changes anything.
	if err := os.Mkdir(srv.fileBackend.Store().Path()+".pre-rotate", 0700); err != nil {
		t.Fatal(err)
	}
	if code := rotateMaster(srv); code != http.StatusInternalServerError {
		t.Fatalf("second rotate = %d, want 500", code)
	}
	prevIsFirst("after a failed rotation")
	if err := os.Remove(srv.fileBackend.Store().Path() + ".pre-rotate"); err != nil {
		t.Fatal(err)
	}
	// Nor does one that fails at the very last step, saving the new key.
	second := p.MasterKey()
	blocked := srv.masterKeyPath
	srv.masterKeyPath = filepath.Join(t.TempDir(), "master.key")
	if err := os.Symlink(blocked, srv.masterKeyPath); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(blocked + ".prev"); err != nil || os.WriteFile(srv.masterKeyPath+".prev", b, 0600) != nil {
		t.Fatal("setup")
	}
	if err := os.Chmod(filepath.Dir(blocked), 0500); err != nil {
		t.Fatal(err)
	}
	// Only the key file's directory is blocked; store and .prev are elsewhere.
	defer os.Chmod(filepath.Dir(blocked), 0700)
	code := rotateMaster(srv)
	os.Chmod(filepath.Dir(blocked), 0700)
	if code == http.StatusOK {
		t.Skip("running as a user the mode does not stop")
	}
	if !bytes.Equal(p.MasterKey(), second) {
		t.Error("the key changed although it could not be saved")
	}
	prevIsFirst("after a failed key save")
	if ents, _ := filepath.Glob(filepath.Join(filepath.Dir(srv.masterKeyPath), "*.new")); len(ents) != 0 {
		t.Errorf("left behind: %v", ents)
	}
}

// .prev as a link to the store (or anything else) is replaced, not followed.
func TestRotateIgnoresLinkAtPrev(t *testing.T) {
	srv, _ := setupTestServer(t)
	seedSecret(t, srv, "admin-token", "test/a", "synthetic-value")
	st := srv.fileBackend.Store().Path()
	for _, name := range []string{".prev", ".prev.new"} {
		if err := os.Symlink(st, srv.masterKeyPath+name); err != nil {
			t.Fatal(err)
		}
	}
	if code := rotateMaster(srv); code != http.StatusOK {
		t.Fatalf("rotate = %d", code)
	}
	key, err := crypto.LoadMasterKey(srv.masterKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.New(st, key); err != nil {
		t.Errorf("the store: %v", err)
	}
}

// A master key another running server uses is not rotated: its store would no
// longer open.
func TestRotateRefusedWhileKeyIsShared(t *testing.T) {
	srv, _ := setupTestServer(t)
	seedSecret(t, srv, "admin-token", "test/a", "synthetic-value")
	mine, err := fsutil.LockUsers(srv.masterKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	srv.SetMasterKeyLock(mine)
	other, err := fsutil.LockUsers(srv.masterKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(srv.masterKeyPath)
	if code := rotateMaster(srv); code != http.StatusConflict {
		t.Errorf("shared: %d, want 409", code)
	}
	if after, _ := os.ReadFile(srv.masterKeyPath); !bytes.Equal(before, after) {
		t.Error("the key file was changed")
	}
	other.Release()
	if code := rotateMaster(srv); code != http.StatusOK {
		t.Errorf("alone: %d, want 200", code)
	}
}

// If the old key cannot take the name .prev, the answer names the file that
// really holds it, and the next rotation, even a failing one, does not lose it.
func TestUnpromotedOldKeyIsNotLost(t *testing.T) {
	srv, _ := setupTestServer(t)
	seedSecret(t, srv, "admin-token", "test/a", "synthetic-value")
	first := srv.fileBackend.Provider().(*crypto.FileKeyProvider).MasterKey()
	prev := srv.masterKeyPath + ".prev"
	if err := os.MkdirAll(filepath.Join(prev, "in-the-way"), 0700); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/v1/rotate-master", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), prev+".new") {
		t.Fatalf("rotate = %d %s, want the staged name", w.Code, w.Body)
	}
	if code := rotateMaster(srv); code != http.StatusInternalServerError {
		t.Errorf("rotate with the old key still unplaced = %d, want 500", code)
	}
	if got, err := crypto.LoadMasterKey(prev + ".new"); err != nil || !bytes.Equal(got, first) {
		t.Errorf("the old key is gone: %v", err)
	}
	if err := os.RemoveAll(prev); err != nil {
		t.Fatal(err)
	}
	// Free again: the leftover is placed first, then overtaken as usual.
	second := srv.fileBackend.Provider().(*crypto.FileKeyProvider).MasterKey()
	if code := rotateMaster(srv); code != http.StatusOK {
		t.Fatalf("rotate = %d", code)
	}
	if got, err := crypto.LoadMasterKey(prev); err != nil || !bytes.Equal(got, second) {
		t.Errorf(".prev: %v", err)
	}
}
