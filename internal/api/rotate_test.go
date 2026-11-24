package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/phoenixsec/phoenix/internal/crypto"
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
}
