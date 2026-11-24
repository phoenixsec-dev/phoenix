package sshca

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func agentKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(sshPub))
}

func TestLoadOrCreateKeepsTheSameKeyAndRefusesLooseFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh_ca.key")
	first, created, err := LoadOrCreate(path)
	if err != nil || !created {
		t.Fatalf("create: created=%v err=%v", created, err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, err = %v", fi.Mode().Perm(), err)
	}
	second, created, err := LoadOrCreate(path)
	if err != nil || created {
		t.Fatalf("reload: created=%v err=%v", created, err)
	}
	if PublicKey(first) != PublicKey(second) {
		t.Fatal("reload produced a different key")
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreate(path); err == nil {
		t.Fatal("a group-readable key must be refused")
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreate(link); err == nil {
		t.Fatal("a symlink must be refused")
	}
}

func TestLoadOrCreateRefusesAFileThatIsNotAKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreate(path); err == nil {
		t.Fatal("expected a parse error")
	}
	if data, _ := os.ReadFile(path); string(data) != "not a key" {
		t.Fatal("an existing file must never be overwritten")
	}
}

func TestSignLimitsWhoWhereAndWhen(t *testing.T) {
	ca, _, err := LoadOrCreate(filepath.Join(t.TempDir(), "ca"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	until := now.Add(15 * time.Minute)
	out, err := Sign(ca, CertRequest{
		PublicKey: agentKey(t), Principal: "build-1", KeyID: "agent=vector grant=gnt_1",
		SourceIP: "192.0.2.30", Now: now, ValidBefore: until,
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	cert := parsed.(*ssh.Certificate)
	if cert.CertType != ssh.UserCert || len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "build-1" {
		t.Fatalf("type=%d principals=%v", cert.CertType, cert.ValidPrincipals)
	}
	if cert.ValidBefore != uint64(until.Unix()) || cert.ValidAfter >= uint64(now.Unix()) {
		t.Fatalf("validity %d..%d", cert.ValidAfter, cert.ValidBefore)
	}
	if cert.CriticalOptions["source-address"] != "192.0.2.30" {
		t.Fatalf("source-address = %q", cert.CriticalOptions["source-address"])
	}
	for _, ext := range []string{"permit-port-forwarding", "permit-agent-forwarding", "permit-X11-forwarding", "permit-user-rc"} {
		if _, ok := cert.Extensions[ext]; ok {
			t.Fatalf("%s must not be allowed", ext)
		}
	}
	checker := ssh.CertChecker{IsUserAuthority: func(k ssh.PublicKey) bool {
		return string(k.Marshal()) == string(ca.PublicKey().Marshal())
	}, Clock: func() time.Time { return now }}
	if err := checker.CheckCert("build-1", cert); err != nil {
		t.Fatalf("a real checker refused it: %v", err)
	}
	if err := checker.CheckCert("gpu-1", cert); err == nil {
		t.Fatal("the certificate must not work for another machine")
	}
}

func TestSignRefusals(t *testing.T) {
	ca, _, err := LoadOrCreate(filepath.Join(t.TempDir(), "ca"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	key := agentKey(t)
	cases := map[string]CertRequest{
		"garbage":  {PublicKey: "nope", ValidBefore: now.Add(time.Minute)},
		"two keys": {PublicKey: key + key, ValidBefore: now.Add(time.Minute)},
		"expired":  {PublicKey: key, ValidBefore: now},
	}
	for name, req := range cases {
		req.Now = now
		if _, err := Sign(ca, req); err == nil {
			t.Errorf("%s: expected a refusal", name)
		}
	}
	// A certificate is not a key: nobody gets to re-sign one to extend it.
	cert, err := Sign(ca, CertRequest{PublicKey: key, Principal: "x", SourceIP: "10.0.0.1", Now: now, ValidBefore: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(ca, CertRequest{PublicKey: strings.TrimSpace(cert), Principal: "x", SourceIP: "10.0.0.1", Now: now, ValidBefore: now.Add(time.Hour)}); err == nil {
		t.Fatal("re-signing a certificate must be refused")
	}
}

// A key cut off while being made must not be left at its path: the server
// would refuse to start on it. It is written elsewhere and moved into place,
// so the path holds a whole key or nothing.
func TestKeyIsMovedIntoPlaceWhole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh_ca.key")
	var partial bool
	write := writeKeyFile
	defer func() { writeKeyFile = write }()
	writeKeyFile = func(p string, data []byte, perm os.FileMode) error {
		if p != path || len(data) == 0 || perm != 0600 {
			t.Errorf("write %s, %d bytes, %o", p, len(data), perm)
		}
		_, err := os.Lstat(path)
		partial = err == nil
		return os.ErrInvalid // the write fails
	}
	if _, _, err := LoadOrCreate(path); err == nil || partial {
		t.Fatalf("err %v, partial file %v", err, partial)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("a failed write left something: %v", err)
	}
	writeKeyFile = write
	first, created, err := LoadOrCreate(path)
	if err != nil || !created {
		t.Fatalf("created %v, err %v", created, err)
	}
	again, created, err := LoadOrCreate(path)
	if err != nil || created || PublicKey(first) != PublicKey(again) {
		t.Errorf("reload: created %v, err %v", created, err)
	}
}
