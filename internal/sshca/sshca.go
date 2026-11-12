// Package sshca is a small SSH certificate authority: it keeps one signing key
// on the server's disk and turns an agent's public key into a short-lived login
// certificate. The signing key is never stored as a secret and no API returns
// it, so no ACL rule, however broad, can read it.
package sshca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// clockSkew backdates a certificate's start so a machine whose clock runs a
// little behind the server still accepts it.
const clockSkew = 30 * time.Second

// LoadOrCreate returns the signing key at path, making a new ed25519 key on
// first use. It refuses a symlink or a file other users can read, and it never
// overwrites an existing file.
func LoadOrCreate(path string) (signer ssh.Signer, created bool, err error) {
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		signer, err = create(path)
		return signer, err == nil, err
	case err != nil:
		return nil, false, err
	case !fi.Mode().IsRegular():
		return nil, false, fmt.Errorf("%s is not a regular file", path)
	case fi.Mode().Perm()&0o077 != 0:
		return nil, false, fmt.Errorf("%s has mode %o; it must be readable by its owner only", path, fi.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	signer, err = ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, false, fmt.Errorf("%s is not an SSH private key: %w", path, err)
	}
	return signer, false, nil
}

func create(path string) (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "phoenix-ssh-ca")
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(pem.EncodeToMemory(block)); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

// PublicKey returns the CA's public key in authorized_keys format. This is what
// each machine installs to trust certificates from this server.
func PublicKey(ca ssh.Signer) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca.PublicKey())))
}

// CertRequest says who a certificate is for and where and when it works.
type CertRequest struct {
	PublicKey   string    // the agent's key in authorized_keys format; ed25519 only
	Principal   string    // the machine's name, matched against its principals file
	KeyID       string    // shows up in the machine's sshd log, so it names the agent and grant
	SourceIP    string    // the certificate only works from this address
	Now         time.Time // start of validity, less clockSkew
	ValidBefore time.Time // end of validity
}

// Sign returns a user certificate in authorized_keys format. It allows a
// terminal but no agent, port or X11 forwarding.
func Sign(ca ssh.Signer, req CertRequest) (string, error) {
	pub, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		return "", errors.New("public_key is not a valid SSH public key")
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return "", errors.New("public_key must be a single key")
	}
	if pub.Type() != ssh.KeyAlgoED25519 {
		return "", errors.New("public_key must be an ssh-ed25519 key")
	}
	if !req.ValidBefore.After(req.Now) {
		return "", errors.New("certificate would already be expired")
	}
	var serial [8]byte
	if _, err := rand.Read(serial[:]); err != nil {
		return "", err
	}
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          binary.BigEndian.Uint64(serial[:]),
		CertType:        ssh.UserCert,
		KeyId:           req.KeyID,
		ValidPrincipals: []string{req.Principal},
		ValidAfter:      uint64(req.Now.Add(-clockSkew).Unix()),
		ValidBefore:     uint64(req.ValidBefore.Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{"source-address": req.SourceIP},
			Extensions:      map[string]string{"permit-pty": ""},
		},
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		return "", err
	}
	return string(ssh.MarshalAuthorizedKey(cert)), nil
}
