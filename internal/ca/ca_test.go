package ca

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateCA(t *testing.T) {
	ca, err := GenerateCA("OpenClaw")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	if ca.cert == nil {
		t.Fatal("CA cert is nil")
	}
	if !ca.cert.IsCA {
		t.Fatal("cert is not marked as CA")
	}
	if ca.cert.Subject.CommonName != "Phoenix Internal CA" {
		t.Fatalf("unexpected CN: %q", ca.cert.Subject.CommonName)
	}
	if len(ca.certPEM) == 0 {
		t.Fatal("certPEM is empty")
	}
}

func TestCASaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	// Generate and save
	ca1, err := GenerateCA("TestOrg")
	if err != nil {
		t.Fatal(err)
	}
	if err := ca1.Save(certPath, keyPath); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Load
	ca2, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	if ca2.cert.Subject.CommonName != "Phoenix Internal CA" {
		t.Fatalf("loaded CA has wrong CN: %q", ca2.cert.Subject.CommonName)
	}
	if !ca2.cert.IsCA {
		t.Fatal("loaded cert is not CA")
	}
}

func TestBundleSave(t *testing.T) {
	ca, _ := GenerateCA("TestOrg")
	bundle, _ := ca.IssueServerCert([]string{"localhost"})

	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	caPath := filepath.Join(dir, "ca.crt")

	if err := bundle.Save(certPath, keyPath, caPath); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Verify files exist and are readable
	for _, p := range []string{certPath, keyPath, caPath} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if info.Size() == 0 {
			t.Fatalf("%s is empty", p)
		}
	}
}

func TestIssueServerCert(t *testing.T) {
	authority, _ := GenerateCA("TestOrg")

	bundle, err := authority.IssueServerCert([]string{"localhost", "127.0.0.1", "phoenix.local"})
	if err != nil {
		t.Fatalf("IssueServerCert: %v", err)
	}

	if len(bundle.CertPEM) == 0 {
		t.Fatal("server cert PEM is empty")
	}

	block, _ := pem.Decode(bundle.CertPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}

	// Check EKU is serverAuth
	found := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			found = true
		}
	}
	if !found {
		t.Fatal("server cert missing serverAuth EKU")
	}

	// Check SANs
	if len(cert.DNSNames) != 2 || cert.DNSNames[0] != "localhost" || cert.DNSNames[1] != "phoenix.local" {
		t.Fatalf("unexpected DNS SANs: %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "127.0.0.1" {
		t.Fatalf("unexpected IP SANs: %v", cert.IPAddresses)
	}

	// Check not CA
	if cert.IsCA {
		t.Fatal("server cert should not be CA")
	}

	// Verify chain against CA
	pool := x509.NewCertPool()
	pool.AddCert(authority.cert)
	opts := x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if _, err := cert.Verify(opts); err != nil {
		t.Fatalf("server cert chain verification failed: %v", err)
	}

	// Check validity period is ~365 days
	validity := cert.NotAfter.Sub(cert.NotBefore)
	expected := time.Duration(ServerValidityDays) * 24 * time.Hour
	diff := validity - expected
	if diff < -time.Hour || diff > time.Hour {
		t.Fatalf("validity %v is not ~%d days", validity, ServerValidityDays)
	}
}

func TestLoadCAFromPEMInvalidPEM(t *testing.T) {
	_, err := LoadCAFromPEM([]byte("not a pem"), []byte("not a pem"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestFingerprintIsSHA256(t *testing.T) {
	authority, _ := GenerateCA("TestOrg")
	fp := authority.Fingerprint()

	// Compute expected SHA-256
	expected := sha256.Sum256(authority.cert.Raw)
	expectedStr := fmt.Sprintf("%X", expected[:])

	if fp != expectedStr {
		t.Fatalf("Fingerprint mismatch:\n  got:      %s\n  expected: %s", fp, expectedStr)
	}

	// SHA-256 hex should be 64 chars
	if len(fp) != 64 {
		t.Fatalf("fingerprint should be 64 hex chars, got %d: %s", len(fp), fp)
	}
}

func TestLoadCAFromPEM_RejectsNonCA(t *testing.T) {
	authority, _ := GenerateCA("Test")
	bundle, _ := authority.IssueServerCert([]string{"localhost"})
	_, err := LoadCAFromPEM(bundle.CertPEM, bundle.KeyPEM)
	if err == nil {
		t.Fatal("LoadCAFromPEM should reject non-CA certificates")
	}
}
