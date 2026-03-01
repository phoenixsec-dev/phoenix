package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
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

func TestIssueAgentCert(t *testing.T) {
	ca, _ := GenerateCA("TestOrg")

	bundle, err := ca.IssueAgentCert("vector")
	if err != nil {
		t.Fatalf("IssueAgentCert: %v", err)
	}

	if len(bundle.CertPEM) == 0 {
		t.Fatal("cert PEM is empty")
	}
	if len(bundle.KeyPEM) == 0 {
		t.Fatal("key PEM is empty")
	}
	if len(bundle.CACert) == 0 {
		t.Fatal("CA cert is empty")
	}

	// Parse and verify the agent cert
	block, _ := pem.Decode(bundle.CertPEM)
	if block == nil {
		t.Fatal("failed to decode cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	if cert.Subject.CommonName != "vector" {
		t.Fatalf("expected CN 'vector', got %q", cert.Subject.CommonName)
	}
	if cert.IsCA {
		t.Fatal("agent cert should not be CA")
	}

	// Verify against CA
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	opts := x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := cert.Verify(opts); err != nil {
		t.Fatalf("cert verification failed: %v", err)
	}
}

func TestVerifyClientCert(t *testing.T) {
	ca, _ := GenerateCA("TestOrg")
	bundle, _ := ca.IssueAgentCert("openclaw")

	// Parse the cert
	block, _ := pem.Decode(bundle.CertPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	// Verify
	name, err := ca.VerifyClientCert([]*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("VerifyClientCert: %v", err)
	}
	if name != "openclaw" {
		t.Fatalf("expected agent name 'openclaw', got %q", name)
	}
}

func TestVerifyClientCertNoCerts(t *testing.T) {
	ca, _ := GenerateCA("TestOrg")

	_, err := ca.VerifyClientCert(nil)
	if err == nil {
		t.Fatal("expected error for no certs")
	}
}

func TestCRLRevocation(t *testing.T) {
	ca, _ := GenerateCA("TestOrg")
	bundle, _ := ca.IssueAgentCert("badagent")

	// Parse cert to get serial
	block, _ := pem.Decode(bundle.CertPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	// Should verify before revocation
	name, err := ca.VerifyClientCert([]*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("expected success before revocation: %v", err)
	}
	if name != "badagent" {
		t.Fatalf("wrong name: %q", name)
	}

	// Revoke
	if err := ca.RevokeCert(cert.SerialNumber, "badagent"); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}

	// Should fail after revocation
	_, err = ca.VerifyClientCert([]*x509.Certificate{cert})
	if err != ErrCertRevoked {
		t.Fatalf("expected ErrCertRevoked, got %v", err)
	}
}

func TestCRLIsRevoked(t *testing.T) {
	crl := &CRL{}

	serial := big.NewInt(12345)
	if crl.IsRevoked(serial) {
		t.Fatal("should not be revoked initially")
	}

	if err := crl.Revoke(serial, "test"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !crl.IsRevoked(serial) {
		t.Fatal("should be revoked after Revoke()")
	}

	// Different serial should not be revoked
	if crl.IsRevoked(big.NewInt(99999)) {
		t.Fatal("unrelated serial should not be revoked")
	}
}

func TestMultipleAgentCerts(t *testing.T) {
	ca, _ := GenerateCA("TestOrg")

	agents := []string{"vector", "openclaw", "homepage", "monitoring"}
	for _, name := range agents {
		bundle, err := ca.IssueAgentCert(name)
		if err != nil {
			t.Fatalf("issue cert for %s: %v", name, err)
		}

		block, _ := pem.Decode(bundle.CertPEM)
		cert, _ := x509.ParseCertificate(block.Bytes)

		got, err := ca.VerifyClientCert([]*x509.Certificate{cert})
		if err != nil {
			t.Fatalf("verify %s: %v", name, err)
		}
		if got != name {
			t.Fatalf("expected %q, got %q", name, got)
		}
	}
}

func TestAgentCertValidity(t *testing.T) {
	ca, _ := GenerateCA("TestOrg")
	bundle, _ := ca.IssueAgentCert("test")

	block, _ := pem.Decode(bundle.CertPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	// Should be valid now
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		t.Fatal("cert should be currently valid")
	}

	// Check validity period is approximately 90 days
	validity := cert.NotAfter.Sub(cert.NotBefore)
	expected := time.Duration(AgentValidityDays) * 24 * time.Hour
	diff := validity - expected
	if diff < -time.Hour || diff > time.Hour {
		t.Fatalf("validity %v is not ~%d days", validity, AgentValidityDays)
	}
}

func TestBundleSave(t *testing.T) {
	ca, _ := GenerateCA("TestOrg")
	bundle, _ := ca.IssueAgentCert("test")

	dir := t.TempDir()
	certPath := filepath.Join(dir, "agent.crt")
	keyPath := filepath.Join(dir, "agent.key")
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

func TestTLSConfig(t *testing.T) {
	ca, _ := GenerateCA("TestOrg")
	tlsCfg := ca.TLSConfig()

	if tlsCfg.ClientAuth != 3 { // tls.VerifyClientCertIfGiven
		t.Fatalf("expected VerifyClientCertIfGiven, got %d", tlsCfg.ClientAuth)
	}
	if tlsCfg.MinVersion != 0x0303 { // tls.VersionTLS12
		t.Fatalf("expected TLS 1.2 min, got %#x", tlsCfg.MinVersion)
	}
	if tlsCfg.ClientCAs == nil {
		t.Fatal("ClientCAs pool is nil")
	}
}

func TestWrongCARejectsAgentCert(t *testing.T) {
	ca1, _ := GenerateCA("Org1")
	ca2, _ := GenerateCA("Org2")

	// Issue cert from CA1
	bundle, _ := ca1.IssueAgentCert("agent")
	block, _ := pem.Decode(bundle.CertPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	// VerifyClientCert on CA2 should reject cert from CA1
	_, err := ca2.VerifyClientCert([]*x509.Certificate{cert})
	if err == nil {
		t.Fatal("cert from CA1 should not verify against CA2")
	}
	if !strings.Contains(err.Error(), "certificate chain verification failed") {
		t.Fatalf("expected chain verification error, got: %v", err)
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

func TestCRLPersistence(t *testing.T) {
	dir := t.TempDir()
	crlPath := filepath.Join(dir, "crl.json")

	// Create CRL, revoke a serial, check it persists
	crl, err := NewCRL(crlPath)
	if err != nil {
		t.Fatalf("NewCRL: %v", err)
	}

	serial := big.NewInt(42)
	if err := crl.Revoke(serial, "badagent"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// File should exist now
	data, err := os.ReadFile(crlPath)
	if err != nil {
		t.Fatalf("CRL file not written: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("CRL file is empty")
	}

	// Verify JSON is valid
	var parsed CRL
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("CRL file is not valid JSON: %v", err)
	}
	if len(parsed.Revoked) != 1 {
		t.Fatalf("expected 1 revoked entry, got %d", len(parsed.Revoked))
	}

	// Load CRL from file and check revocation survives
	crl2, err := NewCRL(crlPath)
	if err != nil {
		t.Fatalf("NewCRL reload: %v", err)
	}
	if !crl2.IsRevoked(serial) {
		t.Fatal("revocation should persist across reload")
	}
	if crl2.IsRevoked(big.NewInt(999)) {
		t.Fatal("unrevoked serial should not be revoked")
	}
}

func TestCRLPersistenceNoPath(t *testing.T) {
	// CRL without a path should not fail on Revoke
	crl, err := NewCRL("")
	if err != nil {
		t.Fatalf("NewCRL empty: %v", err)
	}
	if err := crl.Revoke(big.NewInt(1), "test"); err != nil {
		t.Fatalf("Revoke without path should not error: %v", err)
	}
	if !crl.IsRevoked(big.NewInt(1)) {
		t.Fatal("should be revoked in memory")
	}
}

func TestVerifyExpiredCert(t *testing.T) {
	authority, _ := GenerateCA("TestOrg")

	// Issue a cert, then manually create an expired one
	agentKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := randomSerial()

	// Cert that expired yesterday
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "expired-agent"},
		NotBefore:    now.AddDate(0, 0, -30),
		NotAfter:     now.AddDate(0, 0, -1), // expired yesterday
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, authority.cert, &agentKey.PublicKey, authority.key)
	if err != nil {
		t.Fatalf("create expired cert: %v", err)
	}

	expiredCert, _ := x509.ParseCertificate(certDER)

	_, err = authority.VerifyClientCert([]*x509.Certificate{expiredCert})
	if err == nil {
		t.Fatal("expected error for expired certificate")
	}
	if !strings.Contains(err.Error(), "certificate chain verification failed") {
		t.Fatalf("expected chain verification error, got: %v", err)
	}
}

func TestVerifyNotYetValidCert(t *testing.T) {
	authority, _ := GenerateCA("TestOrg")

	agentKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := randomSerial()

	// Cert valid starting tomorrow
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "future-agent"},
		NotBefore:    now.AddDate(0, 0, 1), // not yet valid
		NotAfter:     now.AddDate(0, 0, 91),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, authority.cert, &agentKey.PublicKey, authority.key)
	futureCert, _ := x509.ParseCertificate(certDER)

	_, err := authority.VerifyClientCert([]*x509.Certificate{futureCert})
	if err == nil {
		t.Fatal("expected error for not-yet-valid certificate")
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
