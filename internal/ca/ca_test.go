package ca

import (
	"crypto/x509"
	"encoding/pem"
	"math/big"
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
	ca.RevokeCert(cert.SerialNumber, "badagent")

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

	crl.Revoke(serial, "test")
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

	// Verify against CA2 — should fail standard x509 verification
	pool := x509.NewCertPool()
	pool.AddCert(ca2.cert)
	opts := x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	_, err := cert.Verify(opts)
	if err == nil {
		t.Fatal("cert from CA1 should not verify against CA2")
	}
}
