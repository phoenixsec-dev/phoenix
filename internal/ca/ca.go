// Package ca is Phoenix's internal certificate authority. phoenix-server
// --init creates it, and it signs the server certificate for the HTTPS
// listener (https_listener); --reissue-cert signs a new one with more
// names. Clients trust it with PHOENIX_CA_CERT. It no longer issues client
// certificates: those were removed with mTLS.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

const (
	CAValidityYears    = 5
	ServerValidityDays = 365
	SerialNumberBits   = 128
)

var ErrCANotInitialized = errors.New("CA not initialized")

// CA holds the internal CA certificate and its private key.
type CA struct {
	mu      sync.RWMutex
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

// CertBundle is a signed certificate, its key and the CA certificate.
type CertBundle struct {
	CertPEM []byte
	KeyPEM  []byte
	CACert  []byte // CA certificate for verification
}

// GenerateCA creates a new self-signed CA certificate and key.
func GenerateCA(org string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   "Phoenix Internal CA",
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(CAValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("creating CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return &CA{
		cert:    cert,
		key:     key,
		certPEM: certPEM,
	}, nil
}

// LoadCA loads a CA from PEM-encoded cert and key files.
func LoadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA cert: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA key: %w", err)
	}

	return LoadCAFromPEM(certPEM, keyPEM)
}

// LoadCAFromPEM loads a CA from PEM-encoded bytes.
func LoadCAFromPEM(certPEM, keyPEM []byte) (*CA, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("failed to decode CA certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}

	if !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, errors.New("certificate is not a CA (BasicConstraints missing or IsCA=false)")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("CA certificate missing KeyUsageCertSign")
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("failed to decode CA key PEM")
	}

	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CA key: %w", err)
	}

	return &CA{
		cert:    cert,
		key:     key,
		certPEM: certPEM,
	}, nil
}

// SaveCA writes the CA cert and key to PEM files.
func (ca *CA) Save(certPath, keyPath string) error {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	if err := os.WriteFile(certPath, ca.certPEM, 0644); err != nil {
		return fmt.Errorf("writing CA cert: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		return fmt.Errorf("marshaling CA key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("writing CA key: %w", err)
	}

	return nil
}

// IssueServerCert creates a TLS server certificate signed by the CA.
// The hosts parameter should include hostnames and/or IP addresses
// that the server will be accessed at.
func (ca *CA) IssueServerCert(hosts []string) (*CertBundle, error) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	if ca.cert == nil || ca.key == nil {
		return nil, ErrCANotInitialized
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating server key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "Phoenix Server",
		},
		NotBefore: now,
		NotAfter:  now.AddDate(0, 0, ServerValidityDays),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &serverKey.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("signing server certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling server key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &CertBundle{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		CACert:  ca.certPEM,
	}, nil
}

// CertPEM returns the CA certificate in PEM format.
func (ca *CA) CertPEM() []byte {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.certPEM
}

// Fingerprint returns the SHA-256 fingerprint of the CA certificate's
// DER encoding for out-of-band verification.
func (ca *CA) Fingerprint() string {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	hash := sha256.Sum256(ca.cert.Raw)
	return fmt.Sprintf("%X", hash[:])
}

// --- Helpers ---

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), SerialNumberBits))
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}
	return serial, nil
}

// SaveBundle writes a CertBundle to files in the given directory.
func (b *CertBundle) Save(certPath, keyPath, caPath string) error {
	if err := os.WriteFile(certPath, b.CertPEM, 0644); err != nil {
		return fmt.Errorf("writing cert: %w", err)
	}
	if err := os.WriteFile(keyPath, b.KeyPEM, 0600); err != nil {
		return fmt.Errorf("writing key: %w", err)
	}
	if err := os.WriteFile(caPath, b.CACert, 0644); err != nil {
		return fmt.Errorf("writing CA cert: %w", err)
	}
	return nil
}
