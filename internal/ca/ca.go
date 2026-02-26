// Package ca implements an internal Certificate Authority for Phoenix mTLS.
//
// The CA generates a self-signed root certificate and signs client certificates
// for agents. Agent identity is bound to the certificate's Common Name (CN),
// which maps directly to the ACL agent name.
//
// Certificate lifecycle:
//   - CA cert: 5-year validity, generated at init time
//   - Agent certs: 90-day validity, signed by CA
//   - Revocation via CRL (Certificate Revocation List)
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	CAValidityYears    = 5
	AgentValidityDays  = 90
	ServerValidityDays = 365
	SerialNumberBits   = 128
)

var (
	ErrCANotInitialized = errors.New("CA not initialized")
	ErrCertExpired      = errors.New("certificate has expired")
	ErrCertRevoked      = errors.New("certificate has been revoked")
)

// CA is the internal Certificate Authority.
type CA struct {
	mu      sync.RWMutex
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	crl     *CRL
}

// CRL tracks revoked certificate serial numbers.
type CRL struct {
	mu      sync.RWMutex
	Revoked []RevokedEntry `json:"revoked"`
	path    string
}

// RevokedEntry records a revoked certificate.
type RevokedEntry struct {
	SerialNumber string    `json:"serial"`
	AgentName    string    `json:"agent"`
	RevokedAt    time.Time `json:"revoked_at"`
}

// CertBundle holds a certificate and private key pair for an agent.
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
		crl:     &CRL{},
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
		crl:     &CRL{},
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

// IssueAgentCert creates a client certificate for an agent.
// The agent name becomes the certificate's Common Name (CN), which is used
// as the ACL identity during mTLS authentication.
func (ca *CA) IssueAgentCert(agentName string) (*CertBundle, error) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	if ca.cert == nil || ca.key == nil {
		return nil, ErrCANotInitialized
	}

	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating agent key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: agentName,
		},
		NotBefore: now,
		NotAfter:  now.AddDate(0, 0, AgentValidityDays),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &agentKey.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("signing agent certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(agentKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling agent key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &CertBundle{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		CACert:  ca.certPEM,
	}, nil
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

// TLSConfig returns a tls.Config configured for mTLS server mode.
// It verifies client certificates against the CA and checks the CRL.
func (ca *CA) TLSConfig() *tls.Config {
	certPool := x509.NewCertPool()
	certPool.AddCert(ca.cert)

	// Load server certificate (self-signed by CA for the server identity)
	return &tls.Config{
		ClientCAs:  certPool,
		ClientAuth: tls.VerifyClientCertIfGiven, // Optional — bearer tokens still work
		MinVersion: tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// Additional check: CRL revocation
			if len(verifiedChains) > 0 && len(verifiedChains[0]) > 0 {
				clientCert := verifiedChains[0][0]
				if ca.crl.IsRevoked(clientCert.SerialNumber) {
					return ErrCertRevoked
				}
			}
			return nil
		},
	}
}

// VerifyClientCert validates a client certificate chain against the CA
// and extracts the agent name. Performs full x509 chain verification,
// checks CRL revocation, and returns the CN (agent name) from the leaf.
func (ca *CA) VerifyClientCert(certs []*x509.Certificate) (string, error) {
	if len(certs) == 0 {
		return "", errors.New("no client certificate provided")
	}

	leaf := certs[0]

	// Verify the certificate chain against our CA
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	opts := x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := leaf.Verify(opts); err != nil {
		return "", fmt.Errorf("certificate chain verification failed: %w", err)
	}

	// Check CRL
	if ca.crl.IsRevoked(leaf.SerialNumber) {
		return "", ErrCertRevoked
	}

	// CN is the agent identity
	agentName := leaf.Subject.CommonName
	if agentName == "" {
		return "", errors.New("client certificate has no Common Name")
	}

	return agentName, nil
}

// RevokeCert adds a certificate to the CRL and persists if a CRL path is set.
func (ca *CA) RevokeCert(serial *big.Int, agentName string) error {
	return ca.crl.Revoke(serial, agentName)
}

// IsRevoked checks whether a serial number has been revoked.
func (ca *CA) IsRevoked(serial *big.Int) bool {
	return ca.crl.IsRevoked(serial)
}

// SetCRL replaces the CA's CRL with the given one.
func (ca *CA) SetCRL(crl *CRL) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.crl = crl
}

// --- CRL methods ---

// NewCRL creates a new empty CRL, optionally loading from a file.
func NewCRL(path string) (*CRL, error) {
	crl := &CRL{path: path}
	if path == "" {
		return crl, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return crl, nil
		}
		return nil, fmt.Errorf("reading CRL file: %w", err)
	}

	if err := json.Unmarshal(data, crl); err != nil {
		return nil, fmt.Errorf("parsing CRL file: %w", err)
	}
	return crl, nil
}

// Revoke adds a serial number to the revocation list.
// If a file path is set, the CRL is persisted to disk.
func (crl *CRL) Revoke(serial *big.Int, agentName string) error {
	crl.mu.Lock()
	defer crl.mu.Unlock()
	crl.Revoked = append(crl.Revoked, RevokedEntry{
		SerialNumber: serial.String(),
		AgentName:    agentName,
		RevokedAt:    time.Now().UTC(),
	})
	if crl.path != "" {
		return crl.saveLocked()
	}
	return nil
}

// IsRevoked checks if a serial number is in the revocation list.
func (crl *CRL) IsRevoked(serial *big.Int) bool {
	crl.mu.RLock()
	defer crl.mu.RUnlock()
	serialStr := serial.String()
	for _, entry := range crl.Revoked {
		if entry.SerialNumber == serialStr {
			return true
		}
	}
	return false
}

// saveLocked writes the CRL to disk. Caller must hold crl.mu.
func (crl *CRL) saveLocked() error {
	data, err := json.MarshalIndent(crl, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling CRL: %w", err)
	}

	dir := filepath.Dir(crl.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating CRL directory: %w", err)
	}

	tmp := crl.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("writing CRL temp file: %w", err)
	}
	if err := os.Rename(tmp, crl.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("renaming CRL temp file: %w", err)
	}
	return nil
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
