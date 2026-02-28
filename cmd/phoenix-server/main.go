// Phoenix server — secrets management API.
//
// Usage:
//
//	phoenix-server [--config /data/config.json]
//	phoenix-server --init /data  (first-time setup)
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"git.home/vector/phoenix/internal/acl"
	"git.home/vector/phoenix/internal/api"
	"git.home/vector/phoenix/internal/audit"
	"git.home/vector/phoenix/internal/ca"
	"git.home/vector/phoenix/internal/config"
	"git.home/vector/phoenix/internal/crypto"
	"git.home/vector/phoenix/internal/nonce"
	"git.home/vector/phoenix/internal/policy"
	"git.home/vector/phoenix/internal/store"
	"git.home/vector/phoenix/internal/token"
)

func main() {
	configPath := flag.String("config", "", "Path to config file (default: /data/config.json)")
	initDir := flag.String("init", "", "Initialize a new Phoenix data directory")
	flag.Parse()

	if *initDir != "" {
		if err := runInit(*initDir); err != nil {
			log.Fatalf("init failed: %v", err)
		}
		return
	}

	// Load config
	cfgPath := *configPath
	if cfgPath == "" {
		cfgPath = os.Getenv("PHOENIX_CONFIG")
	}
	if cfgPath == "" {
		cfgPath = "/data/config.json"
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid config: %v", err)
	}

	// Initialize key provider
	var keyProvider crypto.KeyProvider
	switch cfg.Crypto.Provider {
	case "file", "":
		p, err := crypto.NewFileKeyProviderFromPath(cfg.Store.MasterKey)
		if err != nil {
			log.Fatalf("loading file key provider: %v", err)
		}
		keyProvider = p
	default:
		log.Fatalf("unknown crypto provider: %q (supported: file)", cfg.Crypto.Provider)
	}

	// Initialize store
	s, err := store.NewWithProvider(cfg.Store.Path, keyProvider)
	if err != nil {
		log.Fatalf("initializing store: %v", err)
	}

	// Initialize ACL
	a, err := acl.New(cfg.ACL.Path)
	if err != nil {
		log.Fatalf("initializing ACL: %v", err)
	}

	// Initialize audit logger
	al, err := audit.NewLogger(cfg.Audit.Path)
	if err != nil {
		log.Fatalf("initializing audit logger: %v", err)
	}
	defer al.Close()

	// Create API server
	srv := api.NewServer(s, a, al, cfg.Audit.Path)
	srv.SetBearerEnabled(cfg.Auth.Bearer.Enabled)
	srv.SetMasterKeyPath(cfg.Store.MasterKey)

	// Load attestation policy if configured
	if cfg.Policy.Path != "" {
		pe, err := policy.LoadFile(cfg.Policy.Path)
		if err != nil {
			log.Fatalf("loading attestation policy: %v", err)
		}
		srv.SetPolicy(pe)
		log.Printf("  Policy: %s (%d rules)", cfg.Policy.Path, len(pe.Rules()))
	}

	// Initialize nonce store if enabled
	if cfg.Attestation.Nonce.Enabled {
		maxAge := nonce.DefaultMaxAge
		if cfg.Attestation.Nonce.MaxAge != "" {
			maxAge, _ = time.ParseDuration(cfg.Attestation.Nonce.MaxAge) // validated above
		}
		ns := nonce.NewStore(maxAge)
		srv.SetNonceStore(ns)
		defer ns.Stop()
		log.Printf("  Nonce challenge: enabled (max_age=%s)", maxAge)
	} else {
		log.Printf("  Nonce challenge: disabled")
	}

	// Initialize short-lived token issuer if enabled
	if cfg.Attestation.Token.Enabled {
		ttl := token.DefaultTTL
		if cfg.Attestation.Token.TTL != "" {
			ttl, _ = time.ParseDuration(cfg.Attestation.Token.TTL) // validated above
		}
		ti, err := token.NewIssuer(ttl)
		if err != nil {
			log.Fatalf("initializing token issuer: %v", err)
		}
		srv.SetTokenIssuer(ti)
		log.Printf("  Short-lived tokens: enabled (ttl=%s)", ttl)
	} else {
		log.Printf("  Short-lived tokens: disabled")
	}

	// Initialize CA for mTLS if enabled
	var tlsCfg *tls.Config
	if cfg.Auth.MTLS.Enabled {
		authority, err := ca.LoadCA(cfg.Auth.MTLS.CACert, cfg.Auth.MTLS.CAKey)
		if err != nil {
			log.Fatalf("loading CA for mTLS: %v", err)
		}

		// Load CRL for revocation persistence
		if cfg.Auth.MTLS.CRLPath != "" {
			crl, err := ca.NewCRL(cfg.Auth.MTLS.CRLPath)
			if err != nil {
				log.Fatalf("loading CRL: %v", err)
			}
			authority.SetCRL(crl)
		}

		srv.SetCA(authority)
		tlsCfg = authority.TLSConfig()
		if cfg.Auth.MTLS.Require {
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		}
		log.Printf("  mTLS: enabled (require=%v)", cfg.Auth.MTLS.Require)
		log.Printf("  Bearer: %v", cfg.Auth.Bearer.Enabled)
	}

	log.Printf("Phoenix server starting on %s", cfg.Server.Listen)
	log.Printf("  Store: %s (%d secrets)", cfg.Store.Path, s.Count())
	log.Printf("  Key provider: %s", keyProvider.Name())
	log.Printf("  ACL: %s (%d agents)", cfg.ACL.Path, len(a.ListAgents()))
	log.Printf("  Audit: %s", cfg.Audit.Path)

	httpSrv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           srv,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	if tlsCfg != nil {
		// Use the dedicated server leaf cert for TLS identity (NOT the CA cert)
		log.Printf("  TLS: enabled (server cert: %s)", cfg.Auth.MTLS.ServerCert)
		if err := httpSrv.ListenAndServeTLS(cfg.Auth.MTLS.ServerCert, cfg.Auth.MTLS.ServerKey); err != nil {
			log.Fatalf("server error: %v", err)
		}
	} else {
		if err := httpSrv.ListenAndServe(); err != nil {
			log.Fatalf("server error: %v", err)
		}
	}
}

func runInit(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	// Generate master key
	keyPath := filepath.Join(dir, "master.key")
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("master key already exists at %s — refusing to overwrite", keyPath)
	}
	_, err := crypto.GenerateAndSaveMasterKey(keyPath)
	if err != nil {
		return fmt.Errorf("generating master key: %w", err)
	}
	fmt.Printf("Generated master key: %s\n", keyPath)

	// Generate admin token
	tokenBytes, err := crypto.GenerateKey()
	if err != nil {
		return err
	}
	adminToken := fmt.Sprintf("%x", tokenBytes)

	// Create initial ACL with admin agent
	aclPath := filepath.Join(dir, "acl.json")
	a, err := acl.New(aclPath)
	if err != nil {
		return fmt.Errorf("creating ACL: %w", err)
	}
	if err := a.AddAgent("admin", adminToken, []acl.Permission{
		{Path: "*", Actions: []acl.Action{acl.ActionAdmin}},
	}); err != nil {
		return fmt.Errorf("adding admin agent: %w", err)
	}
	if err := a.Save(); err != nil {
		return fmt.Errorf("saving ACL: %w", err)
	}
	fmt.Printf("Created ACL: %s\n", aclPath)
	fmt.Printf("\n*** ADMIN TOKEN (save this — it won't be shown again): ***\n%s\n\n", adminToken)

	// Generate internal CA
	caCertPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")
	authority, err := ca.GenerateCA("Phoenix")
	if err != nil {
		return fmt.Errorf("generating CA: %w", err)
	}
	if err := authority.Save(caCertPath, caKeyPath); err != nil {
		return fmt.Errorf("saving CA: %w", err)
	}
	fmt.Printf("Generated CA certificate: %s\n", caCertPath)
	fmt.Printf("  Fingerprint: %s\n", authority.Fingerprint())

	// Generate server leaf certificate (for TLS server identity)
	serverCertPath := filepath.Join(dir, "server.crt")
	serverKeyPath := filepath.Join(dir, "server.key")
	serverBundle, err := authority.IssueServerCert([]string{"localhost", "127.0.0.1", "0.0.0.0"})
	if err != nil {
		return fmt.Errorf("generating server cert: %w", err)
	}
	if err := serverBundle.Save(serverCertPath, serverKeyPath, caCertPath); err != nil {
		return fmt.Errorf("saving server cert: %w", err)
	}
	fmt.Printf("Generated server certificate: %s\n", serverCertPath)

	// Write config with actual paths
	crlPath := filepath.Join(dir, "crl.json")
	cfgPath := filepath.Join(dir, "config.json")
	cfg := config.DefaultConfig()
	cfg.Store.Path = filepath.Join(dir, "store.json")
	cfg.Store.MasterKey = keyPath
	cfg.ACL.Path = aclPath
	cfg.Audit.Path = filepath.Join(dir, "audit.log")
	cfg.Auth.MTLS.CACert = caCertPath
	cfg.Auth.MTLS.CAKey = caKeyPath
	cfg.Auth.MTLS.ServerCert = serverCertPath
	cfg.Auth.MTLS.ServerKey = serverKeyPath
	cfg.Auth.MTLS.CRLPath = crlPath

	cfgData, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	if err := os.WriteFile(cfgPath, cfgData, 0600); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	fmt.Printf("Created config: %s\n", cfgPath)

	fmt.Println("\nPhoenix initialized. Start the server with:")
	fmt.Printf("  phoenix-server --config %s\n", cfgPath)

	return nil
}
