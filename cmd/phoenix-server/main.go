// Phoenix server — secrets management API.
//
// Usage:
//
//	phoenix-server [--config /data/config.json]
//	phoenix-server --init /data  (first-time setup)
//	phoenix-server --reissue-cert --san <ip-or-host> [--san ...] --config /data/config.json
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/api"
	"github.com/phoenixsec/phoenix/internal/audit"
	"github.com/phoenixsec/phoenix/internal/ca"
	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/crypto"
	"github.com/phoenixsec/phoenix/internal/dashboard"
	"github.com/phoenixsec/phoenix/internal/grant"
	"github.com/phoenixsec/phoenix/internal/op"
	"github.com/phoenixsec/phoenix/internal/policy"
	"github.com/phoenixsec/phoenix/internal/session"
	"github.com/phoenixsec/phoenix/internal/sshca"
	"github.com/phoenixsec/phoenix/internal/store"
	"github.com/phoenixsec/phoenix/internal/transport"
	"github.com/phoenixsec/phoenix/internal/version"
)

// sanList is a flag.Value that collects multiple --san values.
type sanList []string

func (s *sanList) String() string { return strings.Join(*s, ",") }
func (s *sanList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	configPath := flag.String("config", "", "Path to config file (default: /data/config.json)")
	initDir := flag.String("init", "", "Initialize a new Phoenix data directory")
	showVersion := flag.Bool("version", false, "Print version and exit")
	passphraseStdin := flag.Bool("passphrase-stdin", false, "Read master key passphrase from stdin")
	flag.String("passphrase", "", "Removed: use --passphrase-stdin or PHOENIX_MASTER_PASSPHRASE")
	protectKey := flag.Bool("protect-key", false, "Add, change, or remove passphrase on existing master key")
	hashPassword := flag.Bool("hash-password", false, "Generate a bcrypt hash for dashboard password_hash config")
	checkConfig := flag.Bool("check-config", false, "Check the config file, the policy file and HTTPS certificate it names, then exit without starting")
	reissueCert := flag.Bool("reissue-cert", false, "Re-issue the server TLS certificate with new SANs")
	var sans sanList
	flag.Var(&sans, "san", "Subject Alternative Name for --reissue-cert (repeatable: IPs and hostnames)")
	flag.Parse()

	if flagSet("passphrase") {
		fmt.Fprintln(os.Stderr, "phoenix-server --passphrase was removed: a passphrase on the command line is visible to every user in the process list and lands in shell history. "+
			"Pipe it in with --passphrase-stdin, or set PHOENIX_MASTER_PASSPHRASE.")
		os.Exit(2)
	}

	if *showVersion {
		fmt.Printf("phoenix-server %s\n", version.Version)
		return
	}

	if *hashPassword {
		if err := runHashPassword(); err != nil {
			log.Fatalf("hash-password failed: %v", err)
		}
		return
	}

	if *reissueCert {
		if len(sans) == 0 {
			log.Fatal("--reissue-cert requires at least one --san value")
		}
		cfg, err := config.Load(resolveConfigPath(*configPath))
		if err != nil {
			log.Fatalf("loading config: %v", err)
		}
		if err := runReissueCert(cfg, sans); err != nil {
			log.Fatalf("reissue-cert failed: %v", err)
		}
		return
	}

	if *initDir != "" {
		passphrase, err := initPassphrase(*passphraseStdin)
		if err != nil {
			log.Fatalf("init failed: %v", err)
		}
		if err := runInit(*initDir, passphrase); err != nil {
			log.Fatalf("init failed: %v", err)
		}
		return
	}

	if *protectKey {
		cfg, err := config.Load(resolveConfigPath(*configPath))
		if err != nil {
			log.Fatalf("loading config: %v", err)
		}
		if err := runProtectKey(cfg.Store.MasterKey); err != nil {
			log.Fatalf("protect-key failed: %v", err)
		}
		return
	}

	if *checkConfig {
		if err := runCheckConfig(resolveConfigPath(*configPath)); err != nil {
			fmt.Fprintf(os.Stderr, "config check failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Load config
	cfg, err := config.Load(resolveConfigPath(*configPath))
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid config: %v", err)
	}
	// Load the optional HTTPS certificate before anything else starts: a bad
	// path or mismatched key is a config error and stops startup, like any other.
	optionalHTTPS, err := loadHTTPSListener(cfg.HTTPSListener)
	if err != nil {
		log.Fatalf("invalid config: %v", err)
	}

	// Initialize backend
	var backend store.SecretBackend

	switch cfg.Backend() {
	case "1password":
		tokenEnv := cfg.OnePassword.ServiceAccountTokenEnv
		if tokenEnv == "" {
			tokenEnv = "OP_SERVICE_ACCOUNT_TOKEN"
		}
		opClient := op.New(tokenEnv)
		if err := opClient.Available(); err != nil {
			log.Fatalf("1Password backend: %v", err)
		}
		cacheTTL := 60 * time.Second // default
		if cfg.OnePassword.CacheTTL != "" {
			cacheTTL, _ = time.ParseDuration(cfg.OnePassword.CacheTTL) // validated above
		}
		backend = store.NewOPBackend(opClient, cfg.OnePassword.Vault, cacheTTL)
		log.Printf("  Backend: 1password (vault=%s, cache=%s)", cfg.OnePassword.Vault, cacheTTL)

	default: // "file"
		// Initialize key provider
		var keyProvider crypto.KeyProvider
		switch cfg.Crypto.Provider {
		case "file", "":
			key, err := crypto.LoadMasterKey(cfg.Store.MasterKey)
			if err == crypto.ErrPassphraseRequired {
				passphrase, ppErr := crypto.ReadPassphrase(*passphraseStdin)
				if ppErr != nil {
					log.Fatalf("master key is passphrase-protected: %v", ppErr)
				}
				key, err = crypto.LoadMasterKeyWithPassphrase(cfg.Store.MasterKey, passphrase)
				if err != nil {
					log.Fatalf("decrypting master key: %v", err)
				}
				p, provErr := crypto.NewFileKeyProvider(key)
				if provErr != nil {
					log.Fatalf("creating key provider: %v", provErr)
				}
				p.SetPassphrase(passphrase)
				keyProvider = p
			} else if err != nil {
				log.Fatalf("loading master key: %v", err)
			} else {
				p, provErr := crypto.NewFileKeyProvider(key)
				if provErr != nil {
					log.Fatalf("creating key provider: %v", provErr)
				}
				keyProvider = p
			}
		default:
			log.Fatalf("unknown crypto provider: %q (supported: file)", cfg.Crypto.Provider)
		}

		s, err := store.NewWithProvider(cfg.Store.Path, keyProvider)
		if err != nil {
			log.Fatalf("initializing store: %v", err)
		}
		backend = store.NewFileBackend(s)
		log.Printf("  Backend: file (provider=%s)", keyProvider.Name())
	}

	// Initialize ACL
	a, err := acl.New(cfg.ACL.Path)
	if err != nil {
		log.Fatalf("initializing ACL: %v", err)
	}

	// Initialize audit logger
	al, err := audit.NewRotatingLogger(cfg.Audit.Path, cfg.AuditRotateBytes())
	if err != nil {
		log.Fatalf("initializing audit logger: %v", err)
	}
	defer al.Close()

	// Create API server
	srv := api.NewServer(backend, a, al, cfg.Audit.Path)
	srv.SetBearerEnabled(cfg.Auth.Bearer.Enabled)
	srv.SetMasterKeyPath(cfg.Store.MasterKey)

	// Load attestation policy if configured
	var pe *policy.Engine
	if cfg.Policy.Path != "" {
		pe, err = policy.LoadFile(cfg.Policy.Path)
		if err != nil {
			log.Fatalf("loading attestation policy: %v", err)
		}
		srv.SetPolicy(pe)
		log.Printf("  Policy: %s (%d rules)", cfg.Policy.Path, len(pe.Rules()))
	}

	// Initialize session identity if enabled
	var sessionStore *session.Store
	if cfg.Session.Enabled {
		sessionTTL := session.DefaultTTL
		if cfg.Session.TTL != "" {
			sessionTTL, _ = time.ParseDuration(cfg.Session.TTL) // validated above
		}
		var err error
		sessionStore, err = session.NewStore(sessionTTL)
		if err != nil {
			log.Fatalf("initializing session store: %v", err)
		}
		srv.SetSessionStore(sessionStore)
		srv.SetSessionRoles(cfg.Session.Roles)
		defer sessionStore.Stop()
		log.Printf("  Sessions: enabled (roles=%d, ttl=%s)", len(cfg.Session.Roles), sessionTTL)
	} else {
		log.Printf("  Sessions: disabled")
	}

	// Request-use grants. The store is always opened (it only creates
	// grants.json on the first change), so listing and revoking keep working
	// while the feature is disabled. A missing access_requests block = off.
	grantStore, err := openGrantStore(cfg, a, al)
	if err != nil {
		log.Fatalf("opening grant store: %v", err)
	}
	srv.SetGrantStore(grantStore)
	srv.SetAccessRequests(cfg.AccessRequestsSettings())
	grantCtx, stopGrants := context.WithCancel(context.Background())
	defer stopGrants()
	go grantStore.Run(grantCtx, 30*time.Second)
	logAccessRequests(cfg, a)
	if cfg.SSHCAEnabled() {
		ca, created, err := sshca.LoadOrCreate(cfg.SSHCAKeyPath())
		if err != nil {
			log.Fatalf("loading SSH CA key: %v", err)
		}
		srv.SetSSHCA(ca, cfg.SSHCAHosts())
		log.Printf("SSH certificates: enabled for %d host(s), new key=%v, CA %s", len(cfg.SSHCA.Hosts), created, sshca.PublicKey(ca))
	}

	// Initialize dashboard if enabled
	if cfg.Dashboard.Enabled {
		deps := dashboard.Deps{
			Sessions:     sessionStore,
			SessionRoles: cfg.Session.Roles,
			AuditPath:    cfg.Audit.Path,
			Backend:      backend,
			ACL:          a,
			StartTime:    time.Now(),
			Audit:        al,
			Policy:       pe,
			Grants:       grantStore,
			Access:       srv,
		}
		dash, err := dashboard.New(cfg.Dashboard, deps)
		if err != nil {
			log.Fatalf("initializing dashboard: %v", err)
		}
		srv.SetDashboard(dash)
		log.Printf("  Dashboard: enabled at /dashboard/")
	}

	log.Printf("Phoenix server starting on %s", cfg.Server.Listen)
	log.Printf("  ACL: %s (%d agents)", cfg.ACL.Path, len(a.ListAgents()))
	if rb := cfg.AuditRotateBytes(); rb > 0 {
		log.Printf("  Audit: %s (rotates at %d MB; archives are kept)", cfg.Audit.Path, rb>>20)
	} else {
		log.Printf("  Audit: %s (rotation off)", cfg.Audit.Path)
	}

	httpSrv := newHTTPServer(cfg.Server.Listen, srv, nil)

	if !transport.IsLoopbackListen(cfg.Server.Listen) {
		// Loud, never fatal: loopback plaintext is the supported default,
		// but a non-loopback bind puts bearer tokens and secret values on
		// the wire in cleartext. HTTPS is https_listener's job.
		log.Printf("\n%s", transport.ServerPlaintextWarning(cfg.Server.Listen, cfg.Dashboard.Enabled))
	}
	if err := serveListeners(httpSrv, optionalHTTPS, log.Printf); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// resolveConfigPath picks the config file: --config, then $PHOENIX_CONFIG,
// then /data/config.json.
func resolveConfigPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv("PHOENIX_CONFIG"); env != "" {
		return env
	}
	return "/data/config.json"
}

// runCheckConfig is --check-config: it runs the same checks startup does on
// the config file, the policy file, the ACL file and the HTTPS certificate,
// without opening the store or binding any port, so an operator can check a
// config (including one with removed settings) before deploying a new
// version. Every file is checked, so one run lists every problem.
func runCheckConfig(path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	var errs []error
	if err := cfg.Validate(); err != nil {
		errs = append(errs, err)
	}
	if cfg.Policy.Path != "" {
		pe, err := policy.LoadFile(cfg.Policy.Path)
		if err != nil {
			errs = append(errs, fmt.Errorf("policy %s: %w", cfg.Policy.Path, err))
		} else {
			fmt.Printf("policy OK: %s (%d rules)\n", cfg.Policy.Path, len(pe.Rules()))
		}
	}
	if cfg.ACL.Path != "" {
		a, err := acl.New(cfg.ACL.Path)
		if err != nil {
			errs = append(errs, fmt.Errorf("acl %s: %w", cfg.ACL.Path, err))
		} else {
			fmt.Printf("acl OK: %s (%d agents)\n", cfg.ACL.Path, len(a.ListAgents()))
		}
	}
	if _, err := loadHTTPSListener(cfg.HTTPSListener); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	fmt.Printf("config OK: %s\n", path)
	return nil
}

// flagSet reports whether the named flag was given on the command line, even
// with an empty value.
func flagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// initPassphrase picks the passphrase that protects a new master key for
// --init: stdin with --passphrase-stdin, else PHOENIX_MASTER_PASSPHRASE.
// Neither means an unprotected key (add one later with --protect-key).
func initPassphrase(stdin bool) (string, error) {
	if !stdin && os.Getenv("PHOENIX_MASTER_PASSPHRASE") == "" {
		return "", nil
	}
	return crypto.ReadPassphrase(stdin)
}

func runInit(dir, passphrase string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	// Generate master key
	keyPath := filepath.Join(dir, "master.key")
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("master key already exists at %s — refusing to overwrite", keyPath)
	}
	if passphrase != "" {
		key, err := crypto.GenerateKey()
		if err != nil {
			return fmt.Errorf("generating master key: %w", err)
		}
		if err := crypto.SaveProtectedMasterKey(keyPath, key, passphrase); err != nil {
			return fmt.Errorf("saving protected master key: %w", err)
		}
		fmt.Printf("Generated passphrase-protected master key: %s\n", keyPath)
	} else {
		_, err := crypto.GenerateAndSaveMasterKey(keyPath)
		if err != nil {
			return fmt.Errorf("generating master key: %w", err)
		}
		fmt.Printf("Generated master key: %s\n", keyPath)
	}

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
	cfgPath := filepath.Join(dir, "config.json")
	cfg := config.DefaultConfig()
	cfg.Store.Path = filepath.Join(dir, "store.json")
	cfg.Store.MasterKey = keyPath
	cfg.ACL.Path = aclPath
	cfg.Audit.Path = filepath.Join(dir, "audit.log")
	// HTTPS is written off: turning it on is one setting ("enabled": true)
	// once clients have ca.crt. --reissue-cert uses ca_cert/ca_key.
	cfg.HTTPSListener = config.HTTPSListenerConfig{
		Listen: "0.0.0.0:9443",
		Cert:   serverCertPath,
		Key:    serverKeyPath,
		CACert: caCertPath,
		CAKey:  caKeyPath,
	}
	// New installs get request-use grants switched on (plan Q1); configs
	// written before this release have no block and stay off.
	cfg.AccessRequests = config.NewInstallAccessRequests()

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

// runProtectKey adds, changes, or removes the passphrase on an existing master key.
// Requires an interactive TTY — passphrase removal is too dangerous for piped input.
func runProtectKey(keyPath string) error {
	if !crypto.IsTerminal() {
		return fmt.Errorf("--protect-key requires an interactive terminal (TTY)")
	}

	// Load current key (with old passphrase if needed)
	key, err := crypto.LoadMasterKey(keyPath)
	if err == crypto.ErrPassphraseRequired {
		fmt.Fprintln(os.Stderr, "Current master key is passphrase-protected.")
		oldPass, ppErr := crypto.PromptPassphrase("Enter current passphrase: ")
		if ppErr != nil {
			return fmt.Errorf("reading current passphrase: %w", ppErr)
		}
		key, err = crypto.LoadMasterKeyWithPassphrase(keyPath, oldPass)
		if err != nil {
			return fmt.Errorf("decrypting with current passphrase: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("loading master key: %w", err)
	}

	// Prompt for new passphrase — empty means remove protection
	newPass, ppErr := crypto.PromptPassphraseAllowEmpty("Enter new passphrase (empty to remove protection): ")
	if ppErr != nil {
		return fmt.Errorf("reading new passphrase: %w", ppErr)
	}

	if newPass == "" {
		// Confirm removal
		confirm, cErr := crypto.PromptPassphraseAllowEmpty("Confirm passphrase removal — type REMOVE: ")
		if cErr != nil || confirm != "REMOVE" {
			return fmt.Errorf("aborted — passphrase not changed")
		}
		if err := crypto.SaveMasterKeyAtomic(keyPath, key); err != nil {
			return fmt.Errorf("saving unprotected key: %w", err)
		}
		fmt.Println("Master key passphrase removed.")
	} else {
		if err := crypto.SaveProtectedMasterKey(keyPath, key, newPass); err != nil {
			return fmt.Errorf("saving protected key: %w", err)
		}
		fmt.Println("Master key passphrase updated.")
	}

	return nil
}

// runHashPassword prompts for a password and prints its bcrypt hash.
// The hash can be pasted into config.json as dashboard.password_hash.
func runHashPassword() error {
	pass, err := crypto.PromptPassphrase("Enter dashboard password: ")
	if err != nil {
		return err
	}
	confirm, err := crypto.PromptPassphrase("Confirm dashboard password: ")
	if err != nil {
		return err
	}
	if pass != confirm {
		return fmt.Errorf("passwords do not match")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("generating hash: %w", err)
	}
	fmt.Println(string(hash))
	return nil
}

// runReissueCert is --reissue-cert: it signs a new server certificate for
// https_listener with the internal CA, adding the given names (SANs).
func runReissueCert(cfg *config.Config, sans []string) error {
	hl := cfg.HTTPSListener
	if hl.CACert == "" || hl.CAKey == "" {
		return fmt.Errorf("config is missing https_listener.ca_cert and https_listener.ca_key (--init writes them; older configs had them under auth.mtls)")
	}
	if hl.Cert == "" || hl.Key == "" {
		return fmt.Errorf("config is missing https_listener.cert and https_listener.key paths")
	}

	// Always include localhost and loopback
	allSANs := append([]string{"localhost", "127.0.0.1"}, sans...)

	authority, err := ca.LoadCA(hl.CACert, hl.CAKey)
	if err != nil {
		return fmt.Errorf("loading CA: %w", err)
	}

	bundle, err := authority.IssueServerCert(allSANs)
	if err != nil {
		return fmt.Errorf("issuing server cert: %w", err)
	}

	if err := bundle.Save(hl.Cert, hl.Key, hl.CACert); err != nil {
		return fmt.Errorf("saving server cert: %w", err)
	}

	fmt.Printf("Server certificate reissued: %s\n", hl.Cert)
	fmt.Printf("SANs: %s\n", strings.Join(allSANs, ", "))
	fmt.Println("Restart the server for the new certificate to take effect.")
	return nil
}

// openGrantStore opens grants.json (access_requests.store_path, default next
// to the ACL file).
func openGrantStore(cfg *config.Config, a *acl.ACL, al *audit.Logger) (*grant.Store, error) {
	// Checked again here (Validate already did) so no caller can open a
	// store that would overwrite or quarantine another Phoenix file.
	if err := cfg.ValidateGrantStorePath(); err != nil {
		return nil, err
	}
	set := cfg.AccessRequestsSettings()
	return grant.Open(grant.Options{
		Path:  set.StorePath,
		Audit: api.NewGrantAuditSink(al),
		AgentExists: func(name string) bool {
			_, err := a.GetAgent(name)
			return err == nil
		},
		RequestTTL:      set.RequestTTL,
		DefaultGrantTTL: set.DefaultGrantTTL,
		MaxGrantTTL:     set.MaxGrantTTL,
	})
}

// logAccessRequests prints the request-use status and the startup warnings
// from plan section 6 (unknown approver names; nobody able to approve), plus
// the notify hook summary and its plain-http token warning.
func logAccessRequests(cfg *config.Config, a *acl.ACL) {
	set := cfg.AccessRequestsSettings()
	if !set.Enabled {
		log.Printf("  Access requests: disabled (grants file: %s)", set.StorePath)
		return
	}
	log.Printf("  Access requests: enabled (grants file: %s, approvers=%d, sealed=%v)",
		set.StorePath, len(set.Approvers), set.RequireSealed)
	for _, name := range set.Approvers {
		if _, err := a.GetAgent(name); err != nil {
			log.Printf("WARNING: access_requests.approvers: %q is not an agent in the ACL", name)
		}
	}
	if set.NotifyURL != "" {
		// Host only: an ntfy topic name in the path works like a password.
		host := "?"
		if u, err := url.Parse(set.NotifyURL); err == nil {
			host = u.Host
		}
		log.Printf("  Access request notifications: on (host %s, paths=%v, link=%v)",
			host, set.NotifyIncludePaths, set.NotifyDashboardURL != "")
		if set.NotifyTokenRef != "" && transport.IsPlaintextNonLoopbackURL(set.NotifyURL) {
			log.Printf("WARNING: access_requests.notify_url uses plain http:// with notify_token_ref set: the notify token crosses the network unencrypted; use https://")
		}
	}
	if !cfg.Dashboard.Enabled && len(set.Approvers) == 0 {
		// Worded without "dashboard": e2e scenario 19 checks that the startup
		// log never mentions it when that UI is off.
		log.Printf("WARNING: access_requests is enabled but nobody can approve requests: access_requests.approvers is empty and the operator web UI is off")
	}
}
