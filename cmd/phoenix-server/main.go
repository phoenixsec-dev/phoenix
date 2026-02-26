// Phoenix server — secrets management API.
//
// Usage:
//
//	phoenix-server [--config /data/config.json]
//	phoenix-server --init /data  (first-time setup)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"git.home/vector/phoenix/internal/acl"
	"git.home/vector/phoenix/internal/api"
	"git.home/vector/phoenix/internal/audit"
	"git.home/vector/phoenix/internal/config"
	"git.home/vector/phoenix/internal/crypto"
	"git.home/vector/phoenix/internal/store"
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

	// Load master key
	masterKey, err := crypto.LoadMasterKey(cfg.Store.MasterKey)
	if err != nil {
		log.Fatalf("loading master key: %v", err)
	}

	// Initialize store
	s, err := store.New(cfg.Store.Path, masterKey)
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

	log.Printf("Phoenix server starting on %s", cfg.Server.Listen)
	log.Printf("  Store: %s (%d secrets)", cfg.Store.Path, s.Count())
	log.Printf("  ACL: %s (%d agents)", cfg.ACL.Path, len(a.ListAgents()))
	log.Printf("  Audit: %s", cfg.Audit.Path)

	if err := http.ListenAndServe(cfg.Server.Listen, srv); err != nil {
		log.Fatalf("server error: %v", err)
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
	a, _ := acl.New(aclPath)
	a.AddAgent("admin", adminToken, []acl.Permission{
		{Path: "*", Actions: []acl.Action{acl.ActionAdmin}},
	})
	a.Save()
	fmt.Printf("Created ACL: %s\n", aclPath)
	fmt.Printf("\n*** ADMIN TOKEN (save this — it won't be shown again): ***\n%s\n\n", adminToken)

	// Write config with actual paths
	cfgPath := filepath.Join(dir, "config.json")
	cfg := config.DefaultConfig()
	cfg.Store.Path = filepath.Join(dir, "store.json")
	cfg.Store.MasterKey = keyPath
	cfg.ACL.Path = aclPath
	cfg.Audit.Path = filepath.Join(dir, "audit.log")

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
