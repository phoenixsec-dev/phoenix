package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
)

// SSHCAConfig is the "ssh_ca" block: Phoenix signs short-lived SSH login
// certificates for the machines listed here, once a human approves a request
// for "ssh/<name>". See docs/ssh-certificates.md.
type SSHCAConfig struct {
	Enabled bool               `json:"enabled"`
	KeyPath string             `json:"key_path,omitempty"` // empty = ssh_ca.key next to the ACL file; created on first start
	Hosts   map[string]SSHHost `json:"hosts"`              // machine name -> how to reach it
}

// SSHHost is where an approved agent logs in.
type SSHHost struct {
	Address string `json:"address"`
	User    string `json:"user,omitempty"` // empty = DefaultSSHUser
}

// DefaultSSHUser is the login name set up by the machine's bootstrap.
const DefaultSSHUser = "agent"

var (
	sshHostName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	// Neither may start with "-", so a value can never be read as an ssh option.
	sshAddress = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.:-]{0,254}$`)
	sshUser    = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

// SSHCAEnabled reports whether the block is present and switched on.
func (c *Config) SSHCAEnabled() bool {
	return c.SSHCA != nil && c.SSHCA.Enabled
}

// SSHCAKeyPath is where the signing key lives.
func (c *Config) SSHCAKeyPath() string {
	if c.SSHCA != nil && c.SSHCA.KeyPath != "" {
		return c.SSHCA.KeyPath
	}
	return filepath.Join(filepath.Dir(c.ACL.Path), "ssh_ca.key")
}

// SSHCAHosts returns the configured machines with their defaults filled in.
func (c *Config) SSHCAHosts() map[string]SSHHost {
	hosts := make(map[string]SSHHost, len(c.SSHCA.Hosts))
	for name, h := range c.SSHCA.Hosts {
		if h.User == "" {
			h.User = DefaultSSHUser
		}
		hosts[name] = h
	}
	return hosts
}

func (c *Config) validateSSHCA() error {
	if !c.SSHCAEnabled() {
		return nil
	}
	// Approval is the whole point: without grants nothing could ever be signed.
	if c.AccessRequests == nil || !c.AccessRequests.Enabled {
		return errors.New("ssh_ca: access_requests must be enabled")
	}
	if len(c.SSHCA.Hosts) == 0 {
		return errors.New("ssh_ca: at least one host is required")
	}
	for name, h := range c.SSHCA.Hosts {
		if !sshHostName.MatchString(name) {
			return fmt.Errorf("ssh_ca: invalid host name %q", name)
		}
		if !sshAddress.MatchString(h.Address) {
			return fmt.Errorf("ssh_ca: host %q has an invalid address", name)
		}
		if h.User != "" && !sshUser.MatchString(h.User) {
			return fmt.Errorf("ssh_ca: host %q has an invalid user", name)
		}
	}
	return nil
}
