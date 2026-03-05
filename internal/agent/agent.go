// Package agent implements a local attestation agent that verifies caller
// identity via Unix domain sockets and SO_PEERCRED.
//
// The agent listens on a Unix socket and uses the kernel's SO_PEERCRED
// mechanism to extract the caller's PID, UID, and GID. From the PID it
// resolves the binary path via /proc/<pid>/exe and computes a SHA-256
// hash of the executable.
//
// This proves *this specific process on this machine* is who it claims
// to be, not just "someone with the right cert file." No cert distribution
// is needed for local workloads — just connect to the socket.
package agent

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
)

// PeerInfo contains identity information extracted from a Unix socket peer.
type PeerInfo struct {
	PID        int32  `json:"pid"`
	UID        int32  `json:"uid"`
	GID        int32  `json:"gid"`
	BinaryPath string `json:"binary_path,omitempty"`
	BinaryHash string `json:"binary_hash,omitempty"` // "sha256:<hex>"
}

// AttestRequest is sent by a client to the attestation agent.
type AttestRequest struct {
	Agent string `json:"agent"` // requested agent identity
}

// AttestResponse is returned by the attestation agent.
type AttestResponse struct {
	OK    bool      `json:"ok"`
	Peer  *PeerInfo `json:"peer,omitempty"`
	Error string    `json:"error,omitempty"`
}

// Agent is the local Unix socket attestation agent.
type Agent struct {
	mu       sync.Mutex
	listener net.Listener
	sockPath string
	stopped  bool
}

// New creates a new attestation agent that will listen on the given socket path.
func New(sockPath string) *Agent {
	return &Agent{sockPath: sockPath}
}

// Start begins listening for attestation requests on the Unix socket.
func (a *Agent) Start() error {
	// Remove stale socket file
	os.Remove(a.sockPath)

	ln, err := net.Listen("unix", a.sockPath)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", a.sockPath, err)
	}

	// Restrict socket permissions
	if err := os.Chmod(a.sockPath, 0600); err != nil {
		ln.Close()
		return fmt.Errorf("setting socket permissions: %w", err)
	}

	a.mu.Lock()
	a.listener = ln
	a.mu.Unlock()

	go a.acceptLoop(ln)
	return nil
}

// Stop shuts down the attestation agent.
func (a *Agent) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.stopped {
		return nil
	}
	a.stopped = true

	if a.listener != nil {
		a.listener.Close()
	}
	os.Remove(a.sockPath)
	return nil
}

// SocketPath returns the path to the Unix socket.
func (a *Agent) SocketPath() string {
	return a.sockPath
}

func (a *Agent) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			a.mu.Lock()
			stopped := a.stopped
			a.mu.Unlock()
			if stopped {
				return
			}
			continue
		}
		go a.handleConn(conn)
	}
}

func (a *Agent) handleConn(conn net.Conn) {
	defer conn.Close()

	// Extract peer credentials via SO_PEERCRED
	peer, err := getPeerCred(conn)
	if err != nil {
		writeResponse(conn, &AttestResponse{
			OK:    false,
			Error: fmt.Sprintf("failed to get peer credentials: %v", err),
		})
		return
	}

	// Resolve binary path from /proc/<pid>/exe
	peer.BinaryPath, peer.BinaryHash = resolveBinary(peer.PID)

	// Read the attestation request
	var req AttestRequest
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&req); err != nil {
		writeResponse(conn, &AttestResponse{
			OK:    false,
			Error: "invalid request",
		})
		return
	}

	writeResponse(conn, &AttestResponse{
		OK:   true,
		Peer: peer,
	})
}

func writeResponse(w io.Writer, resp *AttestResponse) {
	json.NewEncoder(w).Encode(resp)
}

// resolveBinary looks up the binary path for a PID and computes its hash.
func resolveBinary(pid int32) (string, string) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	binaryPath, err := os.Readlink(exePath)
	if err != nil {
		return "", ""
	}

	hash, err := hashFile(binaryPath)
	if err != nil {
		return binaryPath, ""
	}

	return binaryPath, hash
}

// hashFile computes SHA-256 of a file, returning "sha256:<hex>".
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("sha256:%X", h.Sum(nil)), nil
}

// HashFile computes SHA-256 of a file, returning "sha256:<hex>".
// Exported for use by callers who need to compute binary hashes.
func HashFile(path string) (string, error) {
	return hashFile(path)
}
