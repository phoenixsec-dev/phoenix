//go:build !linux

package agent

import (
	"net"
	"os"
)

// getPeerCred is a stub for non-Linux platforms.
// SO_PEERCRED is Linux-specific; on other platforms we return basic info
// using the current process credentials as a best-effort fallback.
// Returns nil error so callers can proceed with degraded attestation.
func getPeerCred(conn net.Conn) (*PeerInfo, error) {
	_ = conn
	return &PeerInfo{
		PID: int32(os.Getpid()),
		UID: int32(os.Getuid()),
		GID: int32(os.Getgid()),
	}, nil
}
