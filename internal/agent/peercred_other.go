//go:build !linux

package agent

import (
	"fmt"
	"net"
	"os"
)

// getPeerCred is a stub for non-Linux platforms.
// SO_PEERCRED is Linux-specific; on other platforms we return basic info
// using the current process credentials as a fallback.
func getPeerCred(conn net.Conn) (*PeerInfo, error) {
	_ = conn
	// On non-Linux, return current process info as a best-effort fallback
	return &PeerInfo{
		PID: int32(os.Getpid()),
		UID: int32(os.Getuid()),
		GID: int32(os.Getgid()),
	}, fmt.Errorf("SO_PEERCRED not available on this platform (using fallback)")
}
