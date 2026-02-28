//go:build linux

package agent

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// ucred matches the C struct ucred from <sys/socket.h>.
type ucred struct {
	Pid int32
	Uid uint32
	Gid uint32
}

// getPeerCred extracts peer credentials from a Unix domain socket connection
// using the SO_PEERCRED socket option (Linux-specific).
// Uses raw syscall to avoid external dependencies.
func getPeerCred(conn net.Conn) (*PeerInfo, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("not a Unix connection")
	}

	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("getting raw connection: %w", err)
	}

	var cred ucred
	var credErr error

	err = raw.Control(func(fd uintptr) {
		credLen := uint32(unsafe.Sizeof(cred))
		_, _, errno := syscall.RawSyscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			syscall.SOL_SOCKET,
			syscall.SO_PEERCRED,
			uintptr(unsafe.Pointer(&cred)),
			uintptr(unsafe.Pointer(&credLen)),
			0,
		)
		if errno != 0 {
			credErr = fmt.Errorf("getsockopt SO_PEERCRED: %v", errno)
		}
	})
	if err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	if credErr != nil {
		return nil, credErr
	}

	return &PeerInfo{
		PID: cred.Pid,
		UID: int32(cred.Uid),
		GID: int32(cred.Gid),
	}, nil
}
