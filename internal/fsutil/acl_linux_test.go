package fsutil

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A user given access with setfacl keeps it when the file is replaced.
func TestReplaceKeepsPosixACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.key")
	if err := os.WriteFile(path, []byte("old"), 0640); err != nil {
		t.Fatal(err)
	}
	// u::rw-, u:65534:r--, g::---, mask::r--, o::---
	acl := binary.LittleEndian.AppendUint32(nil, 2)
	for _, e := range [][3]uint32{{0x01, 6, ^uint32(0)}, {0x02, 4, 65534}, {0x04, 0, ^uint32(0)}, {0x10, 4, ^uint32(0)}, {0x20, 0, ^uint32(0)}} {
		acl = binary.LittleEndian.AppendUint16(acl, uint16(e[0]))
		acl = binary.LittleEndian.AppendUint16(acl, uint16(e[1]))
		acl = binary.LittleEndian.AppendUint32(acl, e[2])
	}
	if err := syscall.Setxattr(path, posixACL, acl, 0); err != nil {
		t.Skipf("no POSIX ACLs here: %v", err)
	}
	if err := WriteFileAtomic(path, []byte("new"), 0640); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 256)
	n, err := syscall.Getxattr(path, posixACL, got)
	if err != nil || !bytes.Equal(got[:n], acl) {
		t.Errorf("ACL after replacing: %v", err)
	}
	// A file forced to 0600 (store, keys) does not inherit wider access.
	if err := WriteFileAtomic(path, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if n, err := syscall.Getxattr(path, posixACL, got); err == nil && n > 0 {
		t.Error("a file forced to 0600 kept an ACL")
	}
}
