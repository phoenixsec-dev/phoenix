package fsutil

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Who may read a file stays the same when it is replaced.
func TestReplaceKeepingAccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.key")
	if err := ReplaceKeepingAccess(path, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	if err := ReplaceKeepingAccess(path, []byte("second"), 0600); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if after.Mode().Perm() != 0640 || os.SameFile(before, after) {
		t.Errorf("mode %o, rewritten in place %v", after.Mode().Perm(), os.SameFile(before, after))
	}
	if !setTestACL(path) {
		t.Skip("no POSIX ACLs here")
	}
	if err := ReplaceKeepingAccess(path, []byte("third"), 0600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "third" || !hasACL(path) {
		t.Errorf("content %q, ACL kept %v", b, hasACL(path))
	}
}

// testACL is u::rw-, u:65534:r--, g::---, mask::r--, o::---.
func testACL() []byte {
	acl := binary.LittleEndian.AppendUint32(nil, 2)
	for _, e := range [][3]uint32{{0x01, 6, ^uint32(0)}, {0x02, 4, 65534}, {0x04, 0, ^uint32(0)}, {0x10, 4, ^uint32(0)}, {0x20, 0, ^uint32(0)}} {
		acl = binary.LittleEndian.AppendUint16(acl, uint16(e[0]))
		acl = binary.LittleEndian.AppendUint16(acl, uint16(e[1]))
		acl = binary.LittleEndian.AppendUint32(acl, e[2])
	}
	return acl
}

// A device or pipe is written to, never replaced by a file that takes its mode.
func TestReplaceKeepingAccessLeavesDevices(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	link := filepath.Join(t.TempDir(), "server.key")
	if err := os.Symlink(os.DevNull, link); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceKeepingAccess(link, []byte("key"), 0600); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link was replaced: %v", err)
	}
}
