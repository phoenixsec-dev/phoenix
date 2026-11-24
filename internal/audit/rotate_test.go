package audit

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readAll returns every entry in the current log and all archives, oldest first.
func readAll(t *testing.T, path string) []Entry {
	t.Helper()
	arcs, err := archives(path)
	if err != nil {
		t.Fatal(err)
	}
	var files []archive
	files = append(files, arcs...)
	files = append(files, archive{path: path})
	var out []Entry
	for _, a := range files {
		f, err := os.Open(a.path)
		if err != nil {
			t.Fatal(err)
		}
		var r io.Reader = f
		if a.compressed {
			zr, err := gzip.NewReader(f)
			if err != nil {
				t.Fatalf("%s: %v", a.path, err)
			}
			r = zr
		}
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			var e Entry
			if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
				t.Fatalf("%s: bad line %q", a.path, sc.Text())
			}
			out = append(out, e)
		}
		f.Close()
	}
	return out
}

// Rotation must not lose, repeat or reorder a line. The newest archive stays
// plain, older ones become .gz, and nothing is left half done.
func TestRotationKeepsEveryLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	l, err := NewRotatingLogger(path, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		l.LogAllowed("a", "read", fmt.Sprintf("p/%d", i), "1.1.1.1")
	}
	l.Close() // waits for compression

	all := readAll(t, path)
	if len(all) != 100 {
		t.Fatalf("%d entries across files, want 100", len(all))
	}
	for i, e := range all {
		if want := fmt.Sprintf("p/%d", i); e.Path != want {
			t.Fatalf("entry %d = %s, want %s", i, e.Path, want)
		}
	}
	arcs, _ := archives(path)
	if len(arcs) < 3 {
		t.Fatalf("only %d archives", len(arcs))
	}
	for i, a := range arcs {
		if want := i < len(arcs)-1; a.compressed != want {
			t.Fatalf("archive %d (%s) compressed=%v, want %v", i, a.path, a.compressed, want)
		}
	}
	ents, _ := os.ReadDir(dir)
	for _, de := range ents {
		if strings.HasSuffix(de.Name(), ".tmp") {
			t.Fatalf("leftover %s", de.Name())
		}
	}
}

// Just after a rotation the current file is short, so a search continues
// into the newest archive, with filters applied on both sides. It is marked
// truncated only when it needed more and older archives were skipped.
func TestSearchAcrossRotationBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, _ := NewRotatingLogger(path, 1500)
	for i := 0; i < 40; i++ {
		agent := "a"
		if i%4 == 0 {
			agent = "b"
		}
		l.LogAllowed(agent, "read", fmt.Sprintf("p/%d", i), "1.1.1.1")
	}
	l.Close()

	all := readAll(t, path)
	arcs, _ := archives(path)
	lines := func(p string) int {
		b, _ := os.ReadFile(p)
		return strings.Count(string(b), "\n")
	}
	cur, newest := lines(path), lines(arcs[len(arcs)-1].path)
	if cur == 0 || cur+newest >= len(all) {
		t.Fatalf("setup: current %d, newest archive %d, total %d", cur, newest, len(all))
	}

	// Newest few cross the boundary, in order.
	n := cur + newest/2 // more than the current file holds
	res, _ := Search(path, QueryOptions{Limit: n})
	if len(res.Entries) != n || res.Truncated {
		t.Fatalf("limit %d: got %d, truncated %v", n, len(res.Entries), res.Truncated)
	}
	if fmt.Sprint(paths(res.Entries)) != fmt.Sprint(paths(all[len(all)-n:])) {
		t.Fatalf("got %v\nwant %v", paths(res.Entries), paths(all[len(all)-n:]))
	}

	// Filter across the boundary: every "b" in current + newest archive.
	var wantB []string
	for _, e := range all[len(all)-cur-newest:] {
		if e.Agent == "b" {
			wantB = append(wantB, e.Path)
		}
	}
	res, _ = Search(path, QueryOptions{Agent: "b", Limit: 1000})
	if fmt.Sprint(paths(res.Entries)) != fmt.Sprint(wantB) || !res.Truncated {
		t.Fatalf("agent b = %v truncated %v, want %v truncated", paths(res.Entries), res.Truncated, wantB)
	}
}

// Rotating a log reached through a symlink keeps the new log and the archive
// where the link points, and the link in place. Renaming the link would put
// every later line somewhere else, such as a container's throwaway disk.
func TestRotateThroughSymlink(t *testing.T) {
	vol, dir := t.TempDir(), t.TempDir()
	real, link := filepath.Join(vol, "audit.log"), filepath.Join(dir, "audit.log")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	write := func(lines int, maxBytes int64) {
		t.Helper()
		l, err := NewRotatingLogger(link, maxBytes)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		for range lines {
			if err := l.LogAllowed("a", "read_value", "ns/x", "192.0.2.1"); err != nil {
				t.Fatal(err)
			}
		}
	}
	write(3, 0)
	fi, err := os.Stat(real)
	if err != nil {
		t.Fatal(err)
	}
	write(3, fi.Size()+1) // the fourth line rotates, the others start a new log
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link is gone: %v %v", fi, err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Errorf("%d files next to the link, want only the link", len(ents))
	}
	if arcs, err := archives(real); err != nil || len(arcs) == 0 {
		t.Errorf("archives on the volume = %v %v", arcs, err)
	}
	// Queries given the link find the archives too.
	res, err := Search(link, QueryOptions{})
	if err != nil || len(res.Entries) != 6 {
		t.Errorf("Search = %d entries, %v", len(res.Entries), err)
	}
}

// UsesName knows exactly the names rotation works with, whatever the log's
// extension, because a file with such a name may be compressed and removed.
func TestUsesName(t *testing.T) {
	const stamp = "20261108T120000.000Z"
	for _, log := range []string{"audit.log", "audit.gz", "audit.tmp", "audit.gz.tmp", "audit"} {
		log = filepath.Join("/data", log)
		dir, stem, ext := splitLogName(log)
		arc := filepath.Join(dir, stem+"-"+stamp+ext)
		for _, p := range []string{arc, arc + ".gz", arc + ".gz.tmp"} {
			if !UsesName(log, p) {
				t.Errorf("%s: %s should be taken", log, p)
			}
		}
		for _, p := range []string{log, arc + ".bak", arc + ".tmp.x", arc + ".gz.gz.tmp", filepath.Join("/other", filepath.Base(arc)), filepath.Join(dir, stem+"-notes"+ext), filepath.Join(dir, stem+"-20261399T996060.000Z"+ext)} {
			if UsesName(log, p) {
				t.Errorf("%s: %s should be free", log, p)
			}
		}
	}
}
