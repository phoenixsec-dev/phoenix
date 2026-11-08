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
