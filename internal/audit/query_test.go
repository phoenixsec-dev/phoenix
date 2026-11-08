package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// paths returns the Path of each entry, for compact comparisons.
func paths(es []Entry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Path
	}
	return out
}

// Backward reading must rebuild lines that straddle chunk edges, including a
// line longer than a whole chunk, and keep file order in the result.
func TestSearchReadsBackwardAcrossChunks(t *testing.T) {
	old := chunkSize
	chunkSize = 7
	defer func() { chunkSize = old }()

	path := filepath.Join(t.TempDir(), "audit.log")
	l, _ := NewLogger(path)
	l.LogAllowed("a", "read", "p/0", "1.1.1.1")
	l.LogAllowed("a&<b>", "read", "p/1/"+strings.Repeat("x", 300), "1.1.1.1")
	l.LogDenied("a", "read", "p/2", "1.1.1.1", "acl")
	l.LogAllowed("a", "read", "p/3", "1.1.1.1")
	l.Close()

	got, err := Query(path, QueryOptions{})
	if err != nil || len(got) != 4 || got[0].Path != "p/0" || got[3].Path != "p/3" {
		t.Fatalf("all = %v, err %v", paths(got), err)
	}
	if got, _ := Query(path, QueryOptions{Limit: 2}); fmt.Sprint(paths(got)) != "[p/2 p/3]" {
		t.Fatalf("limit 2 = %v", paths(got))
	}
	// The prefilter needle must use the same JSON escaping as the writer.
	if got, _ := Query(path, QueryOptions{Agent: "a&<b>"}); len(got) != 1 {
		t.Fatalf("escaped agent matched %d", len(got))
	}
	if got, _ := Query(path, QueryOptions{Status: "denied"}); len(got) != 1 || got[0].Path != "p/2" {
		t.Fatalf("denied = %v", paths(got))
	}
}

// A half-written last line (no newline, not valid JSON) is skipped; a
// complete last line that is only missing its newline is still read.
func TestSearchPartialLastLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, _ := NewLogger(path)
	l.LogAllowed("a", "read", "p/0", "1.1.1.1")
	l.LogAllowed("a", "read", "p/1", "1.1.1.1")
	l.Close()

	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString(`{"ts":"2026-11-08T00:00:00Z","agent":"a","act`)
	f.Close()
	got, err := Query(path, QueryOptions{})
	if err != nil || fmt.Sprint(paths(got)) != "[p/0 p/1]" {
		t.Fatalf("with half line = %v, err %v", paths(got), err)
	}

	os.WriteFile(path, []byte(`{"ts":"2026-11-08T00:00:00Z","agent":"a","path":"p/0","status":"allowed"}`+"\n"+
		`{"ts":"2026-11-08T00:00:01Z","agent":"a","path":"p/1","status":"allowed"}`), 0600)
	if got, _ := Query(path, QueryOptions{}); fmt.Sprint(paths(got)) != "[p/0 p/1]" {
		t.Fatalf("no trailing newline = %v", paths(got))
	}
}

// A filter that matches nothing stops at the read cap and says so; the same
// search over a log smaller than the cap is complete.
func TestSearchScanCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, _ := NewLogger(path)
	for i := 0; i < 200; i++ {
		l.LogAllowed("a", "read", fmt.Sprintf("p/%d", i), "1.1.1.1")
	}
	l.Close()

	res, err := Search(path, QueryOptions{Agent: "nobody", MaxScanBytes: 1000})
	if err != nil || len(res.Entries) != 0 || !res.Truncated {
		t.Fatalf("capped = %+v, err %v", res, err)
	}
	res, _ = Search(path, QueryOptions{Agent: "nobody"})
	if res.Truncated {
		t.Fatal("whole log read but marked truncated")
	}
	// Reaching the limit inside the cap is a complete answer.
	res, _ = Search(path, QueryOptions{Limit: 3, MaxScanBytes: 1000})
	if len(res.Entries) != 3 || res.Truncated {
		t.Fatalf("limit inside cap = %+v", res)
	}
}

// After the clock steps back, an older-looking line follows a newer one.
// A since-query must skip it, not stop there and miss the newer match.
func TestSearchSinceSurvivesClockStepBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	os.WriteFile(path, []byte(
		`{"ts":"2026-11-08T12:00:00Z","agent":"a","path":"p/new","status":"allowed"}`+"\n"+
			`{"ts":"2026-11-08T11:00:00Z","agent":"a","path":"p/after-step-back","status":"allowed"}`+"\n"), 0600)
	since, _ := time.Parse(time.RFC3339, "2026-11-08T11:30:00Z")
	res, err := Search(path, QueryOptions{Since: &since})
	if err != nil || fmt.Sprint(paths(res.Entries)) != "[p/new]" || res.Truncated {
		t.Fatalf("since = %v truncated %v, err %v", paths(res.Entries), res.Truncated, err)
	}
}

// A rotation between reading audit.log and listing archives leaves the file
// just read as the newest archive. It must not be read twice.
func TestSearchSkipsArchiveItAlreadyRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	l, _ := NewLogger(path)
	for i := 0; i < 3; i++ {
		l.LogAllowed("a", "read", fmt.Sprintf("p/%d", i), "1.1.1.1")
	}
	l.Close()
	// Same inode under both names: what Search sees mid-rotation.
	if err := os.Link(path, filepath.Join(dir, "audit-20261108T000000.000Z.log")); err != nil {
		t.Skip("no hard links here:", err)
	}
	res, _ := Search(path, QueryOptions{Limit: 10})
	if fmt.Sprint(paths(res.Entries)) != "[p/0 p/1 p/2]" || res.Truncated {
		t.Fatalf("got %v truncated %v", paths(res.Entries), res.Truncated)
	}
}
