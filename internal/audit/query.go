package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"
)

// Reading the audit log for the dashboard and the API.
//
// The log is append-only JSON lines, so the newest entries are at the end.
// Search reads it backwards from the end in fixed-size chunks and stops as
// soon as it has Limit matching entries: a page that shows 10 entries costs
// the same whether the log is 1 MB or 1 GB. It never stops on a timestamp,
// because a clock stepped back can put a newer-looking line after older
// ones. Two limits stop a filter that rarely matches from reading the whole
// history:
//
//   - only the current file and the newest archive are read (see rotate.go);
//   - one query reads at most MaxScanBytes (default DefaultMaxScanBytes).
//
// When either stops a query before it found Limit matches, Result.Truncated
// is set so the caller can say so.

// DefaultMaxScanBytes is how much log one query may read when
// QueryOptions.MaxScanBytes is not set. With the prefilter in matcher.maybe
// a query that matches nothing reads this much in well under a second.
const DefaultMaxScanBytes = 64 << 20

// chunkSize is how much one backward read takes. A var so tests can force
// lines to straddle chunk edges.
var chunkSize = 64 << 10

// QueryOptions filters a query. Empty fields match everything.
type QueryOptions struct {
	Since  *time.Time
	Agent  string
	Path   string
	Status string // "allowed" or "denied"
	Limit  int    // newest N matches; 0 = every match within the scan cap
	// MaxScanBytes caps how much log the query reads; 0 = DefaultMaxScanBytes.
	MaxScanBytes int64
}

// Result is what Search found.
type Result struct {
	Entries []Entry // oldest first, like the file
	// Truncated means the search stopped before it found Limit matches
	// while older log was left unread (scan cap or older archives).
	Truncated bool
}

// Query returns the newest entries matching opts, oldest first.
// It is Search without the Truncated flag.
func Query(path string, opts QueryOptions) ([]Entry, error) {
	r, err := Search(path, opts)
	return r.Entries, err
}

// Search reads the log at path backwards (current file, then the newest
// archive) and returns the newest entries matching opts, oldest first.
func Search(path string, opts QueryOptions) (Result, error) {
	f, err := openCurrent(path)
	if err != nil {
		return Result{}, fmt.Errorf("opening audit log for query: %w", err)
	}
	defer f.Close()
	cur, err := f.Stat()
	if err != nil {
		return Result{}, fmt.Errorf("reading audit log: %w", err)
	}

	s := newScan(opts)
	done, err := s.file(f)
	if err != nil {
		return Result{}, fmt.Errorf("reading audit log: %w", err)
	}
	olderLeft := false
	if !done && !s.capped {
		// The current file ran out: carry on into the newest archive.
		arcs, err := archives(path)
		if err != nil {
			return Result{}, err
		}
		// If a rotation renamed the file we just read, it is now the newest
		// archive; skip it so no entry is returned twice.
		n := len(arcs)
		for n > 0 && sameFile(arcs[n-1].path, cur) {
			n--
		}
		if n > 0 {
			newest := arcs[n-1]
			olderLeft = n > 1
			if newest.compressed {
				olderLeft = true // a .gz cannot be read backwards; it is history
			} else if af, err := os.Open(newest.path); err == nil {
				done, err = s.file(af)
				af.Close()
				if err != nil {
					return Result{}, fmt.Errorf("reading audit archive: %w", err)
				}
			} else {
				olderLeft = true // compressed away mid-query, or unreadable
			}
		}
	}

	// s.found is newest first; callers expect file order.
	out := s.found
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return Result{Entries: out, Truncated: !done && (s.capped || olderLeft)}, nil
}

// openCurrent opens the live log. A rotation renames it and creates the new
// one a moment later; a search landing in that gap retries instead of failing.
func openCurrent(path string) (*os.File, error) {
	f, err := os.Open(path)
	for i := 0; i < 3 && errors.Is(err, fs.ErrNotExist); i++ {
		time.Sleep(time.Millisecond)
		f, err = os.Open(path)
	}
	return f, err
}

// sameFile reports whether path is the file described by fi.
func sameFile(path string, fi os.FileInfo) bool {
	st, err := os.Stat(path)
	return err == nil && os.SameFile(st, fi)
}

// scan is the state of one backward search across one or two files.
type scan struct {
	m      matcher
	limit  int
	budget int64   // bytes still allowed to read
	capped bool    // budget ran out with part of a file unread
	found  []Entry // newest first
	work   []byte  // chunk + carried line, reused
	carry  []byte  // start of a line whose beginning is further back
}

// newScan prepares a search for opts.
func newScan(opts QueryOptions) *scan {
	s := &scan{m: newMatcher(opts), limit: opts.Limit, budget: opts.MaxScanBytes}
	if s.budget <= 0 {
		s.budget = DefaultMaxScanBytes
	}
	return s
}

// file walks f's lines from last to first. It returns true when the search
// has Limit matches. A last line with
// no newline yet (a write in progress) is tried like any other: if it is
// not complete JSON it is skipped.
func (s *scan) file(f *os.File) (bool, error) {
	st, err := f.Stat()
	if err != nil {
		return false, err
	}
	pos := st.Size()
	s.carry = s.carry[:0]
	for pos > 0 {
		if s.budget <= 0 {
			s.capped = true
			return false, nil
		}
		n := min(int64(chunkSize), pos, s.budget)
		pos -= n
		s.budget -= n

		// work = this chunk followed by the carried partial line.
		need := int(n) + len(s.carry)
		if cap(s.work) < need {
			s.work = make([]byte, need)
		}
		data := s.work[:need]
		copy(data[n:], s.carry)
		if _, err := f.ReadAt(data[:n], pos); err != nil && err != io.EOF {
			return false, err
		}

		end := len(data)
		for {
			i := bytes.LastIndexByte(data[:end], '\n')
			if i < 0 {
				break
			}
			if s.line(data[i+1 : end]) {
				return true, nil
			}
			end = i
		}
		s.carry = append(s.carry[:0], data[:end]...)
	}
	return s.line(s.carry), nil
}

// line checks one log line and reports whether the search is finished.
func (s *scan) line(line []byte) bool {
	if len(line) == 0 {
		return false
	}
	if since := s.m.opts.Since; since != nil {
		// Skip, never stop: an older line can follow a newer one.
		if ts, ok := lineTime(line); ok && ts.Before(*since) {
			return false
		}
	}
	if !s.m.maybe(line) {
		return false
	}
	var e Entry
	if err := json.Unmarshal(line, &e); err != nil {
		return false // malformed or half-written line
	}
	if !s.m.match(e) {
		return false
	}
	s.found = append(s.found, e)
	return s.limit > 0 && len(s.found) >= s.limit
}

// lineTime reads the timestamp at the start of a line without decoding the
// rest, so a since-query skips old lines cheaply. Every writer puts "ts" first.
func lineTime(line []byte) (time.Time, bool) {
	const prefix = `{"ts":"`
	if !bytes.HasPrefix(line, []byte(prefix)) {
		return time.Time{}, false
	}
	rest := line[len(prefix):]
	end := bytes.IndexByte(rest, '"')
	if end < 0 {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, string(rest[:end]))
	return t, err == nil
}

// matcher applies QueryOptions to lines and entries.
type matcher struct {
	opts    QueryOptions
	needles [][]byte // `"agent":"x"` etc.; a matching line contains them all
}

// newMatcher builds the needles for the cheap byte prefilter. Every writer
// encodes with encoding/json defaults, so a field equal to v appears in the
// line exactly as `"field":` followed by json.Marshal(v).
func newMatcher(opts QueryOptions) matcher {
	m := matcher{opts: opts}
	add := func(field, v string) {
		if v == "" {
			return
		}
		b, _ := json.Marshal(v)
		m.needles = append(m.needles, append([]byte(`"`+field+`":`), b...))
	}
	add("agent", opts.Agent)
	add("path", opts.Path)
	add("status", opts.Status)
	return m
}

// maybe is the prefilter: false means the line cannot match, so it is not
// decoded. True still needs match, since metadata can repeat a key.
func (m matcher) maybe(line []byte) bool {
	for _, n := range m.needles {
		if !bytes.Contains(line, n) {
			return false
		}
	}
	return true
}

// match is the exact check on a decoded entry.
func (m matcher) match(e Entry) bool {
	o := m.opts
	return (o.Since == nil || !e.Timestamp.Before(*o.Since)) &&
		(o.Agent == "" || e.Agent == o.Agent) &&
		(o.Path == "" || e.Path == o.Path) &&
		(o.Status == "" || e.Status == o.Status)
}
