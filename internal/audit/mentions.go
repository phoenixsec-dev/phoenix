package audit

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
)

// secretActions are the allowed actions that only happen to a secret that is
// there. "read" is from before v0.11; list and session lines prove nothing.
var secretActions = []string{"write", "read_value", "resolve", "dry-resolve", "describe", "delete", "read"}

// MentionsSecrets reports whether the log at path, or any archive of it, has a
// line about a secret that was there: written, handed over, changed or deleted.
// No log means no. A log that is not a file, such as /dev/stdout, keeps no lines.
// It reads everything in the worst case, so it is for a start that found no store.
func MentionsSecrets(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err == nil && !fi.Mode().IsRegular() {
		return false, nil
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	var files []archive
	if err == nil {
		files = append(files, archive{path: path})
	}
	arcs, err := archives(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	slices.Reverse(arcs) // newest first: most likely to answer at once
	var unread error
	for _, a := range append(files, arcs...) {
		found, err := fileMentionsSecrets(a)
		if found {
			return true, nil
		}
		if err != nil {
			unread = errors.Join(unread, fmt.Errorf("%s: %w", a.path, err))
		}
	}
	return false, unread
}

// fileMentionsSecrets is MentionsSecrets for one file.
func fileMentionsSecrets(a archive) (bool, error) {
	f, err := os.Open(a.path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	var r io.Reader = f
	if a.compressed {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return false, err
		}
		r = zr
	}
	br := bufio.NewReaderSize(r, chunkSize)
	for {
		line, err := br.ReadBytes('\n')
		var e struct{ Action, Status string }
		if bytes.Contains(line, []byte("allowed")) && json.Unmarshal(line, &e) == nil &&
			e.Status == "allowed" && slices.Contains(secretActions, e.Action) {
			return true, nil
		}
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}
}
