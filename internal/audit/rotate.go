package audit

import (
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Audit log rotation. Nothing here ever deletes history.
//
// When a write takes audit.log past the rotate size, the file is renamed to
// a dated archive next to it (audit-20261108T120000.000Z.log) and a fresh
// audit.log is started. Archives are kept forever; removing them is left to
// a human. The newest archive stays plain so Search can read it backwards
// when a query needs more than the current file holds. Every older archive
// is gzipped in the background (audit-....log.gz).

// archiveLayout is the UTC time in an archive's name. Fixed width, so
// sorting names sorts archives oldest to newest.
const archiveLayout = "20060102T150405.000Z"

// archive is one rotated-out log file.
type archive struct {
	path       string
	stamp      string // archiveLayout time from the name
	compressed bool
}

// splitLogName splits /dir/audit.log into ("/dir", "audit", ".log").
func splitLogName(path string) (dir, stem, ext string) {
	dir, base := filepath.Split(path)
	ext = filepath.Ext(base)
	return filepath.Clean(dir), strings.TrimSuffix(base, ext), ext
}

// archives lists the archives of the log at path, oldest first. When a
// rotation was cut short and both x.log and x.log.gz exist, the plain one
// is listed.
func archives(path string) ([]archive, error) {
	dir, stem, ext := splitLogName(path)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("listing audit archives: %w", err)
	}
	byStamp := map[string]archive{}
	for _, de := range ents {
		name := de.Name()
		rest, ok := strings.CutPrefix(name, stem+"-")
		if !ok || de.IsDir() {
			continue
		}
		a := archive{path: filepath.Join(dir, name)}
		if s, ok := strings.CutSuffix(rest, ext+".gz"); ok {
			a.stamp, a.compressed = s, true
		} else if s, ok := strings.CutSuffix(rest, ext); ok {
			a.stamp = s
		} else {
			continue
		}
		if _, err := time.Parse(archiveLayout, a.stamp); err != nil {
			continue // not ours
		}
		if prev, dup := byStamp[a.stamp]; dup && !prev.compressed {
			continue
		}
		byStamp[a.stamp] = a
	}
	out := make([]archive, 0, len(byStamp))
	for _, a := range byStamp {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].stamp < out[j].stamp })
	return out, nil
}

// nextArchiveName picks the archive name for a rotation at now. It always
// sorts after every existing archive, even if the clock stepped back.
func nextArchiveName(path string, now time.Time) (string, error) {
	arcs, err := archives(path)
	if err != nil {
		return "", err
	}
	t := now.UTC().Truncate(time.Millisecond)
	if n := len(arcs); n > 0 {
		last, _ := time.Parse(archiveLayout, arcs[n-1].stamp)
		if !t.After(last) {
			t = last.Add(time.Millisecond)
		}
	}
	dir, stem, ext := splitLogName(path)
	return filepath.Join(dir, stem+"-"+t.Format(archiveLayout)+ext), nil
}

// rotate moves the full log aside and starts a new one. It runs with l.mu
// held, so no write can land in between: every line is in exactly one file.
// The old file was synced after its last write and is closed only once the
// new one is open.
func (l *Logger) rotate() error {
	name, err := nextArchiveName(l.path, time.Now())
	if err != nil {
		return err
	}
	if err := os.Rename(l.path, name); err != nil {
		return fmt.Errorf("renaming audit log to %s: %w", name, err)
	}
	nf, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		// Put the old file back; its open handle never stopped working.
		if rerr := os.Rename(name, l.path); rerr != nil {
			log.Printf("audit: WARNING: could not start a new audit log (%v) or restore the old name (%v); still writing to %s", err, rerr, name)
		}
		return fmt.Errorf("opening new audit log: %w", err)
	}
	if err := syncDir(filepath.Dir(l.path)); err != nil {
		log.Printf("audit: WARNING: syncing the audit directory after rotation: %v", err)
	}
	l.file.Close()
	l.file, l.w, l.size = nf, nf, 0
	l.kickCompress()
	return nil
}

// kickCompress asks the background worker to compress old archives.
func (l *Logger) kickCompress() {
	select {
	case l.kick <- struct{}{}:
	default: // a run is already queued
	}
}

// compressWorker gzips archives whenever kicked, until Close closes kick.
func (l *Logger) compressWorker(kick <-chan struct{}) {
	defer l.wg.Done()
	for range kick {
		if err := compressOldArchives(l.path); err != nil {
			log.Printf("audit: WARNING: compressing old audit archives: %v", err)
		}
	}
}

// compressOldArchives gzips every plain archive except the newest. Also
// finishes a compression a crash interrupted.
func compressOldArchives(path string) error {
	arcs, err := archives(path)
	if err != nil {
		return err
	}
	for i, a := range arcs {
		if a.compressed || i == len(arcs)-1 {
			continue
		}
		if err := gzipFile(a.path); err != nil {
			return err
		}
	}
	return nil
}

// gzipFile writes src.gz and only then removes src, so a crash at any point
// leaves at least one complete copy. A leftover .gz.tmp is overwritten.
func gzipFile(src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	dst := src + ".gz"
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(out)
	zw.Name = filepath.Base(src)
	_, err = io.Copy(zw, in)
	if cerr := zw.Close(); err == nil {
		err = cerr
	}
	if serr := out.Sync(); err == nil {
		err = serr
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("compressing %s: %w", src, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(src)); err != nil {
		return err
	}
	return os.Remove(src)
}

// syncDir makes a rename in dir durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
