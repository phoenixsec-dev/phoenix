package store

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/phoenixsec/phoenix/internal/crypto"
)

// ErrSecretExists is returned by Write with WriteNew when the path is taken.
var ErrSecretExists = errors.New("secret already exists")

// WriteMode says what Write may do with the path.
type WriteMode int

const (
	WriteAny      WriteMode = iota // create or replace
	WriteNew                       // only create; ErrSecretExists if it is there
	WriteExisting                  // only replace; ErrSecretNotFound if it is not
)

// MetadataChange is a set of edits to a secret's metadata. A nil field keeps
// what is stored; an empty one clears it.
type MetadataChange struct {
	Description *string
	Tags        *[]string
	Username    *string
	URL         *string
}

// MetadataError says in plain words why a MetadataChange was refused. Its
// text never contains the rejected value.
type MetadataError struct{ Msg string }

func (e *MetadataError) Error() string { return e.Msg }

// Size limits in bytes.
const (
	maxUsernameLen = 256
	maxURLLen      = 2048
)

// Fields names the fields the change sets, for audit lines and replies.
func (ch MetadataChange) Fields() []string {
	var f []string
	if ch.Description != nil {
		f = append(f, "description")
	}
	if ch.Tags != nil {
		f = append(f, "tags")
	}
	if ch.Username != nil {
		f = append(f, "username")
	}
	if ch.URL != nil {
		f = append(f, "url")
	}
	return f
}

// Validate checks the username and link, if set. Descriptions and tags have
// always been free text; every place that shows them escapes them.
func (ch MetadataChange) Validate() error {
	if ch.Username != nil {
		if len(*ch.Username) > maxUsernameLen {
			return &MetadataError{fmt.Sprintf("the username is too long (at most %d bytes)", maxUsernameLen)}
		}
		if !plainText(*ch.Username) {
			return &MetadataError{"the username has control or invisible characters in it"}
		}
	}
	if ch.URL != nil {
		return ValidateURL(*ch.URL)
	}
	return nil
}

// ValidateURL checks a secret's link: empty, or a full http(s) address with
// no password in it. The dashboard also calls it before making a link of a
// stored one, because a hand-edited store file can hold anything.
func ValidateURL(raw string) error {
	if raw == "" {
		return nil
	}
	if len(raw) > maxURLLen {
		return &MetadataError{fmt.Sprintf("the link is too long (at most %d bytes)", maxURLLen)}
	}
	if !plainText(raw) || strings.ContainsAny(raw, " \\") {
		return &MetadataError{"the link has spaces, backslashes or invisible characters in it"}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return &MetadataError{"the link must be a full web address starting with https:// or http://"}
	}
	if u.User != nil {
		return &MetadataError{"the link must not have a username or password in it"}
	}
	return nil
}

// plainText reports whether s is valid UTF-8 with no control, bidi or other
// invisible formatting characters, which could make it display as something
// it is not.
func plainText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

// apply copies the set fields of ch into m.
func (ch MetadataChange) apply(m *SecretMetadata) {
	if ch.Description != nil {
		m.Description = *ch.Description
	}
	if ch.Tags != nil {
		m.Tags = append([]string(nil), *ch.Tags...)
	}
	if ch.Username != nil {
		m.Username = *ch.Username
	}
	if ch.URL != nil {
		m.URL = *ch.URL
	}
}

// Write stores value at path with metadata changes, in one save. CreatedBy
// and Created of an existing secret are kept. If the save fails nothing
// changed, on disk or in memory.
func (s *Store) Write(path, value, by string, ch MetadataChange, mode WriteMode) (err error) {
	if err := ValidatePath(path); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.data.Secrets[path]
	if exists && mode == WriteNew {
		return ErrSecretExists
	}
	if !exists && mode == WriteExisting {
		return ErrSecretNotFound
	}

	ns := namespace(path)
	_, hadNS := s.data.Namespaces[ns]
	dek, err := s.getDEK(ns)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil && !hadNS {
			delete(s.data.Namespaces, ns) // a key made for nothing
		}
	}()
	blob, err := crypto.Encrypt(dek, []byte(value))
	if err != nil {
		return fmt.Errorf("encrypting secret: %w", err)
	}

	now := time.Now().UTC()
	meta := SecretMetadata{Created: now, CreatedBy: by}
	if exists {
		meta = existing.Metadata
	}
	meta.Updated, meta.UpdatedBy, meta.RotationDue = now, by, ""
	ch.apply(&meta)

	return s.replaceLocked(path, encryptedSecret{Path: path, Value: *blob, Namespace: ns, Metadata: meta})
}

// Describe changes the metadata of an existing secret. The stored ciphertext
// is carried over untouched and never decrypted. Created, CreatedBy, Updated
// and UpdatedBy stay as they are: they are about the value. If the save fails
// nothing changed.
func (s *Store) Describe(path string, ch MetadataChange) error {
	if err := ValidatePath(path); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sec, ok := s.data.Secrets[path]
	if !ok {
		return ErrSecretNotFound
	}
	ch.apply(&sec.Metadata)
	return s.replaceLocked(path, sec)
}

// replaceLocked puts one secret in the store and saves it, putting the old
// entry back if the save fails. Caller holds s.mu for writing.
func (s *Store) replaceLocked(path string, sec encryptedSecret) error {
	old, had := s.data.Secrets[path]
	s.data.Secrets[path] = sec
	if err := s.save(); err != nil {
		if had {
			s.data.Secrets[path] = old
		} else {
			delete(s.data.Secrets, path)
		}
		return err
	}
	return nil
}
