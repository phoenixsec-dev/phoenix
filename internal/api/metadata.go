package api

import (
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/store"
)

// secretInfo is everything about a secret except its value. It is built
// field by field from store.SecretMetadata, never from store.Secret, so a
// value cannot end up in a metadata response.
type secretInfo struct {
	Path        string     `json:"path"`
	Description string     `json:"description"`
	Tags        []string   `json:"tags,omitempty"`
	Created     *time.Time `json:"created,omitempty"`
	Updated     *time.Time `json:"updated,omitempty"`
	CreatedBy   string     `json:"created_by,omitempty"`
	UpdatedBy   string     `json:"updated_by,omitempty"`
	RotationDue string     `json:"rotation_due,omitempty"`
}

// metadataRoutes registers the read-only metadata API used by
// `phoenix list`, `phoenix info` and MCP phoenix_list.
func (s *Server) metadataRoutes() {
	s.mux.HandleFunc("GET /v1/metadata/", s.handleSecretMetadata)
}

// newSecretInfo copies the safe metadata fields for one path. UpdatedBy
// falls back to CreatedBy for secrets written before updated_by existed,
// because older versions stored the last writer in created_by.
func newSecretInfo(path string, m *store.SecretMetadata) secretInfo {
	si := secretInfo{
		Path:        path,
		Description: m.Description,
		Tags:        m.Tags,
		CreatedBy:   m.CreatedBy,
		UpdatedBy:   m.UpdatedBy,
		RotationDue: m.RotationDue,
	}
	if si.UpdatedBy == "" {
		si.UpdatedBy = m.CreatedBy
	}
	if !m.Created.IsZero() {
		t := m.Created
		si.Created = &t
	}
	if !m.Updated.IsZero() {
		t := m.Updated
		si.Updated = &t
	}
	return si
}

// handleSecretMetadata serves GET /v1/metadata/<path>. A prefix (empty or
// ending in "/") returns {"secrets": [...]} for every path the caller may
// list, optionally narrowed by ?tag=<tag>. A single path returns one
// secretInfo. Access is exactly the list permission, and both forms are
// audited as "list". Values are never returned. Each request makes one
// backend List call (on 1Password a vault walk, as the list route does).
func (s *Server) handleSecretMetadata(w http.ResponseWriter, r *http.Request) {
	info, err := s.authenticateInfo(r)
	if err != nil {
		handleAuthError(w, err)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1/metadata/")
	ip := clientIP(r)

	if !s.checkSessionSealKey(w, r, info) {
		return
	}
	sealKey, sealErr := s.validateSealHeader(r, info)
	if sealErr != nil {
		jsonError(w, sealErr.Error(), http.StatusBadRequest)
		return
	}
	sealKeyValidated := sealKey != nil

	if path == "" || strings.HasSuffix(path, "/") {
		if !s.checkSessionAction(w, r, info, "list", path, ip) {
			return
		}
		allPaths, err := s.backend.List(path)
		if err != nil {
			log.Printf("error listing secrets with prefix %q: %v", path, err)
			jsonError(w, "internal error", http.StatusInternalServerError)
			return
		}
		tag := r.URL.Query().Get("tag")
		out := []secretInfo{}
		for _, p := range allPaths {
			// Same visibility as the list route: ACL only, then attestation.
			reason := s.baseAccessReason(info, p, "list", acl.ActionList)
			if sessionEndedReason(reason) {
				s.writeDataDenial(w, r, info, "list", path, ip, reason)
				return
			}
			if reason != "" {
				continue
			}
			if s.attestFull(r, p, info, sealKeyValidated) != nil {
				continue
			}
			m, err := s.backend.Metadata(p)
			if err == store.ErrSecretNotFound {
				continue // deleted since List
			}
			if err != nil {
				log.Printf("error reading metadata for %q: %v", p, err)
				jsonError(w, "internal error", http.StatusInternalServerError)
				return
			}
			if tag != "" && !slices.Contains(m.Tags, tag) {
				continue
			}
			out = append(out, newSecretInfo(p, m))
		}
		s.auditAllowed(r, info, "list", path, ip)
		jsonOK(w, map[string]interface{}{"secrets": out})
		return
	}

	if reason := s.baseAccessReason(info, path, "list", acl.ActionList); reason != "" {
		s.writeDataDenial(w, r, info, "list", path, ip, reason)
		return
	}
	if err := s.attestFull(r, path, info, sealKeyValidated); err != nil {
		s.denyAttestation(w, r, info, "list", path, ip, err)
		return
	}
	// Existence comes from List: some backends' Metadata does not check it.
	if err := store.ValidatePath(path); err != nil {
		jsonError(w, "invalid secret path", http.StatusBadRequest)
		return
	}
	paths, err := s.backend.List(path)
	if err != nil {
		log.Printf("error listing secrets with prefix %q: %v", path, err)
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !slices.Contains(paths, path) {
		jsonError(w, "secret not found", http.StatusNotFound)
		return
	}
	m, err := s.backend.Metadata(path)
	if err == store.ErrSecretNotFound {
		jsonError(w, "secret not found", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("error reading metadata for %q: %v", path, err)
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.auditAllowed(r, info, "list", path, ip)
	jsonOK(w, newSecretInfo(path, m))
}
