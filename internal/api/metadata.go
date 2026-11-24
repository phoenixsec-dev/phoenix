package api

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/audit"
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
	Username    string     `json:"username,omitempty"`
	URL         string     `json:"url,omitempty"`
}

// metadataRoutes registers the metadata API: reads for `phoenix list`,
// `phoenix info` and MCP phoenix_list, and changes for `phoenix describe`.
func (s *Server) metadataRoutes() {
	s.mux.HandleFunc("GET /v1/metadata/", s.handleSecretMetadata)
	s.mux.HandleFunc("PATCH /v1/metadata/", s.handleDescribeSecret)
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
		Username:    m.Username,
		URL:         m.URL,
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
			if s.baseAccessReason(info, p, "list", acl.ActionList) != "" {
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
		// Not a short list: say so if the login ended meanwhile.
		if reason := s.loginEnded(info); reason != "" {
			s.writeDataDenial(w, r, info, "list", path, ip, reason)
			return
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

// describeRequest is the JSON body of PATCH /v1/metadata/<path>. A field left
// out (or null) keeps what is stored; an empty one clears it.
type describeRequest struct {
	Description *string   `json:"description"`
	Tags        *[]string `json:"tags"`
	Username    *string   `json:"username"`
	URL         *string   `json:"url"`
}

// handleDescribeSecret serves PATCH /v1/metadata/<path>: it changes the
// description, tags, username or link of an existing secret. It needs write
// permission on the path and never reads or writes the value, so the store's
// created_by and updated_by (who wrote the value) stay as they are. Audited
// as "describe" with the names of the changed fields, never their text (a
// refusal is audited as "write", the permission that was missing). The reply holds no metadata, because write permission does not include list.
func (s *Server) handleDescribeSecret(w http.ResponseWriter, r *http.Request) {
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
	// write is never grantable: session and ACL only, as for a value write.
	if reason := s.dataAccess(info, path, "write", acl.ActionWrite, ip).Reason; reason != "" {
		s.writeDataDenial(w, r, info, "write", path, ip, reason)
		return
	}
	if err := s.attestFull(r, path, info, sealKey != nil); err != nil {
		s.denyAttestation(w, r, info, "write", path, ip, err)
		return
	}

	// Unknown fields are refused: a "value" sent here must not look saved.
	var req describeRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes))
	dec.DisallowUnknownFields()
	err = dec.Decode(&req)
	if err == nil && dec.Decode(&struct{}{}) != io.EOF {
		err = errors.New("trailing content")
	}
	if err != nil {
		jsonError(w, "invalid request body: send description, tags, username or url (the value is changed with PUT /v1/secrets)", http.StatusBadRequest)
		return
	}
	ch := store.MetadataChange{Description: req.Description, Tags: req.Tags, Username: req.Username, URL: req.URL}
	fields := ch.Fields()
	if len(fields) == 0 {
		jsonError(w, "nothing to change: send description, tags, username or url", http.StatusBadRequest)
		return
	}
	if err := ch.Validate(); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.backend.ReadOnly() {
		jsonError(w, "backend is read-only", http.StatusMethodNotAllowed)
		return
	}

	if s.writeLoginEnded(w, r, info) {
		return
	}
	switch err := s.backend.Describe(path, ch); err {
	case nil:
	case store.ErrInvalidPath:
		jsonError(w, "invalid secret path", http.StatusBadRequest)
		return
	case store.ErrSecretNotFound:
		jsonError(w, "secret not found", http.StatusNotFound)
		return
	default:
		log.Printf("error describing secret %q: %v", path, err)
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.auditDescribe(r, info, path, ip, fields)
	jsonOK(w, map[string]interface{}{"status": "ok", "path": path, "changed": fields})
}

// auditDescribe writes the "describe" audit line with the changed field names.
func (s *Server) auditDescribe(r *http.Request, info *authInfo, path, ip string, fields []string) {
	md := callerAuditMetadata(r)
	if md == nil {
		md = map[string]string{}
	}
	md["changed"] = strings.Join(fields, ",")
	s.logAudit(s.writeAudit(r, audit.Entry{
		Agent: info.Agent, Action: "describe", Path: path, Status: "allowed", IP: ip, SessionID: info.SessionID, Metadata: md,
	}))
}
