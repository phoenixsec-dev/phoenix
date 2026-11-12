package api

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/grant"
	"github.com/phoenixsec/phoenix/internal/sshca"
)

// SSH certificates: temporary login to a machine, approved like any grant.
//
// An agent files an access request with action "ssh_login" for the path
// "ssh/<machine>". Once a human approves, the agent sends a public key to
// POST /v1/ssh/sign and gets back a certificate that stops working when the
// grant ends. The machine also asks GET /v1/ssh/window at every login and while
// a session is open, so a revoke beats a certificate that is still in date.
//
// The grant is the only thing that counts. The agent's ACL is ignored, so a "*"
// rule can read every secret and still cannot log in to anything. Keying this on
// the action, not the path, keeps it apart from any secret stored under "ssh/".

const sshPathPrefix = "ssh/"

// SetSSHCA installs the signing key and machine list. Without it the sign
// endpoint answers 404 and "ssh/" paths cannot be requested.
func (s *Server) SetSSHCA(ca ssh.Signer, hosts map[string]config.SSHHost) {
	s.sshCA = ca
	s.sshHosts = hosts
}

func (s *Server) sshRoutes() {
	s.mux.HandleFunc("POST /v1/ssh/sign", s.handleSSHSign)
	s.mux.HandleFunc("GET /v1/ssh/ca", s.handleSSHCA)
	s.mux.HandleFunc("GET /v1/ssh/window/{host}/{grant}", s.handleSSHWindow)
}

// sshRequestAllowed checks a login request: one configured machine per request,
// so one approval can never carry a second machine or a secret along with it.
func (s *Server) sshRequestAllowed(paths []string) bool {
	if s.sshCA == nil || len(paths) != 1 {
		return false
	}
	name, ok := strings.CutPrefix(paths[0], sshPathPrefix)
	if !ok {
		return false
	}
	_, known := s.sshHosts[name]
	return known
}

// sshHostFromRequest answers 404 unless host is a configured machine.
func (s *Server) sshHostFromRequest(w http.ResponseWriter, name string) (config.SSHHost, bool) {
	if s.sshCA != nil {
		if h, ok := s.sshHosts[name]; ok {
			return h, true
		}
	}
	writeAccessError(w, CodeNotFound, "no such SSH host on this server", http.StatusNotFound)
	return config.SSHHost{}, false
}

type sshSignBody struct {
	Host      string `json:"host"`
	PublicKey string `json:"public_key"`
}

// handleSSHSign signs the caller's public key for one machine: POST /v1/ssh/sign.
// It needs an active grant on ssh/<host> for this exact agent, credential and
// IP. The certificate ends with the grant and only works from the caller's IP.
func (s *Server) handleSSHSign(w http.ResponseWriter, r *http.Request) {
	info, ok := s.accessAuth(w, r, false)
	if !ok {
		return
	}
	var body sshSignBody
	if !decodeBody(w, r, &body, false) {
		return
	}
	host, ok := s.sshHostFromRequest(w, body.Host)
	if !ok {
		return
	}
	if !s.grantsOn() {
		writeAccessError(w, CodeRequestsDisabled, "access requests are turned off on this server", http.StatusNotImplemented)
		return
	}
	ip := clientIP(r)
	path := sshPathPrefix + body.Host
	m := s.grants.Match(s.grantCaller(info, ip), path, grant.ActionSSHLogin)
	if m.Grant == nil {
		s.denySSHSign(w, r, info, path, ip, m.Reason)
		return
	}
	cert, err := sshca.Sign(s.sshCA, sshca.CertRequest{
		PublicKey: body.PublicKey,
		Principal: body.Host,
		// The machine reads the grant back out of this, so it comes first and
		// nothing an agent name contains can be mistaken for it.
		KeyID:       fmt.Sprintf("grant=%s,agent=%s,host=%s", m.Grant.ID, info.Agent, body.Host),
		SourceIP:    ip,
		Now:         s.now(),
		ValidBefore: m.Grant.ExpiresAt,
	})
	if err != nil {
		writeAccessError(w, CodeInvalidRequest, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditAllowedAccess(r, info, "ssh.sign", path, ip, false, m.Grant)
	jsonOK(w, map[string]any{
		"certificate": cert,
		"address":     host.Address,
		"user":        host.User,
		"expires_at":  fmtTime(m.Grant.ExpiresAt),
		"grant_id":    m.Grant.ID,
	})
}

// denySSHSign answers a sign attempt with no active grant. A revoked grant is
// final until a person says otherwise, so only the other cases invite a request.
func (s *Server) denySSHSign(w http.ResponseWriter, r *http.Request, info *authInfo, path, ip, reason string) {
	code, step, detail := CodeSSHGrantRequired, NextRequestUse, "logging in to this machine needs a human's approval"
	switch reason {
	case grant.ReasonGrantExpired:
		code, detail = CodeGrantExpired, "your temporary access to this machine has ended"
	case grant.ReasonGrantRevoked:
		code, step, detail = CodeGrantRevoked, NextAskUser, "a human revoked your access to this machine"
	default:
		reason = "ssh_grant_required"
	}
	s.auditDeniedMetadata(info, "ssh.sign", path, ip, reason, callerAuditMetadata(r))
	jsonDeniedStep(w, "access_denied", code, detail, "", step, http.StatusForbidden)
}

// handleSSHCA returns the CA's public key: GET /v1/ssh/ca. It is public by
// nature and needs no login, so a machine's bootstrap can fetch it.
func (s *Server) handleSSHCA(w http.ResponseWriter, r *http.Request) {
	if s.sshCA == nil {
		writeAccessError(w, CodeNotFound, "SSH certificates are not enabled on this server", http.StatusNotFound)
		return
	}
	jsonOK(w, map[string]any{"public_key": sshca.PublicKey(s.sshCA)})
}

// handleSSHWindow says whether one approval still stands for one machine:
// GET /v1/ssh/window/{host}/{grant}. Machines ask this at every login and on a
// timer for each open session, which is what makes a revoke take effect on a
// certificate that has not expired yet.
//
// Anything that is not a yes is a no, including a machine or feature that has
// been switched off, so turning this off also ends the sessions it allowed. It
// needs no login because a machine holds no Phoenix credential, and it tells the
// caller only yes or no about a random id it must already know. It is not audited:
// it would only fill the log.
func (s *Server) handleSSHWindow(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	path := sshPathPrefix + r.PathValue("host")
	open := false
	if s.grantsOn() && s.sshRequestAllowed([]string{path}) && !s.grants.Health().Degraded {
		g, ok := s.grants.GetGrant(r.PathValue("grant"))
		open = ok && g.Action == grant.ActionSSHLogin && slices.Contains(g.Paths, path) && g.State(s.now()) == grant.GrantActive
	}
	jsonOK(w, map[string]any{"open": open})
}
