package api

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/grant"
	"github.com/phoenixsec/phoenix/internal/ref"
)

// Notify hook for access requests (plan section 12, "Notification leaks"
// in section 11).
//
// When access_requests.notify_url is set, every newly created request (201,
// not a duplicate) triggers one POST in the background: 5 second timeout,
// no retries, no redirects. A failure is logged and never affects the
// request. The message is shaped for ntfy (plain-text body plus Title,
// Tags and Click headers) and works as a plain webhook too.
//
// What is sent: agent name, action, number of paths, request id and, when
// notify_dashboard_url is set, a link to /dashboard/approvals#<req_id>.
// Paths only when notify_include_paths is true. The agent's reason is never
// sent, and there are no approve links or tokens. notify_token_ref is
// resolved from the store at send time and sent as "Authorization: Bearer";
// it is never logged.

// defaultNotifyTimeout is the whole-request limit for one notification.
const defaultNotifyTimeout = 5 * time.Second

// notifyClient never follows redirects: a redirect could carry the
// Authorization header somewhere the operator did not configure.
func notifyClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// notifyAccessRequest starts the notification for a new request in the
// background. cfg is the settings snapshot the request was created under.
func (s *Server) notifyAccessRequest(cfg config.AccessRequestsSettings, rq grant.Request) {
	if cfg.NotifyURL == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), s.notifyTimeout)
		defer cancel()
		if err := s.sendAccessNotify(ctx, cfg, rq); err != nil {
			log.Printf("access requests: notify for %s failed: %v", rq.ID, err)
		}
	}()
}

// sendAccessNotify does the one POST. Errors never include the token.
func (s *Server) sendAccessNotify(ctx context.Context, cfg config.AccessRequestsSettings, rq grant.Request) error {
	link := notifyDashboardLink(cfg.NotifyDashboardURL, rq.ID)
	body := notifyMessage(cfg, rq, link)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.NotifyURL, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("Title", "Phoenix: access request")
	req.Header.Set("Tags", "key")
	if link != "" {
		req.Header.Set("Click", link)
	}
	if cfg.NotifyTokenRef != "" {
		token, err := s.resolveNotifyToken(cfg.NotifyTokenRef)
		if err != nil {
			// Do not send without the token: an unauthenticated post
			// could land on a public topic.
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := notifyClient(s.notifyTimeout).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("notify_url answered HTTP %d", resp.StatusCode)
	}
	return nil
}

// resolveNotifyToken reads notify_token_ref from the server's own store.
// The error names the ref, never the value.
func (s *Server) resolveNotifyToken(tokenRef string) (string, error) {
	path, err := ref.Parse(tokenRef)
	if err != nil {
		return "", fmt.Errorf("notify_token_ref is not a valid reference")
	}
	secret, err := s.backend.Get(path)
	if err != nil {
		return "", fmt.Errorf("resolving notify_token_ref %s: %w", tokenRef, err)
	}
	token := strings.TrimSpace(secret.Value)
	if token == "" || strings.ContainsAny(token, "\r\n") {
		return "", fmt.Errorf("notify_token_ref %s holds an empty or multi-line value", tokenRef)
	}
	return token, nil
}

// notifyDashboardLink is <notify_dashboard_url>/dashboard/approvals#<id>,
// or "" when no external dashboard URL is configured. The link is never
// built from a request's Host header, which the caller controls.
func notifyDashboardLink(base, id string) string {
	if base == "" {
		return ""
	}
	return strings.TrimRight(base, "/") + "/dashboard/approvals#" + id
}

// notifyMessage is the plain-text body. It never contains the reason.
func notifyMessage(cfg config.AccessRequestsSettings, rq grant.Request, link string) string {
	noun := "secrets"
	if len(rq.Paths) == 1 {
		noun = "secret"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s asks for %s on %d %s.\n", rq.Agent, rq.Action, len(rq.Paths), noun)
	if cfg.NotifyIncludePaths {
		for _, p := range rq.Paths {
			fmt.Fprintf(&b, "- %s\n", p)
		}
	}
	fmt.Fprintf(&b, "Request %s: approve or deny it in the Phoenix dashboard.\n", rq.ID)
	if link != "" {
		b.WriteString(link + "\n")
	}
	return b.String()
}
