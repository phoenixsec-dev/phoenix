package api

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/grant"
)

// notifyHit is one POST the fake ntfy server received.
type notifyHit struct {
	header http.Header
	body   string
}

// fakeNtfy starts an httptest server that records each POST and answers
// with status. No real network is used.
func fakeNtfy(t *testing.T, status int) (*httptest.Server, chan notifyHit) {
	t.Helper()
	hits := make(chan notifyHit, 10)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		hits <- notifyHit{header: r.Header.Clone(), body: string(b)}
		w.WriteHeader(status)
	}))
	t.Cleanup(ts.Close)
	return ts, hits
}

func waitHit(t *testing.T, hits chan notifyHit) notifyHit {
	t.Helper()
	select {
	case h := <-hits:
		return h
	case <-time.After(5 * time.Second):
		t.Fatal("no notification arrived")
	}
	return notifyHit{}
}

func expectNoHit(t *testing.T, hits chan notifyHit) {
	t.Helper()
	select {
	case h := <-hits:
		t.Fatalf("unexpected notification: %q", h.body)
	case <-time.After(300 * time.Millisecond):
	}
}

// syncBuf collects log output written from the notify goroutine.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func captureLog(t *testing.T) *syncBuf {
	t.Helper()
	buf := &syncBuf{}
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return buf
}

// waitLog polls buf until it contains want.
func waitLog(t *testing.T, buf *syncBuf, want string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s := buf.String(); strings.Contains(s, want) {
			return s
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("log never contained %q; got:\n%s", want, buf.String())
	return ""
}

// Default payload: agent, action, path count, request id and dashboard
// link. Never the paths (unless opted in) and never the reason. Duplicates
// of a pending request do not notify again.
func TestNotifyDefaultPayload(t *testing.T) {
	e := newGrantEnv(t)
	ts, hits := fakeNtfy(t, http.StatusOK)
	e.set(func(s *config.AccessRequestsSettings) {
		s.NotifyURL = ts.URL + "/phoenix"
		s.NotifyDashboardURL = "https://phoenix.example.net/"
	})

	id := e.request(t, vectorTok, "infra/b2/app-key", "infra/other")
	h := waitHit(t, hits)
	link := "https://phoenix.example.net/dashboard/approvals#" + id
	for _, want := range []string{"vector", "read_value", "2 secrets", id, link} {
		if !strings.Contains(h.body, want) {
			t.Errorf("body missing %q:\n%s", want, h.body)
		}
	}
	for _, leak := range []string{"infra/b2/app-key", "infra/other", "backup job"} {
		if strings.Contains(h.body, leak) || strings.Contains(strings.Join(headerValues(h.header), "\n"), leak) {
			t.Errorf("notification leaks %q:\n%s", leak, h.body)
		}
	}
	if got := h.header.Get("Click"); got != link {
		t.Errorf("Click = %q, want %q", got, link)
	}
	if h.header.Get("Title") == "" || h.header.Get("Tags") == "" {
		t.Errorf("missing ntfy Title/Tags headers: %v", h.header)
	}
	if a := h.header.Get("Authorization"); a != "" {
		t.Errorf("Authorization sent without notify_token_ref: %q", a)
	}

	// Identical request while pending: 200, no second notification.
	b := `{"paths":["infra/b2/app-key","infra/other"],"action":"read_value","reason":"backup job fails auth","ttl":"30m"}`
	expect(t, e.do("POST", "/v1/access-requests", vectorTok, b), http.StatusOK, "")
	expectNoHit(t, hits)
}

func headerValues(h http.Header) []string {
	var out []string
	for _, v := range h {
		out = append(out, v...)
	}
	return out
}

func TestNotifyIncludePathsOptIn(t *testing.T) {
	e := newGrantEnv(t)
	ts, hits := fakeNtfy(t, http.StatusOK)
	e.set(func(s *config.AccessRequestsSettings) {
		s.NotifyURL = ts.URL
		s.NotifyIncludePaths = true
	})
	e.request(t, vectorTok, "infra/b2/app-key")
	h := waitHit(t, hits)
	if !strings.Contains(h.body, "infra/b2/app-key") || !strings.Contains(h.body, "1 secret.") {
		t.Errorf("opted-in body should list the path:\n%s", h.body)
	}
	if strings.Contains(h.body, "backup job") {
		t.Errorf("reason must never be sent:\n%s", h.body)
	}
	if h.header.Get("Click") != "" {
		t.Errorf("no notify_dashboard_url, but Click = %q", h.header.Get("Click"))
	}
}

// notify_token_ref is read from the store at send time (a rotated token is
// used for the next message) and sent as a bearer token. It never reaches
// the log, and a ref that does not resolve sends nothing.
func TestNotifyTokenResolvedAtSendTime(t *testing.T) {
	e := newGrantEnv(t)
	ts, hits := fakeNtfy(t, http.StatusOK)
	seedSecret(t, e.srv, adminTok, "phoenix/ntfy-token", "tk_first")
	e.set(func(s *config.AccessRequestsSettings) {
		s.NotifyURL = ts.URL
		s.NotifyTokenRef = "phoenix://phoenix/ntfy-token"
	})

	e.request(t, vectorTok, "infra/b2/app-key")
	if got := waitHit(t, hits).header.Get("Authorization"); got != "Bearer tk_first" {
		t.Fatalf("Authorization = %q, want Bearer tk_first", got)
	}
	seedSecret(t, e.srv, adminTok, "phoenix/ntfy-token", "tk_second")
	e.request(t, vectorTok, "infra/other")
	if got := waitHit(t, hits).header.Get("Authorization"); got != "Bearer tk_second" {
		t.Fatalf("Authorization = %q, want Bearer tk_second (resolved at send time)", got)
	}

	logs := captureLog(t)
	e.set(func(s *config.AccessRequestsSettings) { s.NotifyTokenRef = "phoenix://phoenix/missing" })
	e.request(t, vectorTok, "infra/third")
	waitLog(t, logs, "notify_token_ref phoenix://phoenix/missing")
	expectNoHit(t, hits)
	if strings.Contains(logs.String(), "tk_") {
		t.Fatalf("token value in log:\n%s", logs.String())
	}
}

// A failing or hanging notify_url never blocks or fails the request.
func TestNotifyFailureDoesNotBlockRequest(t *testing.T) {
	t.Run("server error", func(t *testing.T) {
		e := newGrantEnv(t)
		ts, hits := fakeNtfy(t, http.StatusInternalServerError)
		seedSecret(t, e.srv, adminTok, "phoenix/ntfy-token", "tk_secret")
		e.set(func(s *config.AccessRequestsSettings) {
			s.NotifyURL = ts.URL
			s.NotifyTokenRef = "phoenix://phoenix/ntfy-token"
		})
		logs := captureLog(t)
		e.request(t, vectorTok, "infra/b2/app-key") // 201 checked by the helper
		waitHit(t, hits)
		out := waitLog(t, logs, "HTTP 500")
		if strings.Contains(out, "tk_secret") {
			t.Fatalf("token value in log:\n%s", out)
		}
	})

	// The handler hangs until the test ends. The notify timeout is a
	// minute, so a create that waited for it would take a minute.
	t.Run("hang", func(t *testing.T) {
		e := newGrantEnv(t)
		release, entered := make(chan struct{}), make(chan struct{}, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			entered <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}))
		t.Cleanup(ts.Close)
		t.Cleanup(func() { close(release) }) // runs before ts.Close
		e.srv.notifyTimeout = time.Minute
		e.set(func(s *config.AccessRequestsSettings) { s.NotifyURL = ts.URL })

		start := time.Now()
		e.request(t, vectorTok, "infra/b2/app-key") // 201 checked by the helper
		if d := time.Since(start); d > 30*time.Second {
			t.Fatalf("create took %v; the notification must not block it", d)
		}
		select { // the POST really is hanging while the request already succeeded
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("notification never reached the hanging server")
		}
	})

	// One send gives up at the timeout (no retries).
	t.Run("timeout", func(t *testing.T) {
		e := newGrantEnv(t)
		release := make(chan struct{})
		var calls int
		var mu sync.Mutex
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			calls++
			mu.Unlock()
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}))
		t.Cleanup(ts.Close)
		t.Cleanup(func() { close(release) })
		e.srv.notifyTimeout = 200 * time.Millisecond
		cfg := e.settings
		cfg.NotifyURL = ts.URL

		start := time.Now()
		err := e.srv.sendAccessNotify(context.Background(), cfg, grant.Request{
			ID: "req_test", Agent: "vector", Action: "read_value", Paths: []string{"infra/b2/app-key"},
		})
		if err == nil || time.Since(start) > 5*time.Second {
			t.Fatalf("send to a hanging server: err=%v after %v, want a timeout error", err, time.Since(start))
		}
		mu.Lock()
		defer mu.Unlock()
		if calls != 1 {
			t.Fatalf("notify_url called %d times, want exactly 1 (no retries)", calls)
		}
	})
}

// P4 review N1: a transport failure (here: nothing listening) is logged
// without the URL. An ntfy topic name works like a password.
func TestNotifyTransportFailureDoesNotLogURL(t *testing.T) {
	e := newGrantEnv(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens there now: connection refused
	e.set(func(s *config.AccessRequestsSettings) { s.NotifyURL = "http://" + addr + "/private-topic-xyz" })
	logs := captureLog(t)
	e.request(t, vectorTok, "infra/b2/app-key")
	out := waitLog(t, logs, "notify for")
	if strings.Contains(out, "private-topic-xyz") || strings.Contains(out, addr) {
		t.Fatalf("notify failure log shows the URL:\n%s", out)
	}
}
