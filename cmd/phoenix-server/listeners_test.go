package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phoenixsec/phoenix/internal/ca"
	"github.com/phoenixsec/phoenix/internal/config"
)

type listenerLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *listenerLog) printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}
func (l *listenerLog) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func testAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func testCertificates(t *testing.T) (*ca.CA, config.HTTPSListenerConfig, *tls.Config) {
	t.Helper()
	authority, err := ca.GenerateCA("listener-test")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := authority.IssueServerCert([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := config.HTTPSListenerConfig{Enabled: true, Listen: testAddress(t), Cert: filepath.Join(dir, "server.crt"), Key: filepath.Join(dir, "server.key")}
	if err := bundle.Save(cfg.Cert, cfg.Key, filepath.Join(dir, "ca.crt")); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(authority.CertPEM()) {
		t.Fatal("invalid CA")
	}
	return authority, cfg, &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
}

func testClient(t *testing.T, tlsCfg *tls.Config) *http.Client {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: tlsCfg, DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 2 * time.Second}
}

func startTestListeners(t *testing.T, cfg *config.Config, handler http.Handler, tlsCfg *tls.Config, client *http.Client) (*listenerLog, func()) {
	t.Helper()
	primary := &http.Server{Addr: cfg.Server.Listen, Handler: handler, TLSConfig: tlsCfg, ReadHeaderTimeout: time.Second}
	logs := &listenerLog{}
	done := make(chan error, 1)
	go func() { done <- serveListeners(primary, cfg, logs.printf) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = primary.Close()
			select {
			case err := <-done:
				if !errors.Is(err, http.ErrServerClosed) {
					t.Errorf("primary serve: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("listeners did not exit")
			}
		})
	}
	t.Cleanup(stop)
	scheme := "http"
	if cfg.TLSEnabled() {
		scheme = "https"
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get(scheme + "://" + cfg.Server.Listen)
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("primary not ready: %v; %s", err, logs.text())
		}
		time.Sleep(10 * time.Millisecond)
	}
	return logs, stop
}

func TestOptionalHTTPSSharedHandlerAndTLSVerification(t *testing.T) {
	_, optional, trust := testCertificates(t)
	cfg := config.DefaultConfig()
	cfg.Server.Listen = testAddress(t)
	cfg.HTTPSListener = optional
	var requests atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		fmt.Fprintf(w, "%s tls=%t", host, r.TLS != nil)
	})
	client := testClient(t, trust)
	logs, stop := startTestListeners(t, cfg, handler, nil, client)
	if !strings.Contains(logs.text(), "Optional HTTPS listener serving") {
		t.Fatal(logs.text())
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		for _, encrypted := range []bool{false, true} {
			wg.Add(1)
			go func(encrypted bool) {
				defer wg.Done()
				url := "http://" + cfg.Server.Listen
				if encrypted {
					url = "https://" + optional.Listen
				}
				resp, err := client.Get(url)
				if err != nil {
					t.Error(err)
					return
				}
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				if err != nil || string(body) != fmt.Sprintf("127.0.0.1 tls=%t", encrypted) {
					t.Errorf("response: %q, %v", body, err)
				}
			}(encrypted)
		}
	}
	wg.Wait()
	if requests.Load() != 41 {
		t.Fatalf("shared requests = %d", requests.Load())
	}
	for _, tc := range []struct {
		name   string
		change func(*tls.Config)
	}{
		{"untrusted", func(c *tls.Config) { c.RootCAs = x509.NewCertPool() }},
		{"wrong hostname", func(c *tls.Config) { c.ServerName = "wrong.invalid" }},
		{"expired", func(c *tls.Config) { c.Time = func() time.Time { return time.Now().AddDate(100, 0, 0) } }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := trust.Clone()
			tc.change(bad)
			resp, err := testClient(t, bad).Get("https://" + optional.Listen)
			if err == nil {
				resp.Body.Close()
				t.Fatal("TLS verification unexpectedly succeeded")
			}
		})
	}
	resp, err := client.Get("http://" + optional.Listen)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("plaintext accepted: %d", resp.StatusCode)
		}
	}
	stop()
	for _, addr := range []string{cfg.Server.Listen, optional.Listen} {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatalf("socket not released: %v", err)
		}
		l.Close()
	}
	if strings.Contains(logs.text(), "stopped:") {
		t.Fatal("intentional closure logged as failure: " + logs.text())
	}
}

func TestOptionalHTTPSSetupFailurePreservesPrimary(t *testing.T) {
	_, optional, trust := testCertificates(t)
	_, other, _ := testCertificates(t)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	for _, tc := range []struct {
		name   string
		change func(*config.Config)
		want   string
	}{
		{"disabled", func(c *config.Config) { c.HTTPSListener.Enabled = false; c.HTTPSListener.Cert = "missing" }, ""},
		{"missing certificate", func(c *config.Config) { c.HTTPSListener.Cert = "missing" }, "loading certificate"},
		{"mismatched certificate", func(c *config.Config) { c.HTTPSListener.Key = other.Key }, "loading certificate"},
		{"empty address", func(c *config.Config) { c.HTTPSListener.Listen = "" }, "https_listener.listen is required"},
		{"bad address", func(c *config.Config) { c.HTTPSListener.Listen = "bad-address" }, "binding"},
		{"occupied", func(c *config.Config) { c.HTTPSListener.Listen = occupied.Addr().String() }, "binding"},
		{"primary overlap", func(c *config.Config) { c.HTTPSListener.Listen = c.Server.Listen }, "binding"},
		// Attempting a wildcard bind while loopback already owns this port
		// fails before any non-loopback socket can be opened.
		{"wildcard overlap", func(c *config.Config) {
			_, port, _ := net.SplitHostPort(c.Server.Listen)
			c.HTTPSListener.Listen = "0.0.0.0:" + port
		}, "binding"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.Server.Listen = testAddress(t)
			cfg.HTTPSListener = optional
			tc.change(cfg)
			logs, _ := startTestListeners(t, cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }), nil, testClient(t, trust))
			if tc.want == "" {
				if logs.text() != "" {
					t.Fatal(logs.text())
				}
			} else if !strings.Contains(logs.text(), tc.want) || !strings.Contains(logs.text(), "primary endpoint continues") {
				t.Fatal(logs.text())
			}
			if cfg.HTTPSListener.Listen == optional.Listen {
				conn, err := net.DialTimeout("tcp", optional.Listen, 100*time.Millisecond)
				if err == nil {
					conn.Close()
					t.Fatal("failed/disabled optional endpoint left a socket open")
				}
			}
		})
	}
}

func TestOptionalHTTPSInheritsMTLSAndRevocation(t *testing.T) {
	for _, required := range []bool{false, true} {
		t.Run(fmt.Sprintf("required=%t", required), func(t *testing.T) {
			authority, optional, trust := testCertificates(t)
			bundle, err := authority.IssueAgentCert("test-agent")
			if err != nil {
				t.Fatal(err)
			}
			cert, err := tls.X509KeyPair(bundle.CertPEM, bundle.KeyPEM)
			if err != nil {
				t.Fatal(err)
			}
			trust.Certificates = []tls.Certificate{cert}
			serverTLS := authority.TLSConfig()
			if required {
				serverTLS.ClientAuth = tls.RequireAndVerifyClientCert
			}
			cfg := config.DefaultConfig()
			cfg.Server.Listen = testAddress(t)
			cfg.HTTPSListener = optional
			cfg.Auth.MTLS.Enabled = true
			cfg.Auth.MTLS.ServerCert = optional.Cert
			cfg.Auth.MTLS.ServerKey = optional.Key
			client := testClient(t, trust)
			startTestListeners(t, cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }), serverTLS, client)
			for _, addr := range []string{cfg.Server.Listen, optional.Listen} {
				resp, err := client.Get("https://" + addr)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				noCert := trust.Clone()
				noCert.Certificates = nil
				resp, err = testClient(t, noCert).Get("https://" + addr)
				if resp != nil {
					resp.Body.Close()
				}
				if (err != nil) != required {
					t.Fatalf("no client cert: required=%t err=%v", required, err)
				}
			}
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			if err := authority.RevokeCert(leaf.SerialNumber, "test-agent"); err != nil {
				t.Fatal(err)
			}
			for _, addr := range []string{cfg.Server.Listen, optional.Listen} {
				resp, err := client.Get("https://" + addr)
				if err == nil {
					resp.Body.Close()
					t.Fatal("revoked client certificate accepted")
				}
			}
		})
	}
}

type failedListener struct{ net.Listener }

func (l failedListener) Accept() (net.Conn, error) { return nil, errors.New("forced accept failure") }

func TestOptionalHTTPSServeFailureReported(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Listen = testAddress(t)
	client := testClient(t, nil)
	startTestListeners(t, cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), nil, client)
	_, optional, _ := testCertificates(t)
	cert, err := tls.LoadX509KeyPair(optional.Cert, optional.Key)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	logs := &listenerLog{}
	serveOptionalHTTPS(&http.Server{Addr: l.Addr().String(), TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}}, failedListener{l}, logs.printf)
	if !strings.Contains(logs.text(), "forced accept failure") || !strings.Contains(logs.text(), "primary endpoint continues") {
		t.Fatal(logs.text())
	}
	// ServeTLS owns and closes the listener even on an accept failure.
	l2, err := net.Listen("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	l2.Close()
	resp, err := client.Get("http://" + cfg.Server.Listen)
	if err != nil {
		t.Fatalf("primary unavailable after optional serve failure: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("primary status after optional serve failure: %d", resp.StatusCode)
	}
}

func TestPrimaryBindFailureDoesNotStartOptionalHTTPS(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	_, optional, _ := testCertificates(t)
	cfg := config.DefaultConfig()
	cfg.HTTPSListener = optional
	logs := &listenerLog{}
	if err := serveListeners(&http.Server{Addr: occupied.Addr().String()}, cfg, logs.printf); err == nil {
		t.Fatal("primary bind failure must be returned")
	}
	if logs.text() != "" {
		t.Fatalf("optional setup attempted after primary failure: %s", logs.text())
	}
	l, err := net.Listen("tcp", optional.Listen)
	if err != nil {
		t.Fatalf("optional port unexpectedly occupied: %v", err)
	}
	l.Close()
}
