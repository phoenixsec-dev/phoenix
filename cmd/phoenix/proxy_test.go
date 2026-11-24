package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/phoenixsec/phoenix/internal/ca"
)

// With PHOENIX_CA_CERT set, the CLI used to ignore HTTPS_PROXY and dial the
// server directly. Go reads the proxy variables once per process and never
// proxies loopback names, so this runs the client in a child process against
// a name that does not exist; the fake proxy maps it to the test server.
func TestCACertClientUsesProxy(t *testing.T) {
	if os.Getenv("PHOENIX_TEST_PROXY_CHILD") == "1" {
		resp, err := buildHTTPClient().Get("https://phoenix.invalid/v1/health")
		if err != nil {
			t.Fatal(err)
		}
		// Plain http must not go through the proxy: it would see the token.
		if resp, err := buildHTTPClient().Get("http://phoenix.invalid/v1/health"); err == nil {
			resp.Body.Close()
			t.Fatal("a plain http request was answered, so it went through the proxy")
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "through" {
			t.Fatalf("unexpected answer %q", body)
		}
		return
	}

	dir := t.TempDir()
	caPath, certPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	authority, err := ca.GenerateCA("Phoenix test")
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Save(caPath, filepath.Join(dir, "ca.key")); err != nil {
		t.Fatal(err)
	}
	bundle, err := authority.IssueServerCert([]string{"phoenix.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.Save(certPath, keyPath, caPath); err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "through")
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	defer server.Close()

	var connects atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != "phoenix.invalid:443" {
			http.Error(w, "unexpected proxy request", http.StatusBadGateway)
			return // answered, so the child sees a response, not an error
		}
		connects.Add(1)
		upstream, err := net.Dial("tcp", server.Listener.Addr().String())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
		go io.Copy(upstream, buf)
		io.Copy(conn, upstream)
	}))
	defer proxy.Close()

	cmd := exec.Command(os.Args[0], "-test.run=^TestCACertClientUsesProxy$")
	cmd.Env = []string{"PHOENIX_TEST_PROXY_CHILD=1", "PHOENIX_CA_CERT=" + caPath, "HTTPS_PROXY=" + proxy.URL, "HTTP_PROXY=" + proxy.URL}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("client did not get through the proxy: %v\n%s", err, strings.TrimSpace(out.String()))
	}
	if connects.Load() != 1 {
		t.Fatalf("proxy saw %d CONNECTs, want 1", connects.Load())
	}
}
