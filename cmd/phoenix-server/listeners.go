package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/phoenixsec/phoenix/internal/config"
)

// newHTTPServer builds every Phoenix HTTP server, primary and optional, so
// timeouts and other settings cannot drift between the two endpoints.
func newHTTPServer(addr string, handler http.Handler, tlsCfg *tls.Config) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// httpsListener is an enabled https_listener block whose certificate has
// already been loaded. A nil *httpsListener means the feature is off.
type httpsListener struct {
	addr string
	cert tls.Certificate
}

// loadHTTPSListener runs at startup, after Config.Validate. It returns nil when
// the block is disabled. A certificate that cannot be loaded is a static
// misconfiguration, so main treats the returned error as fatal.
func loadHTTPSListener(cfg config.HTTPSListenerConfig) (*httpsListener, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("https_listener: loading certificate: %w", err)
	}
	return &httpsListener{addr: cfg.Listen, cert: cert}, nil
}

// serveListeners reserves the primary socket first, so an overlapping optional
// address cannot take it, then starts the optional HTTPS endpoint (if any) and
// serves the primary until it stops. Only primary failures are returned;
// optional bind and serve failures are logged and the primary keeps running.
func serveListeners(primary *http.Server, cfg *config.Config, optional *httpsListener, logf func(string, ...any)) error {
	listener, err := net.Listen("tcp", primary.Addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	if optional != nil {
		closeHTTPS, err := startHTTPSListener(primary, optional, logf)
		if err != nil {
			logf("Optional HTTPS listener %q unavailable: %v; primary endpoint continues", optional.addr, err)
		} else {
			defer closeHTTPS()
		}
	}
	if cfg.TLSEnabled() {
		cert, key := cfg.TLSCertKey()
		return primary.ServeTLS(listener, cert, key)
	}
	return primary.Serve(listener)
}

// startHTTPSListener binds the optional HTTPS address and serves the primary's
// handler on it in the background, reusing the primary's mTLS/CRL settings.
// It returns a stop function that shuts the endpoint down and waits for it, or
// a bind error that the caller logs while the primary continues.
func startHTTPSListener(primary *http.Server, optional *httpsListener, logf func(string, ...any)) (func(), error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if primary.TLSConfig != nil {
		// Preserve client certificate verification, including the CA's CRL
		// callback. This endpoint must not bypass global mTLS requirements.
		tlsCfg = primary.TLSConfig.Clone()
	}
	tlsCfg.Certificates = []tls.Certificate{optional.cert}
	server := newHTTPServer(optional.addr, primary.Handler, tlsCfg)
	listener, err := net.Listen("tcp", optional.addr)
	if err != nil {
		return nil, fmt.Errorf("binding: %w", err)
	}
	logf("Optional HTTPS listener serving on %s", listener.Addr())
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveOptionalHTTPS(server, listener, logf)
	}()
	return func() {
		_ = server.Close()
		// Also close the socket if Close raced with ServeTLS starting.
		_ = listener.Close()
		<-done
	}, nil
}

// serveOptionalHTTPS runs the optional endpoint until it is closed. A runtime
// failure (for example, accept errors) is logged, never returned, so it cannot
// take the primary endpoint down with it.
func serveOptionalHTTPS(server *http.Server, listener net.Listener, logf func(string, ...any)) {
	if err := server.ServeTLS(listener, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logf("Optional HTTPS listener %q stopped: %v; primary endpoint continues", server.Addr, err)
	}
}
