package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/phoenixsec/phoenix/internal/config"
)

// serveListeners reserves the primary socket first, so an overlapping optional
// address cannot take it. Only primary failures are returned to the caller.
func serveListeners(primary *http.Server, cfg *config.Config, logf func(string, ...any)) error {
	listener, err := net.Listen("tcp", primary.Addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	if cfg.HTTPSListener.Enabled {
		closeHTTPS, err := startHTTPSListener(primary, cfg.HTTPSListener, logf)
		if err != nil {
			logf("Optional HTTPS listener %q unavailable: %v; primary endpoint continues", cfg.HTTPSListener.Listen, err)
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

func startHTTPSListener(primary *http.Server, cfg config.HTTPSListenerConfig, logf func(string, ...any)) (func(), error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("loading certificate: %w", err)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if primary.TLSConfig != nil {
		// Preserve client certificate verification, including the CA's CRL
		// callback. This endpoint must not bypass global mTLS requirements.
		tlsCfg = primary.TLSConfig.Clone()
	}
	tlsCfg.Certificates = []tls.Certificate{cert}
	server := &http.Server{
		Addr: cfg.Listen, Handler: primary.Handler, TLSConfig: tlsCfg,
		ReadHeaderTimeout: primary.ReadHeaderTimeout,
		ReadTimeout:       primary.ReadTimeout,
		WriteTimeout:      primary.WriteTimeout,
		IdleTimeout:       primary.IdleTimeout,
	}
	listener, err := net.Listen("tcp", cfg.Listen)
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

func serveOptionalHTTPS(server *http.Server, listener net.Listener, logf func(string, ...any)) {
	if err := server.ServeTLS(listener, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logf("Optional HTTPS listener %q stopped: %v; primary endpoint continues", server.Addr, err)
	}
}
