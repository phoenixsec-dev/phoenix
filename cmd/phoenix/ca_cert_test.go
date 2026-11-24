package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A CA certificate that cannot be used must not quietly become "trust any
// public CA": over https the request fails and says why. Plain http, where it
// is not used, keeps working.
func TestUnusableCACertRefusesHTTPS(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.crt")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	ok := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	plain, tls := httptest.NewServer(ok), httptest.NewTLSServer(ok)
	defer plain.Close()
	defer tls.Close()
	for name, path := range map[string]string{"missing": bad + ".missing", "invalid": bad} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("PHOENIX_CA_CERT", path)
			c := buildHTTPClient()
			if c == http.DefaultClient {
				t.Error("fell back to the default client")
			}
			if resp, err := c.Get(plain.URL); err != nil {
				t.Errorf("http: %v", err)
			} else {
				resp.Body.Close()
			}
			if _, err := c.Get(tls.URL); err == nil || !strings.Contains(err.Error(), "PHOENIX_CA_CERT") {
				t.Errorf("https: %v, want an error naming PHOENIX_CA_CERT", err)
			}
		})
	}
}
