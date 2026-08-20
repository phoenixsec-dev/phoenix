package transport

import (
	"strings"
	"testing"
)

func TestIsLoopbackListen(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:9090", true},
		{"127.0.0.2:9090", true}, // whole 127/8 block is loopback
		{"localhost:9090", true},
		{"LOCALHOST:9090", true},
		{"[::1]:9090", true},
		{"0.0.0.0:9090", false},
		{"[::]:9090", false},
		{":9090", false}, // empty host binds all interfaces
		{"192.168.1.10:9090", false},
		{"10.0.0.5:80", false},
		{"phoenix.internal:9090", false}, // hostnames are not resolved: warn
		{"phoenix.internal", false},      // no port: judged as host
		{"127.0.0.1", true},              // no port: judged as host
		{"", false},
	}
	for _, tt := range tests {
		if got := IsLoopbackListen(tt.addr); got != tt.want {
			t.Errorf("IsLoopbackListen(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestIsPlaintextNonLoopbackURL(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"http://127.0.0.1:9090", false},
		{"http://localhost:9090", false},
		{"http://[::1]:9090", false},
		{"http://192.168.1.10:9090", true},
		{"http://0.0.0.0:9090", true},
		{"http://phoenix.internal:9090", true},
		{"HTTP://192.168.1.10:9090", true},
		{"https://192.168.1.10:9090", false}, // encrypted: no warning
		{"https://phoenix.internal:9090", false},
		{"", false},
		{"not a url", false},
	}
	for _, tt := range tests {
		if got := IsPlaintextNonLoopbackURL(tt.url); got != tt.want {
			t.Errorf("IsPlaintextNonLoopbackURL(%q) = %v, want %v", tt.url, got, tt.want)
		}
	}
}

func TestServerPlaintextWarning(t *testing.T) {
	w := ServerPlaintextWarning("0.0.0.0:9090", false)
	for _, want := range []string{
		"INSECURE TRANSPORT",
		`"0.0.0.0:9090"`,
		"bearer tokens",
		"secret value",
		`"tls": { "enabled": true }`,
		"--reissue-cert",
	} {
		if !strings.Contains(w, want) {
			t.Errorf("server warning missing %q:\n%s", want, w)
		}
	}
	if strings.Contains(w, "dashboard") {
		t.Errorf("dashboard line present when dashboard disabled:\n%s", w)
	}

	wd := ServerPlaintextWarning("0.0.0.0:9090", true)
	if !strings.Contains(wd, "dashboard passwords and session cookies") {
		t.Errorf("dashboard warning line missing:\n%s", wd)
	}
}

func TestMCPPlaintextWarning(t *testing.T) {
	w := MCPPlaintextWarning("0.0.0.0:8080")
	for _, want := range []string{"INSECURE TRANSPORT", `"0.0.0.0:8080"`, "MCP bearer token", "--tls-cert"} {
		if !strings.Contains(w, want) {
			t.Errorf("MCP warning missing %q:\n%s", want, w)
		}
	}
}

func TestClientPlaintextWarning(t *testing.T) {
	if w := ClientPlaintextWarning("http://127.0.0.1:9090"); w != "" {
		t.Errorf("loopback URL should not warn, got:\n%s", w)
	}
	if w := ClientPlaintextWarning("https://192.168.1.10:9090"); w != "" {
		t.Errorf("https URL should not warn, got:\n%s", w)
	}
	w := ClientPlaintextWarning("http://192.168.1.10:9090")
	for _, want := range []string{"WARNING", "http://192.168.1.10:9090", "unencrypted", "PHOENIX_CA_CERT"} {
		if !strings.Contains(w, want) {
			t.Errorf("client warning missing %q:\n%s", want, w)
		}
	}
}
