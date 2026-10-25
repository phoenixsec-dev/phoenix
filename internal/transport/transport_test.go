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

func TestPlaintextAllowed(t *testing.T) {
	tests := []struct {
		url, allow string
		want       bool
	}{
		// Basic named-host matching.
		{"http://192.168.1.10:9090", "192.168.1.10", true},
		{"http://192.168.1.10:9090", " 10.0.0.5 , 192.168.1.10 ", true},
		{"http://192.168.1.10:9090", ", ,192.168.1.10", true},
		{"http://Phoenix.Internal:9090", "phoenix.internal", true},
		{"http://192.168.1.10:8443", "192.168.1.10", true}, // every port on a named host
		{"http://192.168.1.10:9090", "", false},
		{"http://192.168.1.10:9090", "   ", false},
		{"http://192.168.1.10:9090", ",,,", false},
		{"http://192.168.1.10:9090", "192.168.1.11", false},
		{"http://192.168.1.10:9090", "192.168.1.10:9090", false}, // host only, no port
		{"http://192.168.1.10:9090", "192.168.1.1", false},       // no prefix match
		{"http://192.168.1.10:9090", "1", false},                 // not a blanket switch
		{"http://192.168.1.10:9090", "http://192.168.1.10", false},
		{"http://192.168.1.10:9090", "192.168.1.10/", false},
		{"http://192.168.1.10:9090", "::ffff:192.168.1.10", false}, // other spelling warns
		{"not a url %%", "192.168.1.10", false},
		// No wildcards.
		{"http://192.168.1.10:9090", "*", false},
		{"http://a.example.com:9090", "*.example.com", false},
		// IPv6 compares as an address; brackets optional.
		{"http://[fd00::10]:9090", "fd00::10", true},
		{"http://[fd00::10]:9090", "[fd00::10]", true},
		{"http://[fd00::10]:9090", "FD00:0::10", true},
		{"http://[fd00::10]:9090", "fd00::11", false},
		// IPv6 zones are case-sensitive interface names and must match.
		{"http://[fe80::1%25eth0]:9090", "fe80::1%eth0", true},
		{"http://[fe80::1%25ETH0]:9090", "fe80::1%eth0", false},
		{"http://[fe80::1%25eth0]:9090", "fe80::1", false},
		{"http://[fe80::1]:9090", "fe80::1%eth0", false},
		// Non-ASCII names never fold: these are different DNS names.
		{"http://ς.example:9090", "σ.example", false}, // final sigma vs sigma
		{"http://σ.example:9090", "σ.example", true},
		{"http://K.example:9090", "k.example", false}, // Kelvin sign vs k
	}
	for _, tt := range tests {
		if got := PlaintextAllowed(tt.url, tt.allow); got != tt.want {
			t.Errorf("PlaintextAllowed(%q, %q) = %v, want %v", tt.url, tt.allow, got, tt.want)
		}
	}
}

func TestClientPlaintextWarning(t *testing.T) {
	if w := ClientPlaintextWarning("http://127.0.0.1:9090", ""); w != "" {
		t.Errorf("loopback URL should not warn, got:\n%s", w)
	}
	if w := ClientPlaintextWarning("https://192.168.1.10:9090", ""); w != "" {
		t.Errorf("https URL should not warn, got:\n%s", w)
	}
	if w := ClientPlaintextWarning("http://192.168.1.10:9090", "192.168.1.10"); w != "" {
		t.Errorf("allowed host should not warn, got:\n%s", w)
	}
	if w := ClientPlaintextWarning("http://192.168.1.10:9090", "192.168.1.99"); w == "" {
		t.Error("host not in PHOENIX_ALLOW_PLAINTEXT should still warn")
	}
	// Review regressions: names that only Unicode or zone case-folding
	// would equate dial different destinations, so they must still warn.
	if w := ClientPlaintextWarning("http://\u03c2.example:9090", "\u03c3.example"); w == "" {
		t.Error("final sigma host must not be silenced by a sigma entry")
	}
	if w := ClientPlaintextWarning("http://[fe80::1%25ETH0]:9090", "fe80::1%eth0"); w == "" {
		t.Error("IPv6 zone must match exactly to silence the warning")
	}
	w := ClientPlaintextWarning("http://192.168.1.10:9090", "")
	for _, want := range []string{"WARNING", "http://192.168.1.10:9090", "unencrypted", "PHOENIX_CA_CERT", "PHOENIX_ALLOW_PLAINTEXT=192.168.1.10"} {
		if !strings.Contains(w, want) {
			t.Errorf("client warning missing %q:\n%s", want, w)
		}
	}
}
