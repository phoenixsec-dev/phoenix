package ref

import (
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"phoenix://openclaw/api-key", "openclaw/api-key", false},
		{"phoenix://ns/deep/nested/path", "ns/deep/nested/path", false},
		{"phoenix://monitoring/grafana-admin", "monitoring/grafana-admin", false},

		// Invalid references
		{"", "", true},                           // empty
		{"openclaw/api-key", "", true},            // no scheme
		{"http://openclaw/api-key", "", true},     // wrong scheme
		{"phoenix://", "", true},                  // empty path
		{"phoenix://noslash", "", true},            // path must have slash
		{"phoenix:///leading", "", true},           // leading slash
		{"phoenix://trailing/", "", true},          // trailing slash
		{"phoenix://double//slash", "", true},      // double slash
		{"phoenix://dot/../traversal", "", true},   // path traversal
	}

	for _, tt := range tests {
		got, err := Parse(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("Parse(%q): err=%v, wantErr=%v", tt.input, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("Parse(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFormat(t *testing.T) {
	if got := Format("openclaw/api-key"); got != "phoenix://openclaw/api-key" {
		t.Errorf("Format = %q, want phoenix://openclaw/api-key", got)
	}
}

func TestIsRef(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"phoenix://openclaw/key", true},
		{"phoenix://", true}, // prefix match only, not validity
		{"http://example.com", false},
		{"openclaw/key", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := IsRef(tt.input); got != tt.want {
			t.Errorf("IsRef(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestFormatParseRoundTrip(t *testing.T) {
	path := "openclaw/api-key"
	ref := Format(path)
	got, err := Parse(ref)
	if err != nil {
		t.Fatalf("Parse(Format(%q)): %v", path, err)
	}
	if got != path {
		t.Fatalf("round-trip: got %q, want %q", got, path)
	}
}
