package removed

import (
	"strings"
	"testing"
)

func TestFind(t *testing.T) {
	fields := []Field{
		{Path: "auth.mtls", Why: "client certificates are gone", Instead: "use https_listener"},
		{Path: "roles.*.step_up", Why: "step-up is gone"},
		{Path: "roles.*.trust.[]", Value: "mtls", Why: "mtls is gone"},
		{Path: "rules.[].deny_tools", Why: "tool rules checked nothing"},
	}
	data := []byte(`{
		"auth": {"mtls": {"enabled": false}},
		"roles": {"b": {"step_up": false, "trust": ["bearer", "mtls"]}, "a": {"trust": ["bearer"]}},
		"rules": [{"path": "x"}, {"path": "y", "deny_tools": []}]
	}`)
	got := Find(data, fields)
	want := []string{
		"auth.mtls: removed. Why: client certificates are gone. Instead: use https_listener.",
		"roles.b.step_up: removed. Why: step-up is gone.",
		`roles.b.trust "mtls": removed. Why: mtls is gone.`,
		"rules[1].deny_tools: removed. Why: tool rules checked nothing.",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Find:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if err := Error("config", got); err == nil || !strings.Contains(err.Error(), "\n  roles.b.step_up") {
		t.Fatalf("Error should list one line per field, got %v", err)
	}
}

func TestFindNothing(t *testing.T) {
	fields := []Field{{Path: "auth.mtls", Why: "x"}}
	for _, data := range []string{`{"auth": {"bearer": {}}}`, `[]`, `{}`, ``, "  \n"} {
		if got := Find([]byte(data), fields); len(got) != 0 {
			t.Errorf("Find(%s) = %v, want none", data, got)
		}
	}
	if Error("config", nil) != nil {
		t.Error("Error(nil) should be nil")
	}
}

// Review R1-01: the config decoder matches keys case-insensitively, merges
// repeated objects and skips numbers it cannot hold, so the scan must do the
// same or a removed setting slips through.
func TestFindMatchesLikeTheConfigDecoder(t *testing.T) {
	fields := []Field{
		{Path: "tls", Why: "w"},
		{Path: "auth.mtls", Why: "w"},
		{Path: "roles.*.step_up", Why: "w"},
	}
	for name, tc := range map[string]struct {
		data string
		want []string
	}{
		"capitals":         {`{"TLS": {"enabled": true}, "Auth": {"MTLS": {}}}`, []string{"Auth.MTLS", "TLS"}},
		"capitalised role": {`{"Roles": {"Dev": {"Step_Up": true}}}`, []string{"Roles.Dev.Step_Up"}},
		"duplicate parent": {`{"auth": {"mtls": {}}, "auth": {"bearer": {}}}`, []string{"auth.mtls"}},
		"same key twice":   {`{"auth": {"mtls": {}}, "auth": {"mtls": {}}}`, []string{"auth.mtls"}},
		"huge number":      {`{"metadata": 1e400, "tls": {}}`, []string{"tls"}},
	} {
		got := Find([]byte(tc.data), fields)
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %v, want %d lines for %v", name, got, len(tc.want), tc.want)
			continue
		}
		for i, w := range tc.want {
			if !strings.HasPrefix(got[i], w+": removed.") {
				t.Errorf("%s: line %d = %q, want path %q", name, i, got[i], w)
			}
		}
	}
	// Anything the scan cannot read is refused, never treated as clean.
	if got := Find([]byte(`{"tls": {}`), fields); len(got) != 1 || !strings.Contains(got[0], "could not be checked") {
		t.Errorf("truncated JSON: got %v, want one refusal line", got)
	}
}
