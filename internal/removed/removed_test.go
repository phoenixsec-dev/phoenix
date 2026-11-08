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
		"auth.mtls: removed, client certificates are gone; use https_listener",
		"roles.b.step_up: removed, step-up is gone",
		`roles.b.trust "mtls": removed, mtls is gone`,
		"rules[1].deny_tools: removed, tool rules checked nothing",
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
	for _, data := range []string{`{"auth": {"bearer": {}}}`, `not json`, `[]`, `{}`} {
		if got := Find([]byte(data), fields); len(got) != 0 {
			t.Errorf("Find(%s) = %v, want none", data, got)
		}
	}
	if Error("config", nil) != nil {
		t.Error("Error(nil) should be nil")
	}
}
