package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A line an older version wrote reads back with the caller fields empty and
// not attested, and a new line keeps every key the old one had.
func TestCallerFieldsOldAndNewLines(t *testing.T) {
	const oldLine = `{"ts":"2026-01-02T03:04:05Z","agent":"a","action":"read_value","path":"p","status":"allowed","ip":"1.1.1.1","session_id":"s","sealed":false}`
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte(oldLine+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	l, _ := NewLogger(path)
	l.Log(Entry{Agent: "a", Action: "read_value", Path: "p", Status: "allowed", IP: "1.1.1.1", SessionID: "s",
		Caller: Caller{Who: "w", Host: "h", Authority: "x"}})
	l.Close()

	es, err := Query(path, QueryOptions{})
	if err != nil || len(es) != 2 {
		t.Fatalf("entries = %v, %v", es, err)
	}
	if es[0].Caller != (Caller{}) || es[0].Declared() {
		t.Fatalf("old line caller = %+v", es[0].Caller)
	}
	if es[1].Caller != (Caller{Who: "w", Host: "h", Authority: "x"}) || !es[1].Declared() {
		t.Fatalf("new line caller = %+v", es[1].Caller)
	}

	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var before, after map[string]any
	json.Unmarshal([]byte(lines[0]), &before)
	json.Unmarshal([]byte(lines[1]), &after)
	for k, v := range before {
		if k != "ts" && after[k] != v {
			t.Errorf("new line %q = %v, old line %v", k, after[k], v)
		}
	}
	if after["attested"] != false || len(after) != len(before)+4 {
		t.Errorf("new line keys = %v", after)
	}
}

// The who, host and authority filters match those fields only, and a search
// by name also finds the names the identity had before.
func TestCallerFilters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, _ := NewLogger(path)
	l.Log(Entry{Agent: "old-a", Path: "p/0"})
	l.Log(Entry{Agent: "a", Path: "p/1", Caller: Caller{Who: "w", Host: "h", Authority: "x"}})
	// The same words in metadata are not the fields.
	l.Log(Entry{Agent: "b", Path: "p/2", Caller: Caller{Who: "v"}, Metadata: map[string]string{"who": "w", "host": "h", "agent": "a"}})
	l.Close()
	for want, o := range map[string]QueryOptions{
		"p/1":     {Who: "w"},
		"p/1 ":    {Host: "h", Authority: "x"},
		"p/2":     {Who: "v"},
		"":        {Who: "w", Host: "other"},
		"p/0 p/1": {Agent: "a", FormerAgents: []string{"old-a", "older-a"}},
		"p/0":     {Agent: "old-a"},
		" p/1":    {Agent: "a"},
	} {
		got, err := Query(path, o)
		if err != nil || strings.Join(paths(got), " ") != strings.TrimSpace(want) {
			t.Errorf("%+v = %v (%v), want %q", o, paths(got), err, want)
		}
	}
}
