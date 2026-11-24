package grant

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// sinkFn is an AuditSink made of a function.
type sinkFn func(Event) error

func (f sinkFn) Append(e Event) error { return f(e) }

// A grants file from a server without actor labels loads, its queued line has
// none, and that older server reads a file that has them.
func TestPendingEventsWithAndWithoutLabels(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.json")
	var got []Event
	full := true
	opts := Options{Path: path, Logf: t.Logf,
		Audit: sinkFn(func(e Event) error {
			if full && e.Phase == PhaseCommitted {
				return errors.New("disk full")
			}
			got = append(got, e)
			return nil
		}),
	}
	s, err := Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Create(CreateInput{Agent: "a", SourceIP: "1.1.1.1", AuthMethod: AuthBearer, CredentialFP: "sha256:x", Paths: []string{"p/x"}, Action: ActionReadValue, Reason: "why", Labels: Labels{Who: "robin", Authority: "desk"}}); err != nil {
		t.Fatal(err)
	}

	// The new file, as the older server's types see it.
	b, _ := os.ReadFile(path)
	var old struct {
		Version      int             `json:"version"`
		Requests     json.RawMessage `json:"requests"`
		Grants       json.RawMessage `json:"grants"`
		AuditPending []struct {
			ID      string            `json:"id"`
			Name    string            `json:"name"`
			Phase   Phase             `json:"phase"`
			Time    string            `json:"time"`
			Agent   string            `json:"agent"`
			Actor   string            `json:"actor"`
			ActorIP string            `json:"actor_ip"`
			Request string            `json:"request_id"`
			Paths   []string          `json:"paths"`
			Action  string            `json:"action"`
			Detail  map[string]string `json:"detail"`
		} `json:"audit_pending"`
	}
	if err := json.Unmarshal(b, &old); err != nil || len(old.AuditPending) != 1 || old.AuditPending[0].Actor != "a" {
		t.Fatalf("older server: %v, %d pending", err, len(old.AuditPending))
	}

	// What the older server writes back, opened here.
	b, _ = json.Marshal(old)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	full, got = false, nil
	if _, err := Open(opts); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != old.AuditPending[0].ID || got[0].ActorWho != "" || got[0].ActorAuthority != "" {
		t.Fatalf("replayed = %+v", got)
	}
}
