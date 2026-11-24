package acl

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/phoenixsec/phoenix/internal/crypto"
	"github.com/phoenixsec/phoenix/internal/fsutil"
)

func ptr[T any](v T) *T { return &v }

// readAgents returns the raw "agents" object of an ACL file.
func readAgents(t *testing.T, path string) map[string]map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Agents map[string]map[string]any `json:"agents"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f.Agents
}

func reload(t *testing.T, path string) *ACL {
	t.Helper()
	a, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// Labels survive a restart, change one at a time, touch nothing else, and are
// kept when the token is replaced. The serial stays with the identity and is
// new when the identity is deleted and made again.
func TestLabelsAndSerialLifetime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acl.json")
	a := reload(t, path)
	perms := []Permission{{Path: "a/*", Actions: []Action{ActionList}}}
	if err := a.AddAgentLabeled("bot", "tok-1", perms, LabelChange{Kind: ptr(" agent ")}); err != nil {
		t.Fatal(err)
	}
	made, _ := a.GetAgent("bot")
	if made.Serial == "" || made.Serial == made.CredentialID || made.Kind != "agent" {
		t.Fatalf("new agent = %+v", made)
	}

	if _, err := a.SetLabels("bot", LabelChange{Who: ptr("robin"), Authority: ptr("night-desk"), Formerly: ptr([]string{"old-bot", "old-bot"})}); err != nil {
		t.Fatal(err)
	}
	a = reload(t, path)
	set, _ := a.GetAgent("bot")
	want := *made
	want.Labels = Labels{Who: "robin", Authority: "night-desk", Kind: "agent", Formerly: []string{"old-bot"}}
	if !reflect.DeepEqual(*set, want) {
		t.Fatalf("after set and restart = %+v\nwant %+v", *set, want)
	}

	// Clearing one leaves the others.
	if _, err := a.SetLabels("bot", LabelChange{Authority: ptr(""), Formerly: ptr([]string{})}); err != nil {
		t.Fatal(err)
	}
	// A new token is a new credential of the same identity.
	if err := a.UpdateAgent("bot", "tok-2", perms); err != nil {
		t.Fatal(err)
	}
	rot, _ := reload(t, path).GetAgent("bot")
	if rot.Serial != made.Serial || rot.CredentialID == made.CredentialID || rot.Who != "robin" || rot.Authority != "" || rot.Kind != "agent" || rot.Formerly != nil {
		t.Fatalf("after token change = %+v", rot)
	}
	// Deleted and re-made under the same name and token: a different identity.
	if err := a.RemoveAgent("bot"); err != nil {
		t.Fatal(err)
	}
	if err := a.AddAgent("bot", "tok-2", perms); err != nil {
		t.Fatal(err)
	}
	if again, _ := a.GetAgent("bot"); again.Serial == made.Serial || again.Who != "" {
		t.Fatalf("re-made agent kept the old identity: %+v", again)
	}
}

const oldACLFile = `{
  "agents": {
    "admin": {"name": "admin", "token_hash": "%s", "credential_id": "c1", "permissions": [{"path": "*", "actions": ["admin"]}]},
    "plain": {"name": "plain", "token_hash": "%s", "permissions": null, "seal_public_key": "k"}
  }
}`

// An ACL file from v0.24.0 loads as it is and is not rewritten by loading.
// The next change gives every identity a serial and alters nothing else.
func TestOldACLFileLoadsUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acl.json")
	old := []byte(fmt.Sprintf(oldACLFile, crypto.HashToken("t-admin"), crypto.HashToken("t-plain")))
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	a := reload(t, path)
	if b, _ := os.ReadFile(path); string(b) != string(old) {
		t.Fatal("loading rewrote the ACL file")
	}
	if name, err := a.Authenticate("t-plain"); err != nil || name != "plain" {
		t.Fatalf("authenticate = %q, %v", name, err)
	}
	before := readAgents(t, path)
	if _, err := a.SetLabels("plain", LabelChange{Who: ptr("robin")}); err != nil {
		t.Fatal(err)
	}
	after := readAgents(t, path)
	for name, agent := range after {
		if s, _ := agent["serial"].(string); len(s) != 32 {
			t.Errorf("%s has serial %q", name, s)
		}
		delete(agent, "serial")
	}
	before["plain"]["who"] = "robin"
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("file after a change = %v\nwant %v", after, before)
	}
}

// An older server reads a new file and everything it knows works. When it
// saves, the new fields are dropped, and this version loads that too.
func TestOlderServerOpensNewACLFile(t *testing.T) {
	// legacyAgent is Agent as v0.24.0 had it.
	type legacyAgent struct {
		Name          string       `json:"name"`
		TokenHash     string       `json:"token_hash"`
		CredentialID  string       `json:"credential_id,omitempty"`
		Permissions   []Permission `json:"permissions"`
		SealPublicKey string       `json:"seal_public_key,omitempty"`
	}
	path := filepath.Join(t.TempDir(), "acl.json")
	a := reload(t, path)
	perms := []Permission{{Path: "a/*", Actions: []Action{ActionList}}}
	if err := a.AddAgentLabeled("bot", "tok", perms, LabelChange{Who: ptr("robin"), Formerly: ptr([]string{"x"})}); err != nil {
		t.Fatal(err)
	}
	cur, _ := a.GetAgent("bot")

	b, _ := os.ReadFile(path)
	var legacy struct {
		Agents map[string]legacyAgent `json:"agents"`
	}
	if err := json.Unmarshal(b, &legacy); err != nil {
		t.Fatalf("older server cannot read the file: %v", err)
	}
	if got, want := legacy.Agents["bot"], (legacyAgent{"bot", cur.TokenHash, cur.CredentialID, perms, ""}); !reflect.DeepEqual(got, want) {
		t.Fatalf("older server sees %+v, want %+v", got, want)
	}
	b, _ = json.Marshal(legacy)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	a = reload(t, path)
	if name, err := a.Authenticate("tok"); err != nil || name != "bot" {
		t.Fatalf("after the older server saved: %q, %v", name, err)
	}
	if got, _ := a.GetAgent("bot"); got.Who != "" || got.Serial != "" || got.CredentialID != cur.CredentialID {
		t.Fatalf("after the older server saved: %+v", got)
	}
}

// A save that fails leaves the old file and the old labels. One that replaced
// the file but failed its last sync is still an error, with the labels in use
// matching the file.
func TestLabelSaveFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acl.json")
	a := reload(t, path)
	if err := a.AddAgentLabeled("bot", "tok", nil, LabelChange{Who: ptr("robin")}); err != nil {
		t.Fatal(err)
	}
	saved, _ := os.ReadFile(path)
	strict := func(ops fsutil.AtomicOps) {
		a.writeFile = func(p string, d []byte, perm os.FileMode) error {
			return fsutil.WriteFileAtomicStrictOps(p, d, perm, ops)
		}
	}
	for name, ops := range map[string]fsutil.AtomicOps{
		"half written": {Write: func(f *os.File, b []byte) error { f.Write(b[:len(b)/2]); return errors.New("disk full") }},
		"not renamed":  {Rename: func(string, string) error { return errors.New("no") }},
	} {
		strict(ops)
		if _, err := a.SetLabels("bot", LabelChange{Who: ptr("eve")}); err == nil {
			t.Fatalf("%s: no error", name)
		}
		if b, _ := os.ReadFile(path); string(b) != string(saved) {
			t.Fatalf("%s: file changed", name)
		}
		if got, _ := a.GetAgent("bot"); got.Who != "robin" {
			t.Fatalf("%s: who in use = %q", name, got.Who)
		}
		if left, _ := filepath.Glob(path + ".tmp-*"); len(left) != 0 {
			t.Fatalf("%s: left %v", name, left)
		}
	}
	strict(fsutil.AtomicOps{SyncDir: func(string) error { return errors.New("no") }})
	if _, err := a.SetLabels("bot", LabelChange{Who: ptr("sam")}); err == nil {
		t.Fatal("unsynced save reported as done")
	}
	got, _ := a.GetAgent("bot")
	if disk := readAgents(t, path)["bot"]["who"]; got.Who != "sam" || disk != "sam" {
		t.Fatalf("after an unsynced save: in use %q, file %q", got.Who, disk)
	}
}

// Two identities with one serial (a hand-copied block) both get a new one.
func TestDuplicateSerialsReplaced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acl.json")
	os.WriteFile(path, []byte(`{"agents":{"a":{"name":"a","serial":"s"},"b":{"name":"b","serial":"s"},"c":{"name":"c","serial":"only"}}}`), 0600)
	a := reload(t, path)
	if err := a.Save(); err != nil {
		t.Fatal(err)
	}
	got := readAgents(t, path)
	if got["a"]["serial"] == "s" || got["b"]["serial"] == "s" || got["a"]["serial"] == got["b"]["serial"] || got["c"]["serial"] != "only" {
		t.Fatalf("serials = %v", got)
	}
}

func TestLabelsRefused(t *testing.T) {
	for name, c := range map[string]LabelChange{
		"line break":     {Who: ptr("a\nb")},
		"right-to-left":  {Authority: ptr("a\u202eb")},
		"zero width":     {Kind: ptr("a\u200bb")},
		"too long":       {Who: ptr(strings.Repeat("x", maxLabelRunes+1))},
		"own name":       {Formerly: ptr([]string{"bot"})},
		"empty former":   {Formerly: ptr([]string{" "})},
		"control former": {Formerly: ptr([]string{"a\x1b[2J"})},
	} {
		if _, err := c.Normalized("bot"); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Any words are fine: the vocabulary is the operator's.
	if _, err := (LabelChange{Who: ptr("Köchin, 夜勤"), Kind: ptr("kitchen robot")}).Normalized("bot"); err != nil {
		t.Error(err)
	}
}
