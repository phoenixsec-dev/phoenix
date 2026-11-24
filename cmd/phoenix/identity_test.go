package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// identityServer points the CLI at a server that answers with h and logs calls.
func identityServer(t *testing.T, h http.HandlerFunc) *callLog {
	t.Helper()
	log := &callLog{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		log.add(r)
		r.Body = io.NopCloser(bytes.NewReader(body))
		h(w, r)
	}))
	t.Cleanup(ts.Close)
	oldURL, oldToken := serverURL, token
	serverURL, token = ts.URL, "test-token"
	t.Cleanup(func() { serverURL, token = oldURL, oldToken })
	t.Setenv("PHOENIX_SERVER", ts.URL)
	t.Setenv("PHOENIX_TOKEN", "test-token")
	return log
}

func TestAgentSetSendsOnlyWhatWasGiven(t *testing.T) {
	log := identityServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"identity":{"name":"desk bot","who":"robin","formerly":["a","b"]}}`)
	})
	_, out, errOut := runMain(t, "agent", "set", "desk bot", "--who", "robin", "--authority=", "--formerly", "a, b")
	if want := `PATCH /v1/agents/desk%20bot/identity {"authority":"","formerly":["a","b"],"who":"robin"}`; log.String() != want {
		t.Fatalf("sent %s\nwant %s\n%s", log, want, errOut)
	}
	if !strings.Contains(out, "Who:       robin") || !strings.Contains(out, "Kind:      -") || !strings.Contains(out, "Formerly:  a, b") {
		t.Fatalf("output:\n%s", out)
	}
	for _, bad := range []string{",", "a,", "a,,b"} {
		if err := cmdAgentSet([]string{"bot", "--formerly", bad}); err == nil || !strings.Contains(err.Error(), "empty name") {
			t.Errorf("--formerly %q: %v", bad, err)
		}
	}
	if runMain(t, "agent", "set", "bot", "--formerly="); !strings.HasSuffix(log.String(), `{"formerly":[]}`) {
		t.Errorf("clearing formerly sent %s", log)
	}
	if err := cmdAgentSet([]string{"bot"}); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("set with nothing to set = %v", err)
	}
}

// A value spelled like an option is a value: the credential and permissions
// sent are the ones given.
func TestAgentCreateOptionLikeValues(t *testing.T) {
	var got struct {
		Token       string
		Permissions []struct{ Path string }
		Who, Kind   *string
	}
	identityServer(t, func(w http.ResponseWriter, r *http.Request) {
		got.Token, got.Permissions, got.Who, got.Kind = "", nil, nil, nil
		json.NewDecoder(r.Body).Decode(&got)
		fmt.Fprint(w, `{"identity":{"name":"bot"}}`)
	})
	for _, v := range []string{"--who", "--authority", "--kind", "--formerly", "--acl", "--force"} {
		if code, _, _ := runMain(t, "agent", "create", "bot", "-t", v, "--acl", "a/*:list", "--kind", v); code != -1 {
			t.Errorf("%s: exit %d", v, code)
		}
		if got.Token != v || len(got.Permissions) != 1 || got.Permissions[0].Path != "a/*" || got.Who != nil || got.Kind == nil || *got.Kind != v {
			t.Errorf("a value spelled %s changed the request", v)
		}
	}
}

// A server that does not know the filters would answer with everything.
func TestAuditFiltersNeedServerSupport(t *testing.T) {
	entries := `[]`
	identityServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"entries":%s}`, entries)
	})
	for _, f := range []string{"--who", "--host", "--authority"} {
		for _, entries = range []string{`[]`, `[{"agent":"other","path":"p"}]`} {
			if err := cmdAudit([]string{f, "x"}); err == nil || !strings.Contains(err.Error(), "too old") {
				t.Errorf("%s: %v", f, err)
			}
		}
	}
	if code, out, _ := runMain(t, "audit"); code != -1 || strings.Contains(out, "attested") {
		t.Errorf("plain audit: exit %d, %q", code, out)
	}
}

// An older server ignores or lacks the fields; the CLI says so instead of
// looking as if it worked.
func TestIdentityFieldsOnOlderServer(t *testing.T) {
	identityServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PATCH":
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		case "POST":
			fmt.Fprint(w, `{"status":"ok","agent":"bot"}`)
		default:
			if r.URL.Path == "/v1/whoami" {
				fmt.Fprint(w, `{"agent":"bot","auth_method":"bearer","source_ip":"1.1.1.1"}`)
				return
			}
			fmt.Fprint(w, `{"agents":["bot"]}`)
		}
	})
	for name, err := range map[string]error{
		"set":    cmdAgentSet([]string{"bot", "--who", "robin"}),
		"show":   cmdAgentShow([]string{"bot"}),
		"create": cmdAgentCreate([]string{"bot", "-t", "tok", "--kind", "agent"}),
	} {
		if err == nil || !strings.Contains(err.Error(), "too old") {
			t.Errorf("%s = %v", name, err)
		}
	}
	if err := cmdAgentCreate([]string{"bot", "-t", "tok"}); err != nil {
		t.Errorf("plain create = %v", err)
	}
	if _, out, _ := runMain(t, "whoami"); strings.Contains(out, "Attested") || !strings.Contains(out, "Agent:     bot") {
		t.Errorf("whoami:\n%s", out)
	}
}

func TestAuditAndWhoamiShowIdentity(t *testing.T) {
	log := identityServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/whoami" {
			fmt.Fprint(w, `{"agent":"bot","auth_method":"bearer","source_ip":"1.1.1.1","who":"robin","host":"","authority":"night-desk","kind":"agent","formerly":["helper"],"attested":false}`)
			return
		}
		fmt.Fprint(w, `{"identity_filters":true,"entries":[{"ts":"T1","agent":"bot","action":"list","path":"p","status":"allowed","ip":"1.1.1.1"},
			{"ts":"T3","agent":"bot","action":"list","path":"p","status":"allowed","ip":"1.1.1.1","who":"","host":"","authority":"","attested":false},
			{"ts":"T2","agent":"bot","action":"list","path":"p","status":"allowed","ip":"1.1.1.1","host":"","who":"ro\u001b[2Jbin","authority":"x","attested":false}]}`)
	})
	_, out, _ := runMain(t, "audit", "--who", "robin", "--host", "h", "--authority", "x", "-n", "5")
	if want := "GET /v1/audit?authority=x&host=h&limit=5&who=robin"; log.String() != want {
		t.Errorf("sent %s, want %s", log, want)
	}
	lines := strings.Split(out, "\n")
	if !strings.HasSuffix(lines[0], "1.1.1.1") || !strings.HasSuffix(lines[1], `1.1.1.1  who=-  host=-  authority=-  attested=no`) ||
		!strings.HasSuffix(lines[2], `1.1.1.1  who="ro[2Jbin"  host=-  authority="x"  attested=no`) {
		t.Errorf("audit output:\n%s", out)
	}
	_, out, _ = runMain(t, "whoami")
	for _, want := range []string{"Who:       robin", "Host:      -", "Authority: night-desk", "Kind:      agent", "Formerly:  helper", "Attested:  no"} {
		if !strings.Contains(out, want) {
			t.Errorf("whoami lacks %q:\n%s", want, out)
		}
	}
}
