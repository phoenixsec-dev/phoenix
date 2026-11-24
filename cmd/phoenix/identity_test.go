package main

import (
	"fmt"
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
		log.add(r)
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
	if err := cmdAgentSet([]string{"bot"}); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("set with nothing to set = %v", err)
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
			fmt.Fprint(w, `{"agent":"bot","auth_method":"bearer","source_ip":"1.1.1.1","who":"robin","host":"","authority":"night-desk","kind":"agent","attested":false}`)
			return
		}
		fmt.Fprint(w, `{"entries":[{"ts":"T1","agent":"bot","action":"list","path":"p","status":"allowed","ip":"1.1.1.1"},
			{"ts":"T2","agent":"bot","action":"list","path":"p","status":"allowed","ip":"1.1.1.1","who":"ro\u001b[2Jbin","authority":"x","attested":false}]}`)
	})
	_, out, _ := runMain(t, "audit", "--who", "robin", "--host", "h", "--authority", "x", "-n", "5")
	if want := "GET /v1/audit?authority=x&host=h&limit=5&who=robin"; log.String() != want {
		t.Errorf("sent %s, want %s", log, want)
	}
	lines := strings.Split(out, "\n")
	if !strings.HasSuffix(lines[0], "1.1.1.1") || !strings.HasSuffix(lines[1], `1.1.1.1  who="ro[2Jbin"  authority="x"  attested=no`) {
		t.Errorf("audit output:\n%s", out)
	}
	_, out, _ = runMain(t, "whoami")
	for _, want := range []string{"Who:       robin", "Host:      -", "Authority: night-desk", "Kind:      agent", "Attested:  no"} {
		if !strings.Contains(out, want) {
			t.Errorf("whoami lacks %q:\n%s", want, out)
		}
	}
}
