package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Under PHOENIX_ROLE, exec asks for what the role may not read as the agent
// itself, but only at the address where nothing but an approval counts.
func TestExecUsesApprovalsUnderARole(t *testing.T) {
	type call struct{ path, auth, body string }
	run := func(approved string, refs ...string) (calls []call, res execResolved, err error) {
		withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
			auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			b, _ := io.ReadAll(r.Body)
			calls = append(calls, call{r.URL.Path, auth, string(b)})
			if r.URL.Path == "/v1/resolve-approved" && approved == "old server" {
				http.NotFound(w, r)
				return
			}
			var req struct {
				Refs []string `json:"refs"`
				All  bool     `json:"all_or_nothing"`
			}
			json.Unmarshal(b, &req)
			if !req.All {
				t.Error("exec did not ask for all or nothing")
			}
			values, errs, codes := map[string]string{}, map[string]string{}, map[string]any{}
			for _, ref := range req.Refs {
				code := ""
				if r.URL.Path == "/v1/resolve" && strings.Contains(ref, "infra/") {
					code = "SCOPE_EXCEEDED"
				}
				if r.URL.Path == "/v1/resolve-approved" && !strings.HasSuffix(ref, approved) {
					code = "ACL_DENIED"
				}
				if code != "" {
					errs[ref], codes[ref] = "denied", map[string]string{"code": code, "next_step": "request_use"}
					continue
				}
				values[ref] = "v:" + ref
			}
			if len(errs) > 0 {
				values = map[string]string{}
			}
			json.NewEncoder(w).Encode(map[string]any{"values": values, "errors": errs, "error_codes": codes})
		}, func() {
			setupCachedSession(t, "r1")
			res, err = resolveForExec(context.Background(), refs, nil)
		})
		return calls, res, err
	}
	calls, res, err := run("infra/once", "phoenix://dev/db", "phoenix://infra/once")
	if err != nil || len(res.errs) != 0 || len(res.values) != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	last := calls[len(calls)-1]
	if last.path != "/v1/resolve-approved" || last.auth != "bootstrap-token" || strings.Contains(last.body, "dev/db") {
		t.Fatalf("calls = %+v", calls)
	}
	for _, c := range calls[:len(calls)-1] {
		if c.path != "/v1/resolve" || c.auth != "phxs_old" {
			t.Fatalf("calls = %+v", calls)
		}
	}
	// Not approved, or a server that cannot say: the role's answer stands, and
	// the agent's own token never goes to the ordinary address.
	for _, approved := range []string{"something/else", "old server"} {
		calls, res, err = run(approved, "phoenix://infra/plain")
		if err != nil || len(res.values) != 0 || res.codes["phoenix://infra/plain"].Code != "SCOPE_EXCEEDED" {
			t.Errorf("%s: %+v %v", approved, res, err)
		}
		for _, c := range calls {
			if c.path == "/v1/resolve" && c.auth != "phxs_old" {
				t.Errorf("%s: %+v", approved, c)
			}
		}
	}
}

func TestGrantedLimitText(t *testing.T) {
	at := time.Now().Add(2 * time.Minute).UTC()
	until := "until " + clockTime(at.Format(time.RFC3339))
	for want, rq := range map[string]accessRequestView{
		"always":                                 {Always: true},
		until:                                    {GrantExpiresAt: at.Format(time.RFC3339)},
		"one use left, " + until:                 {GrantExpiresAt: at.Format(time.RFC3339), MaxUses: 1, UsesLeft: map[string]int64{"a": 1}},
		"no uses left, " + until:                 {GrantExpiresAt: at.Format(time.RFC3339), MaxUses: 1, UsesLeft: map[string]int64{"a": 0}},
		"one use left for each secret, " + until: {GrantExpiresAt: at.Format(time.RFC3339), MaxUses: 1, UsesLeft: map[string]int64{"a": 1, "b": 1}},
		"a: no uses left; b: 2 uses left, " + until: {GrantExpiresAt: at.Format(time.RFC3339), MaxUses: 2, UsesLeft: map[string]int64{"a": 0, "b": 2}},
	} {
		if got := grantedLimit(rq); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

// A server too old to count uses gets no approval it could mistake for one
// without a limit.
func TestApproveUsesOnOldServerApprovesNothing(t *testing.T) {
	useMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET":
			json.NewEncoder(w).Encode(pendingRequestJSON("why"))
		case strings.HasSuffix(r.URL.Path, "/approve"):
			t.Error("a limited approval was sent where the limit is ignored")
		default:
			http.NotFound(w, r)
		}
	})
	err := cmdApprove([]string{testReqID, "--uses", "1", "--yes"})
	if err == nil || !strings.Contains(err.Error(), "nothing was approved") {
		t.Fatalf("err = %v", err)
	}
}

// An approver's own token may see every agent's requests. Working through a
// role, the MCP status tool shows only the agent's own.
func TestMCPStatusUnderARoleShowsOnlyOwnRequests(t *testing.T) {
	for owner, want := range map[string]bool{"me": true, "other": false} {
		withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/whoami" {
				w.Write([]byte(`{"agent":"me"}`))
				return
			}
			rq := pendingRequestJSON("why")
			rq["agent"] = owner
			json.NewEncoder(w).Encode(rq)
		}, func() {
			setupCachedSession(t, "r1")
			text, isErr := mcpToolRequestStatus(json.RawMessage(`{"request_id":"`+testReqID+`"}`), nil)
			if isErr == want || strings.Contains(text, "infra/a") != want {
				t.Errorf("%s: %v %s", owner, isErr, text)
			}
		})
	}
}

func TestNextHintSkipsSpentPath(t *testing.T) {
	rq := accessRequestView{Status: "approved", NextStep: "use_exec", GrantedPaths: []string{"a/one", "b/two"},
		MaxUses: 1, UsesLeft: map[string]int64{"a/one": 0, "b/two": 1}}
	if got := requestNextHint(rq); !strings.Contains(got, "phoenix://b/two") {
		t.Fatalf("hint = %q", got)
	}
}

// A role does not stop the MCP server from asking as the agent.
func TestMCPRequestUsesOwnIdentityUnderARole(t *testing.T) {
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer bootstrap-token" {
			t.Errorf("asked with %q", got)
		}
		rq := pendingRequestJSON("why")
		delete(rq, "agent") // a plain agent's view does not name the owner
		rq["status"], rq["always"], rq["granted_paths"] = "approved", true, []string{"infra/a"}
		json.NewEncoder(w).Encode(rq)
	}, func() {
		setupCachedSession(t, "r1")
		text, isErr := mcpToolRequestStatus(json.RawMessage(`{"request_id":"`+testReqID+`"}`), nil)
		if isErr || !strings.Contains(text, "granted: infra/a, always") {
			t.Fatalf("%v %s", isErr, text)
		}
	})
}
