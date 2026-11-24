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

// Under PHOENIX_ROLE, exec reads a secret the role may not read as the agent
// itself, but only when a human approved exactly that path for the agent.
func TestExecUsesApprovalsUnderARole(t *testing.T) {
	type call struct{ auth, body string }
	run := func(whoami string, refs ...string) ([]call, execResolved, error) {
		var calls []call
		var res execResolved
		var err error
		withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
			auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if r.URL.Path == "/v1/whoami" {
				w.Write([]byte(whoami))
				return
			}
			b, _ := io.ReadAll(r.Body)
			calls = append(calls, call{auth, string(b)})
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
				if auth == "phxs_old" && strings.Contains(ref, "infra/") {
					errs[ref], codes[ref] = "denied", map[string]string{"code": "SCOPE_EXCEEDED", "next_step": "request_use"}
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
	grants := `{"acl":[{"path":"infra/always","always":true},{"path":"infra/plain"}],"grants":[{"paths":["infra/once"],"action":"read_value"},{"paths":["infra/login"],"action":"ssh_login"}]}`

	calls, res, err := run(grants, "phoenix://dev/db", "phoenix://infra/once", "phoenix://infra/always")
	if err != nil || len(res.errs) != 0 || len(res.values) != 3 {
		t.Fatalf("%+v %v", res, err)
	}
	last := calls[len(calls)-1]
	if len(calls) != 3 || calls[1].auth != "phxs_old" || last.auth != "bootstrap-token" || strings.Contains(last.body, "dev/db") {
		t.Fatalf("calls = %+v", calls)
	}
	// The agent's own wider access is not a way around the role.
	for _, ref := range []string{"phoenix://infra/plain", "phoenix://infra/login", "phoenix://infra/other"} {
		calls, res, _ = run(grants, ref)
		if len(calls) != 1 || len(res.errs) != 1 {
			t.Errorf("%s: calls %+v", ref, calls)
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

// An older server ignores "uses" and makes a grant without a limit. The
// approver must hear that, with the way to take it back.
func TestApproveUsesOnOldServerIsNotSilent(t *testing.T) {
	useMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(pendingRequestJSON("why"))
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"grant_id": "gnt_0123456789abcdef0123456789abcdef", "paths": []string{"infra/a"}, "expires_at": "x"})
	})
	err := cmdApprove([]string{testReqID, "--uses", "1", "--yes"})
	if err == nil || !strings.Contains(err.Error(), "NO use limit") {
		t.Fatalf("err = %v", err)
	}
}

// A role does not stop the MCP server from asking as the agent.
func TestMCPRequestUsesOwnIdentityUnderARole(t *testing.T) {
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer bootstrap-token" {
			t.Errorf("asked with %q", got)
		}
		rq := pendingRequestJSON("why")
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
