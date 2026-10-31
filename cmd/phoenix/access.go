package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Request-use grants on the CLI (plan section 12): an agent asks a human for
// temporary use of exact secret paths, an approver decides, and the agent
// uses the grant through phoenix exec. Everything here runs on the agent's
// OWN identity (PHOENIX_TOKEN bootstrap token or mTLS cert): the server
// refuses session tokens for requests and grants. All text that came from
// the server is passed through cleanServerText before it is printed.

var (
	requestIDPattern = regexp.MustCompile(`^req_[0-9a-f]{32}$`)
	grantIDPattern   = regexp.MustCompile(`^gnt_[0-9a-f]{32}$`)
)

// accessRequestView is the subset of a request's JSON the CLI prints.
type accessRequestView struct {
	ID                  string   `json:"id"`
	Status              string   `json:"status"`
	Agent               string   `json:"agent"`
	SourceIP            string   `json:"source_ip"`
	AuthMethod          string   `json:"auth_method"`
	Paths               []string `json:"paths"`
	Action              string   `json:"action"`
	Reason              string   `json:"reason"`
	RequestedTTL        string   `json:"requested_ttl"`
	ExpiresAt           string   `json:"expires_at"`
	NextStep            string   `json:"next_step"`
	Message             string   `json:"message"`
	GrantID             string   `json:"grant_id"`
	GrantedPaths        []string `json:"granted_paths"`
	GrantExpiresAt      string   `json:"grant_expires_at"`
	AlreadyAllowedPaths []string `json:"already_allowed_paths"`
	Note                string   `json:"note"`
}

// grantView is the subset of a grant's JSON the CLI prints.
type grantView struct {
	ID         string   `json:"id"`
	Agent      string   `json:"agent"`
	Paths      []string `json:"paths"`
	Action     string   `json:"action"`
	State      string   `json:"state"`
	ExpiresAt  string   `json:"expires_at"`
	UseCount   int64    `json:"use_count"`
	LastUsedAt string   `json:"last_used_at"`
}

// requireBootstrapAuth is requireAuth for request-use commands. They must
// run on the agent's own identity, so PHOENIX_ROLE is ignored (no session is
// minted) and a phxs_ session token is refused before anything is sent.
func requireBootstrapAuth() error {
	if strings.HasPrefix(token, "phxs_") {
		return fmt.Errorf("access requests and grants use the agent's own identity (bootstrap PHOENIX_TOKEN or mTLS cert), not a phxs_ session token")
	}
	if token != "" {
		return nil
	}
	if os.Getenv("PHOENIX_CLIENT_CERT") != "" && os.Getenv("PHOENIX_CLIENT_KEY") != "" {
		return nil
	}
	return fmt.Errorf("no auth configured: set PHOENIX_TOKEN or PHOENIX_CLIENT_CERT + PHOENIX_CLIENT_KEY")
}

// apiJSON sends a request and decodes a 200/201 JSON reply into out. Any
// other status becomes the usual cleaned denial error.
func apiJSON(method, path string, body any, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	}
	resp, err := apiRequest(method, path, rd)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return resp.StatusCode, handleError(resp)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("decoding response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

// cleanList cleans each server-supplied string and joins them. It is used
// for path lists, so items are never shortened below a valid path.
func cleanList(items []string, sep string) string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = cleanPath(s)
	}
	return strings.Join(out, sep)
}

// cmdRequest handles "phoenix request <path>... --reason ... [--ttl] [--wait]"
// and "phoenix request status <req_id>".
func cmdRequest(args []string) error {
	if len(args) > 0 && args[0] == "status" {
		return cmdRequestStatus(args[1:])
	}
	var paths []string
	var reason, ttl string
	wait := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--reason", "-r":
			if i+1 >= len(args) {
				return fmt.Errorf("--reason needs a value")
			}
			i++
			reason = args[i]
		case "--ttl":
			if i+1 >= len(args) {
				return fmt.Errorf("--ttl needs a duration like 30m")
			}
			i++
			ttl = args[i]
		case "--wait":
			wait = true
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("unknown flag %s", args[i])
			}
			paths = append(paths, strings.TrimPrefix(args[i], "phoenix://"))
		}
	}
	if len(paths) == 0 || strings.TrimSpace(reason) == "" {
		return fmt.Errorf(`usage: phoenix request <path>... --reason "why you need it" [--ttl 30m] [--wait]`)
	}
	if err := requireBootstrapAuth(); err != nil {
		return err
	}
	var rq accessRequestView
	code, err := apiJSON("POST", "/v1/access-requests", map[string]any{
		"paths": paths, "action": "read_value", "reason": reason, "ttl": ttl,
	}, &rq)
	if err != nil {
		return err
	}
	if code == http.StatusOK {
		fmt.Fprintln(os.Stderr, "An identical request is already pending; showing it.")
	}
	printRequest(rq)
	if !wait {
		return nil
	}
	return waitForDecision(rq)
}

// cmdRequestStatus prints one request and what to do next.
func cmdRequestStatus(args []string) error {
	if len(args) != 1 || !requestIDPattern.MatchString(args[0]) {
		return fmt.Errorf("usage: phoenix request status <req_id>")
	}
	if err := requireBootstrapAuth(); err != nil {
		return err
	}
	var rq accessRequestView
	if _, err := apiJSON("GET", "/v1/access-requests/"+args[0], nil, &rq); err != nil {
		return err
	}
	printRequest(rq)
	return nil
}

// printRequest shows a request's state for the agent that asked.
func printRequest(rq accessRequestView) {
	fmt.Printf("Request: %s\n", cleanServerText(rq.ID))
	fmt.Printf("Status:  %s\n", cleanServerText(rq.Status))
	fmt.Printf("Paths:   %s\n", cleanList(rq.Paths, ", "))
	if len(rq.GrantedPaths) > 0 {
		fmt.Printf("Granted: %s until %s\n", cleanList(rq.GrantedPaths, ", "), cleanServerText(rq.GrantExpiresAt))
	}
	if rq.Note != "" {
		fmt.Printf("Note:    %s\n", cleanServerText(rq.Note))
	}
	fmt.Printf("Next:    %s\n", requestNextHint(rq))
}

// requestNextHint is the client-authored "what now" for a request. For an
// active grant it names the exact phoenix exec command.
func requestNextHint(rq accessRequestView) string {
	if rq.NextStep == "use_exec" && len(rq.GrantedPaths) > 0 {
		if p := hintPath(rq.GrantedPaths[0]); p != "" {
			return "phoenix exec --redact-output --env NAME=phoenix://" + p + " -- <command>"
		}
	}
	return nextStepHint(rq.NextStep)
}

// waitForDecision polls a request every 5s until it is decided or expires.
// A deny or expiry is returned as an error so scripts can tell.
func waitForDecision(rq accessRequestView) error {
	// The id comes from the server and is reused in a URL: accept only the
	// real format.
	if !requestIDPattern.MatchString(rq.ID) {
		return fmt.Errorf("server returned an invalid request id %q", cleanServerText(rq.ID))
	}
	id := rq.ID
	deadline := time.Now().Add(16 * time.Minute)
	if t, err := time.Parse(time.RFC3339, rq.ExpiresAt); err == nil {
		deadline = t.Add(5 * time.Second)
	}
	fmt.Fprintln(os.Stderr, "Waiting for a human to decide...")
	for rq.Status == "pending" {
		if time.Now().After(deadline) {
			return fmt.Errorf("request %s was not decided in time", id)
		}
		time.Sleep(5 * time.Second)
		var next accessRequestView
		if _, err := apiJSON("GET", "/v1/access-requests/"+id, nil, &next); err != nil {
			fmt.Fprintf(os.Stderr, "  poll error: %v\n", err)
			continue
		}
		// Keep polling the id we validated; a reply about another id is
		// a broken or hostile server.
		if next.ID != id {
			return fmt.Errorf("server answered for a different request id %q", cleanServerText(next.ID))
		}
		rq = next
	}
	printRequest(rq)
	if rq.Status != "approved" {
		return fmt.Errorf("request %s %s", id, cleanServerText(rq.Status))
	}
	return nil
}

// cmdWhoami prints who the server thinks this CLI is, its ACL rules, its
// active grants and pending requests.
func cmdWhoami(args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}
	var w struct {
		Agent      string `json:"agent"`
		AuthMethod string `json:"auth_method"`
		SourceIP   string `json:"source_ip"`
		ACL        []struct {
			Path    string   `json:"path"`
			Actions []string `json:"actions"`
		} `json:"acl"`
		Session *struct {
			Role       string   `json:"role"`
			Namespaces []string `json:"namespaces"`
			Actions    []string `json:"actions"`
		} `json:"session"`
		Grants []struct {
			ID        string   `json:"id"`
			Paths     []string `json:"paths"`
			Action    string   `json:"action"`
			ExpiresAt string   `json:"expires_at"`
		} `json:"grants"`
		Pending []struct {
			ID        string   `json:"id"`
			Paths     []string `json:"paths"`
			ExpiresAt string   `json:"expires_at"`
		} `json:"pending_requests"`
		Access struct {
			Enabled           bool `json:"enabled"`
			SealedRequired    bool `json:"sealed_required"`
			SealKeyRegistered bool `json:"seal_key_registered"`
		} `json:"access_requests"`
	}
	if _, err := apiJSON("GET", "/v1/whoami", nil, &w); err != nil {
		return err
	}
	fmt.Printf("Agent:     %s (%s from %s)\n", cleanServerText(w.Agent), cleanServerText(w.AuthMethod), cleanServerText(w.SourceIP))
	if w.Session != nil {
		fmt.Printf("Session:   role %s, %s on %s\n", cleanServerText(w.Session.Role),
			cleanList(w.Session.Actions, ","), cleanList(w.Session.Namespaces, ", "))
		fmt.Println("           Grants are used through the agent's own identity, not a session.")
	}
	for _, r := range w.ACL {
		fmt.Printf("ACL:       %s  %s\n", cleanPath(r.Path), cleanList(r.Actions, ","))
	}
	for _, g := range w.Grants {
		fmt.Printf("Grant:     %s  %s  %s until %s\n", cleanServerText(g.ID), cleanList(g.Paths, ", "),
			cleanServerText(g.Action), cleanServerText(g.ExpiresAt))
	}
	for _, p := range w.Pending {
		fmt.Printf("Pending:   %s  %s (expires %s)\n", cleanServerText(p.ID), cleanList(p.Paths, ", "), cleanServerText(p.ExpiresAt))
	}
	fmt.Printf("Requests:  enabled=%v sealed_required=%v seal_key_registered=%v\n",
		w.Access.Enabled, w.Access.SealedRequired, w.Access.SealKeyRegistered)
	return nil
}

// cmdPending lists step-up approvals AND access requests waiting for a
// human. A section the caller may not see is reported, not fatal.
func cmdPending(args []string) error {
	if err := requireBootstrapAuth(); err != nil {
		return err
	}
	var steps struct {
		Approvals []struct {
			ID        string `json:"id"`
			Role      string `json:"role"`
			Agent     string `json:"agent"`
			SourceIP  string `json:"source_ip"`
			ExpiresAt string `json:"expires_at"`
		} `json:"approvals"`
	}
	fmt.Println("Step-up approvals:")
	if _, err := apiJSON("GET", "/v1/approvals", nil, &steps); err != nil {
		fmt.Printf("  (not available: %s)\n", oneLine(err))
	} else if len(steps.Approvals) == 0 {
		fmt.Println("  none")
	}
	for _, a := range steps.Approvals {
		fmt.Printf("  %s  role=%s agent=%s ip=%s expires=%s\n", cleanServerText(a.ID), cleanServerText(a.Role),
			cleanServerText(a.Agent), cleanServerText(a.SourceIP), cleanServerText(a.ExpiresAt))
	}
	var reqs struct {
		Requests []accessRequestView `json:"requests"`
	}
	fmt.Println("Access requests:")
	if _, err := apiJSON("GET", "/v1/access-requests?status=pending", nil, &reqs); err != nil {
		fmt.Printf("  (not available: %s)\n", oneLine(err))
	} else if len(reqs.Requests) == 0 {
		fmt.Println("  none")
	}
	for _, r := range reqs.Requests {
		fmt.Printf("  %s  agent=%s %s ttl=%s expires=%s\n", cleanServerText(r.ID), cleanServerText(r.Agent),
			cleanServerText(r.Action), cleanServerText(r.RequestedTTL), cleanServerText(r.ExpiresAt))
		for _, p := range r.Paths {
			fmt.Printf("      %s\n", cleanPath(p))
		}
	}
	return nil
}

// oneLine flattens an error for an indented list.
func oneLine(err error) string {
	return strings.Join(strings.Fields(err.Error()), " ")
}

// cmdApprove dispatches on the ID prefix: req_ is an access request, any
// other ID keeps the original step-up flow (cmdApproveStepUp) unchanged.
func cmdApprove(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: phoenix approve <apr_id|req_id> [--ttl 15m] [--path p ...] [--yes]")
	}
	if strings.HasPrefix(args[0], "req_") {
		return cmdApproveAccess(args)
	}
	return cmdApproveStepUp(args)
}

// cmdApproveAccess approves an access request after showing every path,
// the action, TTL and the agent's (unverified) reason. --path narrows the
// grant, --ttl shortens it. --yes skips the y/N prompt; without it the
// answer is read from /dev/tty, or stdin when there is no terminal (same
// as the step-up approve).
func cmdApproveAccess(args []string) error {
	id := args[0]
	if !requestIDPattern.MatchString(id) {
		return fmt.Errorf("invalid request id %q", cleanServerText(id))
	}
	var paths []string
	var ttl string
	yes := false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--path":
			if i+1 >= len(args) {
				return fmt.Errorf("--path needs a value")
			}
			i++
			paths = append(paths, args[i])
		case "--ttl":
			if i+1 >= len(args) {
				return fmt.Errorf("--ttl needs a duration like 15m")
			}
			i++
			ttl = args[i]
		case "--yes", "-y":
			yes = true
		default:
			return fmt.Errorf("unknown argument %s", args[i])
		}
	}
	if err := requireBootstrapAuth(); err != nil {
		return err
	}
	var rq accessRequestView
	if _, err := apiJSON("GET", "/v1/access-requests/"+id, nil, &rq); err != nil {
		return err
	}
	if rq.Status != "pending" {
		return fmt.Errorf("request %s is already %s", id, cleanServerText(rq.Status))
	}
	fmt.Fprint(os.Stderr, approvalPrompt(rq, paths, ttl))
	if !yes {
		fmt.Fprint(os.Stderr, "\nApprove? [y/N]: ")
		answer, err := readFromTTY()
		if err != nil {
			return fmt.Errorf("reading confirmation: %w", err)
		}
		if a := strings.TrimSpace(strings.ToLower(answer)); a != "y" && a != "yes" {
			fmt.Fprintln(os.Stderr, "Not approved. The request stays pending; use phoenix deny to refuse it.")
			return nil
		}
	}
	body := map[string]any{}
	if paths != nil {
		body["paths"] = paths
	}
	if ttl != "" {
		body["ttl"] = ttl
	}
	var res struct {
		GrantID   string   `json:"grant_id"`
		Paths     []string `json:"paths"`
		ExpiresAt string   `json:"expires_at"`
	}
	if _, err := apiJSON("POST", "/v1/access-requests/"+id+"/approve", body, &res); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Approved: grant %s for %s until %s\n", cleanServerText(res.GrantID),
		cleanList(res.Paths, ", "), cleanServerText(res.ExpiresAt))
	return nil
}

// approvalPrompt is the text shown before a y/N on an access request. It
// lists every path in full (marking ones --path removes), the action, the
// TTL that will be granted and the reason, labelled as unverified.
func approvalPrompt(rq accessRequestView, keep []string, ttl string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\nAccess request %s\n", cleanServerText(rq.ID))
	fmt.Fprintf(&b, "  Agent:   %s (%s from %s)\n", cleanServerText(rq.Agent), cleanServerText(rq.AuthMethod), cleanServerText(rq.SourceIP))
	fmt.Fprintf(&b, "  Action:  %s\n", cleanServerText(rq.Action))
	fmt.Fprintln(&b, "  Paths:")
	for _, p := range rq.Paths {
		mark := "+"
		if keep != nil && !containsString(keep, p) {
			mark = "-" // removed by --path
		}
		note := ""
		if containsString(rq.AlreadyAllowedPaths, p) {
			note = "  (already allowed)"
		}
		fmt.Fprintf(&b, "    %s %s%s\n", mark, cleanPath(p), note)
	}
	if ttl == "" {
		ttl = rq.RequestedTTL
	}
	fmt.Fprintf(&b, "  TTL:     %s (requested %s)\n", cleanServerText(ttl), cleanServerText(rq.RequestedTTL))
	fmt.Fprintf(&b, "  Agent says (not verified): %s\n", cleanServerText(rq.Reason))
	fmt.Fprintln(&b, "  Revoking later does not recall a value already used.")
	return b.String()
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// cmdDeny dispatches on the ID prefix: req_ denies an access request (with
// an optional --note), anything else denies a step-up approval.
func cmdDeny(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: phoenix deny <apr_id|req_id> [--note \"...\"]")
	}
	id := args[0]
	note := ""
	for i := 1; i < len(args); i++ {
		if args[i] == "--note" && i+1 < len(args) {
			i++
			note = args[i]
			continue
		}
		return fmt.Errorf("unknown argument %s", args[i])
	}
	if err := requireBootstrapAuth(); err != nil {
		return err
	}
	if strings.HasPrefix(id, "req_") {
		if !requestIDPattern.MatchString(id) {
			return fmt.Errorf("invalid request id %q", cleanServerText(id))
		}
		if _, err := apiJSON("POST", "/v1/access-requests/"+id+"/deny", map[string]string{"note": note}, nil); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Denied %s. The agent cannot ask for those paths again for 10 minutes.\n", id)
		return nil
	}
	if !approvalIDPattern.MatchString(id) {
		return fmt.Errorf("invalid approval id %q", cleanServerText(id))
	}
	if note != "" {
		return fmt.Errorf("--note is only supported for access requests (req_...)")
	}
	if _, err := apiJSON("POST", "/v1/approval/"+id+"/deny", map[string]string{}, nil); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Session denied.")
	return nil
}

// cmdGrants handles "phoenix grants [--all] [--agent name]" and
// "phoenix grants revoke <gnt_id>". Approvers see every agent's grants,
// anyone else only their own.
func cmdGrants(args []string) error {
	if len(args) > 0 && args[0] == "revoke" {
		if len(args) != 2 || !grantIDPattern.MatchString(args[1]) {
			return fmt.Errorf("usage: phoenix grants revoke <gnt_id>")
		}
		if err := requireBootstrapAuth(); err != nil {
			return err
		}
		if _, err := apiJSON("POST", "/v1/grants/"+args[1]+"/revoke", nil, nil); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Revoked %s. A value already delivered is not recalled; rotate the secret if that matters.\n", args[1])
		return nil
	}
	q := url.Values{}
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--all":
			q.Set("include", "inactive")
		case args[i] == "--agent" && i+1 < len(args):
			i++
			q.Set("agent", args[i])
		default:
			return fmt.Errorf("usage: phoenix grants [--all] [--agent <name>] | phoenix grants revoke <gnt_id>")
		}
	}
	if err := requireBootstrapAuth(); err != nil {
		return err
	}
	path := "/v1/grants"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var res struct {
		Grants []grantView `json:"grants"`
	}
	if _, err := apiJSON("GET", path, nil, &res); err != nil {
		return err
	}
	if len(res.Grants) == 0 {
		fmt.Println("No grants.")
		return nil
	}
	for _, g := range res.Grants {
		last := g.LastUsedAt
		if last == "" {
			last = "never"
		}
		fmt.Printf("%s  %-8s  agent=%s  %s  expires=%s  uses=%d  last=%s\n", cleanServerText(g.ID), cleanServerText(g.State),
			cleanServerText(g.Agent), cleanServerText(g.Action), cleanServerText(g.ExpiresAt), g.UseCount, cleanServerText(last))
		for _, p := range g.Paths {
			fmt.Printf("    %s\n", cleanPath(p))
		}
	}
	return nil
}
