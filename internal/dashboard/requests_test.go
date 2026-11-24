package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/grant"
	"github.com/phoenixsec/phoenix/internal/policy"
)

// answer taps one button on a request's card, as the plain form does.
func (e *accessEnv) answer(t *testing.T, id, choice string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	if form == nil {
		form = url.Values{"path": {"infra/a"}}
	}
	form.Set("choice", choice)
	return e.post(t, "/dashboard/requests/"+id+"/answer", form, true)
}

// feed polls like requests.js does.
func (e *accessEnv) feed(t *testing.T, rev string) (int, requestFeed) {
	t.Helper()
	req := httptest.NewRequest("GET", "/dashboard/requests/feed?page=1&rev="+rev, nil)
	req.AddCookie(e.cookie)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	var f requestFeed
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &f); err != nil {
			t.Fatal(err)
		}
	}
	return w.Code, f
}

func (e *accessEnv) canRead(path string) bool {
	return e.acl.Authorize("courier", path, acl.ActionReadValue) == nil
}

func TestRequestCardShowsFacts(t *testing.T) {
	e := newAccessEnv(t)
	rq := e.request(t, "backup job fails auth <script>alert(1)</script> \u202Etxt.exe\u200B", 30*time.Minute, "infra/a", "dev/db", "infra/missing")
	page := e.get(t, "/dashboard/requests")
	for _, want := range []string{
		`id="` + rq.ID + `"`, "May courier use 3 secrets?", "10.0.0.5", "Agent says (not verified)",
		"&lt;script&gt;alert(1)&lt;/script&gt;", "does not exist", "hidden from this agent", "already allowed",
		">No</button>", ">Once</button>", ">15 minutes</button>", ">Always</button>",
		"Taking access back later does not recall a value already handed over.",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("card missing %q", want)
		}
	}
	if strings.ContainsAny(page, "\u202E\u200B") || strings.Contains(page, "<script>alert") {
		t.Error("the agent's reason reached the page unescaped or with hidden characters")
	}
}

func TestAnswers(t *testing.T) {
	cases := []struct {
		choice    string
		form      url.Values
		ttl       time.Duration
		uses      int64
		requested time.Duration
	}{
		{"once", nil, 30 * time.Minute, 1, 30 * time.Minute},
		{"time", nil, 15 * time.Minute, 0, 30 * time.Minute},
		{"time", nil, 5 * time.Minute, 0, 5 * time.Minute}, // never longer than asked
		{"custom", url.Values{"path": {"infra/a"}, "ttl": {"5m"}, "uses": {"3"}}, 5 * time.Minute, 3, 30 * time.Minute},
		{"custom", url.Values{"path": {"infra/a"}, "ttl": {"30m"}, "uses": {""}}, 30 * time.Minute, 0, 30 * time.Minute},
	}
	for _, c := range cases {
		e := newAccessEnv(t)
		rq := e.request(t, "why", c.requested, "infra/a", "infra/b")
		if code := redirectParam(t, e.answer(t, rq.ID, c.choice, c.form), "error"); code != "" {
			t.Fatalf("%s: %s", c.choice, code)
		}
		got, _ := e.gs.GetRequest(rq.ID)
		g, _ := e.gs.GetGrant(got.GrantID)
		if !slices.Equal(g.Paths, []string{"infra/a"}) || g.ExpiresAt.Sub(g.CreatedAt) != c.ttl || g.MaxUses != c.uses ||
			g.ApprovedBy != "dashboard@192.0.2.9" || !g.SealedOnly || e.canRead("infra/a") {
			t.Errorf("%s: grant = %+v", c.choice, g)
		}
	}
}

func TestAnswerNo(t *testing.T) {
	e := newAccessEnv(t)
	rq := e.request(t, "why", 30*time.Minute, "infra/a")
	if code := redirectParam(t, e.answer(t, rq.ID, "no", url.Values{"note": {"not today"}}), "error"); code != "" {
		t.Fatal(code)
	}
	got, _ := e.gs.GetRequest(rq.ID)
	if got.Status != grant.StatusDenied || got.Note != "not today" || got.DecidedBy != "dashboard@192.0.2.9" {
		t.Fatalf("request = %+v", got)
	}
}

func TestAnswerAlwaysAndRemove(t *testing.T) {
	e := newAccessEnv(t)
	rq := e.request(t, "why", 30*time.Minute, "infra/a", "infra/b")
	if code := redirectParam(t, e.answer(t, rq.ID, "always", nil), "error"); code != "" {
		t.Fatal(code)
	}
	// Exactly the ticked path, reading only.
	if !e.canRead("infra/a") || e.canRead("infra/b") || e.canRead("infra/a/x") ||
		e.acl.Authorize("courier", "infra/a", acl.ActionWrite) == nil || e.acl.Authorize("courier", "infra/a", acl.ActionList) == nil {
		t.Fatal("always did not add exactly read_value on infra/a")
	}
	page := e.get(t, "/dashboard/requests")
	if !strings.Contains(page, `name="path" value="infra/a"`) || !strings.Contains(page, "Always, by dashboard@192.0.2.9") {
		t.Fatal("always entry not on the page")
	}
	remove := url.Values{"agent": {"courier"}, "path": {"infra/a"}, "request": {rq.ID}}
	stale := url.Values{"agent": {"courier"}, "path": {"infra/a"}, "request": {"req_older"}}
	if code := redirectParam(t, e.post(t, "/dashboard/requests/always/remove", stale, true), "error"); code != "NOT_FOUND" || !e.canRead("infra/a") {
		t.Fatalf("an old page removed a newer answer: %q", code)
	}
	if w := e.post(t, "/dashboard/requests/always/remove", remove, false); w.Code != http.StatusForbidden {
		t.Fatalf("remove without CSRF: %d", w.Code)
	}
	if code := redirectParam(t, e.post(t, "/dashboard/requests/always/remove", remove, true), "error"); code != "" {
		t.Fatal(code)
	}
	if e.canRead("infra/a") {
		t.Fatal("removed access still reads")
	}
	// A replayed "always" answers the same and must not put it back.
	if code := redirectParam(t, e.answer(t, rq.ID, "always", nil), "error"); code != "" {
		t.Fatal(code)
	}
	if e.canRead("infra/a") {
		t.Fatal("a replayed answer put removed access back")
	}
	if !strings.Contains(e.get(t, "/dashboard/requests"), "removed since") {
		t.Fatal("history does not say the access was removed")
	}
}

// Several people (or taps) answer one request at once: one answer wins, and the
// agent holds exactly what that answer gives.
func TestAnswersAtOnce(t *testing.T) {
	for range 10 {
		e := newAccessEnv(t)
		rq := e.request(t, "why", 30*time.Minute, "infra/a")
		var wg sync.WaitGroup
		for _, choice := range []string{"no", "once", "time", "always", "once", "always"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				form := url.Values{"path": {"infra/a"}, "choice": {choice}, "_csrf": {e.csrf}}
				req := httptest.NewRequest("POST", "/dashboard/requests/"+rq.ID+"/answer", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.AddCookie(e.cookie)
				e.h.ServeHTTP(httptest.NewRecorder(), req)
			}()
		}
		wg.Wait()
		got, _ := e.gs.GetRequest(rq.ID)
		grants := e.gs.ListGrants("courier", false)
		wantGrants := 0
		if got.Status == grant.StatusApproved && !got.Always {
			wantGrants = 1
		}
		if got.Status == grant.StatusPending || len(grants) != wantGrants || e.canRead("infra/a") != got.Always {
			t.Fatalf("request %s always=%v, %d grants, can read %v", got.Status, got.Always, len(grants), e.canRead("infra/a"))
		}
	}
}

func TestAnswerRefusals(t *testing.T) {
	e := newAccessEnv(t)
	rq := e.request(t, "why", 30*time.Minute, "infra/a")
	expect := func(want, choice string, form url.Values) {
		t.Helper()
		if code := redirectParam(t, e.answer(t, rq.ID, choice, form), "error"); code != want {
			t.Errorf("%s: error = %q, want %q", choice, code, want)
		}
	}
	expect("INVALID_REQUEST", "forever", nil)
	expect("INVALID_REQUEST", "", nil)
	expect("WIDENING_NOT_ALLOWED", "always", url.Values{"path": {"infra/a", "infra/b"}})
	expect("WIDENING_NOT_ALLOWED", "once", url.Values{"path": {"infra/b"}})
	expect("INVALID_REQUEST", "always", url.Values{"path": {"infra/*"}})
	for _, choice := range []string{"once", "time", "always", "custom"} {
		expect("EMPTY_GRANT", choice, url.Values{})
	}
	for _, ttl := range []string{"1h", "10m", "30s", "", "forever"} {
		expect("INVALID_TTL", "custom", url.Values{"path": {"infra/a"}, "ttl": {ttl}})
	}
	for _, uses := range []string{"0", "-1", "1001", "two", "1.5"} {
		expect("INVALID_USES", "custom", url.Values{"path": {"infra/a"}, "ttl": {"5m"}, "uses": {uses}})
	}
	// Refused by today's config, whatever it was when the agent asked.
	cfg := e.cfg
	cfg.DenyPaths = []string{"infra/**"}
	e.srv.SetAccessRequests(cfg)
	for _, choice := range []string{"once", "time", "always"} {
		expect("NOT_REQUESTABLE", choice, nil)
	}
	e.srv.SetAccessRequests(e.cfg)
	if w := e.post(t, "/dashboard/requests/"+rq.ID+"/answer", url.Values{"choice": {"always"}, "path": {"infra/a"}}, false); w.Code != http.StatusForbidden {
		t.Errorf("answer without CSRF: %d", w.Code)
	}
	// The token that asked was replaced: no answer but No reaches anybody.
	if err := e.acl.UpdateAgent("courier", "another-token", nil); err != nil {
		t.Fatal(err)
	}
	for _, choice := range []string{"once", "time", "always"} {
		expect("CREDENTIAL_CHANGED", choice, nil)
	}
	if !strings.Contains(e.get(t, "/dashboard/requests"), "token was replaced after it asked") {
		t.Error("card does not say the token changed")
	}
	e.acl.RemoveAgent("courier")
	expect("UNKNOWN_AGENT", "always", nil)
	if got, _ := e.gs.GetRequest(rq.ID); got.Status != grant.StatusPending || e.canRead("infra/a") {
		t.Fatalf("request = %s", got.Status)
	}
	expect("", "no", url.Values{})
}

func TestSSHLoginCard(t *testing.T) {
	e := newAccessEnv(t)
	pe, err := policy.Load([]byte(`{"attestation": {"ssh/*": {"source_ip": ["10.9.9.9"]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	e.h.deps.Policy = pe
	login := e.h.card(grant.Request{ID: "req_x", Agent: "courier", Action: grant.ActionSSHLogin, Paths: []string{"ssh/build-1"}, RequestedTTL: time.Hour}, "")
	if login.Machine != "build-1" || login.AlwaysOK || len(login.Attest) != 0 {
		t.Fatalf("login card = %+v", login)
	}
	html := string(e.h.fragment("request-card", login))
	if !strings.Contains(html, "Once issues one certificate") || !strings.Contains(html, "root login on <strong>build-1</strong>") || strings.Contains(html, `value="always"`) || !strings.Contains(html, `value="once"`) {
		t.Fatalf("login card html:\n%s", html)
	}
	secret := e.h.card(grant.Request{ID: "req_y", Agent: "courier", Action: grant.ActionReadValue, Paths: []string{"ssh/build-1"}, RequestedTTL: time.Hour}, "")
	if secret.Machine != "" || !secret.AlwaysOK || len(secret.Attest) == 0 {
		t.Fatalf("a secret at the same path must keep its normal card: %+v", secret)
	}
}

func TestRequestFeed(t *testing.T) {
	e := newAccessEnv(t)
	code, f := e.feed(t, "")
	if code != http.StatusOK || len(f.Waiting) != 0 {
		t.Fatalf("empty feed: %d %+v", code, f)
	}
	if code, _ := e.feed(t, f.Rev); code != http.StatusNoContent {
		t.Fatalf("unchanged feed: %d, want 204", code)
	}
	rq := e.request(t, "why", 30*time.Minute, "infra/a")
	code, f = e.feed(t, f.Rev)
	if code != http.StatusOK || len(f.Waiting) != 1 || f.Waiting[0].ID != rq.ID || !strings.Contains(string(f.Waiting[0].HTML), `data-request="`+rq.ID+`"`) {
		t.Fatalf("feed with a request: %d %+v", code, f)
	}
	if code, _ := e.feed(t, f.Rev); code != http.StatusNoContent {
		t.Fatal("a waiting card must not change the feed by itself")
	}
	e.answer(t, rq.ID, "no", nil)
	_, f = e.feed(t, f.Rev)
	if len(f.Waiting) != 0 || len(f.Ended) != 1 || f.Ended[0].ID != rq.ID || f.Ended[0].State != "denied" {
		t.Fatalf("feed after no: %+v", f)
	}
	// An open tab is not someone using the dashboard.
	mid := e.h.logins.list(time.Now())[0].LastUsed
	e.feed(t, "")
	if after := e.h.logins.list(time.Now())[0].LastUsed; !after.Equal(mid) {
		t.Fatal("polling counted as using the dashboard")
	}
	req := httptest.NewRequest("GET", "/dashboard/requests/feed", nil)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("feed without a login: %d", w.Code)
	}
}

// Removing an "always" says so when something else still lets the agent read.
func TestRemoveSaysWhatIsLeft(t *testing.T) {
	done := func(prepare func(e *accessEnv)) string {
		e := newAccessEnv(t)
		prepare(e)
		rq := e.request(t, "always", 30*time.Minute, "infra/a", "infra/b")
		if code := redirectParam(t, e.answer(t, rq.ID, "always", nil), "error"); code != "" {
			t.Fatal(code)
		}
		w := e.post(t, "/dashboard/requests/always/remove", url.Values{"agent": {"courier"}, "path": {"infra/a"}, "request": {rq.ID}}, true)
		return redirectParam(t, w, "done")
	}
	if got := done(func(*accessEnv) {}); got != "removed" {
		t.Errorf("nothing left: %q", got)
	}
	if got := done(func(e *accessEnv) {
		e.answer(t, e.request(t, "timed", 30*time.Minute, "infra/a").ID, "time", nil)
	}); got != "removed-open" {
		t.Errorf("open grant: %q", got)
	}
	if got := done(func(e *accessEnv) {
		e.acl.UpdateAgent("courier", "courier-token", []acl.Permission{{Path: "infra/*", Actions: []acl.Action{acl.ActionReadValue}}})
	}); got != "removed-still" {
		t.Errorf("another rule: %q", got)
	}
}

func TestExpiredStaysVisible(t *testing.T) {
	e := newAccessEnv(t)
	rq := e.request(t, "why", 30*time.Minute, "infra/a")
	row, badge, _ := e.h.outcome(grant.Request{ID: rq.ID, Status: grant.StatusExpired, ExpiresAt: rq.ExpiresAt}, time.Now())
	if badge != "expired" || !strings.Contains(row, "nobody answered") {
		t.Fatalf("outcome = %q %q", row, badge)
	}
	if _, err := e.gs.DeleteAgent("courier", "admin", "", nil); err != nil { // expires it
		t.Fatal(err)
	}
	if page := e.get(t, "/dashboard/requests/"+rq.ID); !strings.Contains(page, "status-expired") || strings.Contains(page, `value="once"`) {
		t.Fatal("an expired request must stay on the page, marked, with no buttons")
	}
}

func TestRevokeOnRequestsPage(t *testing.T) {
	e := newAccessEnv(t)
	rq := e.request(t, "why", 30*time.Minute, "infra/a")
	_, g, err := e.srv.ApproveAccessRequestAs(rq.ID, "dashboard@test", "127.0.0.1", grant.Approval{})
	if err != nil {
		t.Fatal(err)
	}
	action := "/dashboard/requests/grants/" + g.ID + "/revoke"
	if !strings.Contains(e.get(t, "/dashboard/requests"), action) {
		t.Fatal("active grant has no Revoke")
	}
	if w := e.post(t, action, nil, false); w.Code != http.StatusForbidden {
		t.Fatalf("revoke without CSRF: %d", w.Code)
	}
	if code := redirectParam(t, e.post(t, action, nil, true), "error"); code != "" {
		t.Fatal(code)
	}
	got, _ := e.gs.GetGrant(g.ID)
	if got.State(time.Now()) != grant.GrantRevoked || got.RevokedBy != "dashboard@192.0.2.9" {
		t.Fatalf("grant %s by %q", got.State(time.Now()), got.RevokedBy)
	}
}

func TestRevokeNotDurableShownInRed(t *testing.T) {
	e := newAccessEnv(t)
	rq := e.request(t, "why", 30*time.Minute, "infra/a")
	_, g, err := e.srv.ApproveAccessRequestAs(rq.ID, "dashboard@test", "127.0.0.1", grant.Approval{})
	if err != nil {
		t.Fatal(err)
	}
	e.fs.fail.Store(true)
	w := e.post(t, "/dashboard/requests/grants/"+g.ID+"/revoke", nil, true)
	if page := e.get(t, w.Header().Get("Location")); !strings.Contains(page, `flash-error flash-sticky">REVOKE_NOT_DURABLE`) {
		t.Fatal("REVOKE_NOT_DURABLE not shown in red")
	}
	if page := e.get(t, "/dashboard/"); !strings.Contains(page, "Access requests degraded") {
		t.Fatal("overview does not show degraded state")
	}
	// The Revoke to try again with is still there, and works once the disk does.
	action := "/dashboard/requests/grants/" + g.ID + "/revoke"
	if page := e.get(t, "/dashboard/requests"); !strings.Contains(page, action) || !strings.Contains(page, "revoke again") {
		t.Fatal("no way to retry the revoke")
	}
	e.fs.fail.Store(false)
	if code := redirectParam(t, e.post(t, action, nil, true), "error"); code != "" {
		t.Fatal(code)
	}
	if strings.Contains(e.get(t, "/dashboard/requests"), action) {
		t.Fatal("still listed after it was saved")
	}
}

func TestOldAddressesAndCraftedLinks(t *testing.T) {
	e := newAccessEnv(t)
	for old, want := range map[string]string{"/dashboard/approvals": "/dashboard/requests", "/dashboard/grants": "/dashboard/requests#active"} {
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, httptest.NewRequest("GET", old, nil))
		if w.Code != http.StatusFound || w.Header().Get("Location") != want {
			t.Errorf("%s -> %d %q", old, w.Code, w.Header().Get("Location"))
		}
	}
	page := e.get(t, "/dashboard/requests?error="+url.QueryEscape("Safe to approve")+"&done="+url.QueryEscape("Safe to approve"))
	if strings.Contains(page, "Safe to approve") {
		t.Fatal("text from the URL was rendered")
	}
	if page := e.get(t, "/dashboard/"); !strings.Contains(page, `href="/dashboard/requests"`) || strings.Contains(page, "/dashboard/grants") {
		t.Fatal("navigation still has the old pages")
	}
}

// A notification link ends at its request: through the login page, and past the
// login cookie a browser holds back on a link from another site.
func TestNotificationLinkReachesTheRequest(t *testing.T) {
	e := newAccessEnv(t)
	rq := e.request(t, "why", 30*time.Minute, "infra/a")
	link := "/dashboard/requests/" + rq.ID
	get := func(path, fetchSite string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Sec-Fetch-Site", fetchSite)
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, req)
		return w
	}
	if w := get(link, "cross-site"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "url="+link) {
		t.Fatalf("link from another site: %d %s", w.Code, w.Body.String())
	}
	w := get(link, "none")
	if want := "/dashboard/login?next=" + url.QueryEscape(link); w.Header().Get("Location") != want {
		t.Fatalf("redirect = %q, want %q", w.Header().Get("Location"), want)
	}
	if page := get(w.Header().Get("Location"), "none").Body.String(); !strings.Contains(page, `name="next" value="`+link+`"`) {
		t.Fatal("login form lost the request")
	}
	logIn := func(next string) string {
		form := url.Values{"credential": {"testpass"}, "next": {next}}
		req := httptest.NewRequest("POST", "/dashboard/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, req)
		return w.Header().Get("Location")
	}
	if got := logIn(link); got != link {
		t.Fatalf("after login: %q", got)
	}
	for _, bad := range []string{"https://evil.example/", "//evil.example", "/dashboard/requests/../../x", "/dashboard/requests/req_x", "/dashboard/requests//evil.example"} {
		if got := logIn(bad); got != "/dashboard/" {
			t.Errorf("next %q sent the browser to %q", bad, got)
		}
	}
}

func TestOverviewPendingAccessBadge(t *testing.T) {
	e := newAccessEnv(t)
	e.request(t, "why", 30*time.Minute, "infra/a")
	page := e.get(t, "/dashboard/")
	if !strings.Contains(page, "Access Requests") || !strings.Contains(page, `data-requests-badge>1</span>`) {
		t.Fatal("overview missing access request count / nav badge")
	}
}
