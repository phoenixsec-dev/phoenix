package dashboard

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/audit"
	"github.com/phoenixsec/phoenix/internal/config"
	"github.com/phoenixsec/phoenix/internal/crypto"
	"github.com/phoenixsec/phoenix/internal/policy"
	"github.com/phoenixsec/phoenix/internal/store"

	"golang.org/x/crypto/bcrypt"
)

const fakeValue = "fake-value-for-tests-only"

// revealOn is a config whose owner turned showing secrets on.
var revealOn = config.DashboardConfig{Reveal: true}

// secretsEnv is a signed-in dashboard over a real store holding one secret,
// shop/petstore, with a username and link.
type secretsEnv struct {
	h      *Handler
	store  *store.Store
	audit  *bytes.Buffer
	cookie *http.Cookie
	csrf   string
}

func newSecretsEnv(t *testing.T, cfg config.DashboardConfig, rules string) *secretsEnv {
	t.Helper()
	mk, err := crypto.GenerateAndSaveMasterKey(filepath.Join(t.TempDir(), "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.New(filepath.Join(t.TempDir(), "store.json"), mk)
	if err != nil {
		t.Fatal(err)
	}
	user, link, desc := "me@example.com", "https://shop.example.com/login", "Pet shop account"
	if err := st.Write("shop/petstore", fakeValue, "maker", store.MetadataChange{
		Description: &desc, Username: &user, URL: &link, Tags: &[]string{"shopping"}}, store.WriteNew); err != nil {
		t.Fatal(err)
	}
	a := acl.NewFromConfig(&acl.ACLConfig{Agents: map[string]acl.Agent{}})
	a.AddAgent("shopper", "shopper-token", []acl.Permission{{Path: "shop/*", Actions: []acl.Action{acl.ActionReadValue}}})
	a.AddAgent("other", "other-token", []acl.Permission{{Path: "shop/*", Actions: []acl.Action{acl.ActionList}}})
	pe, err := policy.Load([]byte(rules))
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpass"), bcrypt.MinCost)
	cfg.Enabled, cfg.PasswordHash = true, string(hash)
	buf := &bytes.Buffer{}
	h, err := New(cfg, Deps{Backend: store.NewFileBackend(st), ACL: a, Policy: pe, StartTime: time.Now(), Audit: audit.NewWriterLogger(buf)})
	if err != nil {
		t.Fatal(err)
	}
	e := &secretsEnv{h: h, store: st, audit: buf, cookie: login(t, h)}
	e.csrf = csrfFromCookie(t, h, e.cookie)
	return e
}

// do sends a request with the login cookie and any extra headers.
func (e *secretsEnv) do(method, path string, form url.Values, headers ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	if e.cookie != nil {
		r.AddCookie(e.cookie)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

// post sends a form with the CSRF token. Fields are name, value pairs.
func (e *secretsEnv) post(path string, fields ...string) *httptest.ResponseRecorder {
	form := url.Values{"_csrf": {e.csrf}}
	for i := 0; i+1 < len(fields); i += 2 {
		form.Set(fields[i], fields[i+1])
	}
	return e.do("POST", path, form)
}

// age makes the password look like it was typed d ago.
func (e *secretsEnv) age(d time.Duration) {
	e.h.logins.mu.Lock()
	defer e.h.logins.mu.Unlock()
	for _, l := range e.h.logins.byNonce {
		l.authAt = time.Now().Add(-d)
	}
}

func (e *secretsEnv) showValue() *httptest.ResponseRecorder {
	return e.post("/dashboard/secrets/value", "path", "shop/petstore", "use", "show")
}

// newCookie adopts the login cookie a response set.
func (e *secretsEnv) newCookie(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == "phoenix_dash" {
			e.cookie = c
			return
		}
	}
	t.Fatal("no new cookie")
}

// No page holds a value, every page shows the login details, and the list can
// be searched by name, description, tag and username.
func TestSecretPagesNeverHoldTheValue(t *testing.T) {
	e := newSecretsEnv(t, revealOn, "")
	for _, p := range []string{"/dashboard/secrets", "/dashboard/secrets/open?path=shop/petstore", "/dashboard/secrets/new",
		"/dashboard/secrets/details?path=shop/petstore", "/dashboard/secrets/replace?path=shop/petstore", "/dashboard/more", "/dashboard/"} {
		w := e.do("GET", p, nil)
		if w.Code != http.StatusOK {
			t.Errorf("%s: %d", p, w.Code)
		}
		if strings.Contains(w.Body.String(), fakeValue) {
			t.Errorf("%s holds the value", p)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control %q", p, w.Header().Get("Cache-Control"))
		}
	}
	body := e.do("GET", "/dashboard/secrets/open?path=shop/petstore", nil).Body.String()
	for _, want := range []string{"Pet shop account", "me@example.com", "shopping", `href="https://shop.example.com/login"`, "Opens shop.example.com", "shopper", "by maker", `rel="noopener noreferrer"`} {
		if !strings.Contains(body, want) {
			t.Errorf("open page: no %q", want)
		}
	}
	if strings.Contains(body, ">other<") {
		t.Error("an agent without read_value is listed as a reader")
	}
	for q, match := range map[string]bool{"petstore": true, "PET account": true, "shopping": true, "me@example": true, "pet nothere": false} {
		hidden := strings.Contains(e.do("GET", "/dashboard/secrets?q="+url.QueryEscape(q), nil).Body.String(), `tags shopping" hidden`) ||
			strings.Contains(e.do("GET", "/dashboard/secrets?q="+url.QueryEscape(q), nil).Body.String(), `data-search="shop/petstore pet shop account me@example.com shopping" hidden`)
		if hidden == match {
			t.Errorf("search %q: hidden=%v", q, hidden)
		}
	}
	if w := e.do("GET", "/dashboard/secrets/open?path=shop/none", nil); w.Code != http.StatusNotFound {
		t.Errorf("missing secret: %d", w.Code)
	}
	if entries := parseAuditEntries(e.audit); findAuditEntry(entries, "read_value", "allowed") != nil {
		t.Error("opening pages was audited as a value read")
	}
}

// Show and copy hand out the value as no-store JSON and audit each one with
// path, address and dashboard login.
func TestShowAndCopyAreAudited(t *testing.T) {
	e := newSecretsEnv(t, revealOn, "")
	loginID := e.h.logins.list(time.Now())[0].ID
	for _, use := range []string{"show", "copy"} {
		e.audit.Reset()
		w := e.post("/dashboard/secrets/value", "path", "shop/petstore", "use", use)
		var got struct{ Value string }
		json.Unmarshal(w.Body.Bytes(), &got)
		if w.Code != http.StatusOK || got.Value != fakeValue {
			t.Fatalf("%s: %d", use, w.Code)
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "application/json" {
			t.Errorf("%s: headers %v", use, w.Header())
		}
		entry := findAuditEntry(parseAuditEntries(e.audit), "read_value", "allowed")
		if entry == nil || entry.Path != "shop/petstore" || entry.IP == "" || entry.Agent != "dashboard@"+entry.IP ||
			entry.Metadata["dashboard.login"] != loginID || entry.Metadata["dashboard.use"] != use {
			t.Errorf("%s: audit entry %+v", use, entry)
		}
		if strings.Contains(e.audit.String(), fakeValue) {
			t.Error("the audit log holds the value")
		}
	}
	if w := e.post("/dashboard/secrets/value", "path", "shop/petstore", "use", "other"); w.Code != http.StatusBadRequest {
		t.Errorf("unknown use: %d", w.Code)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// No audit line, no value.
func TestNoValueWithoutAudit(t *testing.T) {
	e := newSecretsEnv(t, revealOn, "")
	e.h.deps.Audit = audit.NewWriterLogger(failingWriter{})
	if w := e.showValue(); w.Code == http.StatusOK || strings.Contains(w.Body.String(), fakeValue) {
		t.Fatalf("value sent without an audit line: %d", w.Code)
	}
	e.h.deps.Audit = nil
	if w := e.showValue(); w.Code == http.StatusOK || strings.Contains(w.Body.String(), fakeValue) {
		t.Fatalf("value sent with no audit log: %d", w.Code)
	}
}

// Cross-site requests: no cookie, no or wrong CSRF token, a GET, and a
// request a browser marks as coming from elsewhere all get nothing.
func TestValueRefusesForgedRequests(t *testing.T) {
	e := newSecretsEnv(t, revealOn, "")
	form := url.Values{"path": {"shop/petstore"}, "use": {"show"}, "_csrf": {e.csrf}}
	try := func(name string, w *httptest.ResponseRecorder) {
		if w.Code == http.StatusOK || strings.Contains(w.Body.String(), fakeValue) {
			t.Errorf("%s: %d got through", name, w.Code)
		}
		if w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%s: CORS header set", name)
		}
	}
	for _, site := range []string{"cross-site", "same-site", "none"} {
		try("Sec-Fetch-Site "+site, e.do("POST", "/dashboard/secrets/value", form, "Sec-Fetch-Site", site))
	}
	for _, origin := range []string{"https://evil.example", "https://sibling.example.com", "null", "::"} {
		try("Origin "+origin, e.do("POST", "/dashboard/secrets/value", form, "Origin", origin))
		if w := e.do("POST", "/dashboard/logout", form, "Origin", origin); w.Code != http.StatusForbidden {
			t.Errorf("Origin %s: logout answered %d", origin, w.Code)
		}
	}
	// https dashboard (behind a TLS proxy), http page.
	try("http Origin on https", e.do("POST", "/dashboard/secrets/value", form, "Origin", "http://example.com", "X-Forwarded-Proto", "https"))
	if w := e.do("POST", "/dashboard/secrets/value", form, "Origin", "https://example.com", "X-Forwarded-Proto", "https"); w.Code != http.StatusOK {
		t.Errorf("own https request refused: %d", w.Code)
	}
	// The login form too, and a forged one costs no attempt.
	for i := 0; i < 2*loginMaxFailures; i++ {
		if w := e.do("POST", "/dashboard/login", url.Values{"credential": {"wrong"}}, "Sec-Fetch-Site", "cross-site"); w.Code != http.StatusForbidden {
			t.Fatalf("cross-site login: %d", w.Code)
		}
	}
	if w := e.do("POST", "/dashboard/login", url.Values{"credential": {"testpass"}}); w.Header().Get("Location") != "/dashboard/" {
		t.Errorf("login after forged attempts: %s", w.Header().Get("Location"))
	}
	for _, h := range [][]string{{"Sec-Fetch-Site", "same-origin"}, {"Origin", "https://example.com"}} { // httptest's host
		if w := e.do("POST", "/dashboard/secrets/value", form, h...); w.Code != http.StatusOK {
			t.Errorf("%v: own request refused: %d", h, w.Code)
		}
	}
	// A GET is not a value route at all (it falls through to the home page).
	if w := e.do("GET", "/dashboard/secrets/value?"+form.Encode(), nil); strings.Contains(w.Body.String(), fakeValue) {
		t.Error("a GET returned the value")
	}
	form.Set("_csrf", "wrong")
	try("wrong token", e.do("POST", "/dashboard/secrets/value", form))
	form.Del("_csrf")
	for _, p := range []string{"value", "new", "details", "replace"} {
		try("no token: "+p, e.do("POST", "/dashboard/secrets/"+p, form))
	}
	form.Set("_csrf", e.csrf)
	e.cookie = nil
	try("no cookie", e.do("POST", "/dashboard/secrets/value", form))
}

// Clickjacking and injected content: every response forbids framing and
// foreign scripts, and no template relies on an inline script.
func TestSecurityHeaders(t *testing.T) {
	e := newSecretsEnv(t, revealOn, "")
	for _, p := range []string{"/dashboard/login", "/dashboard/secrets", "/dashboard/requests", "/dashboard/static/secrets.js", "/dashboard/nothing"} {
		hd := e.do("GET", p, nil).Header()
		if hd.Get("X-Frame-Options") != "DENY" || !strings.Contains(hd.Get("Content-Security-Policy"), "frame-ancestors 'none'") ||
			!strings.Contains(hd.Get("Content-Security-Policy"), "script-src 'self';") || hd.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: headers %v", p, hd)
		}
	}
	inline := regexp.MustCompile(`(?i)<script>|<script [^>]*[^>s]>[^<]|\son[a-z]+="|javascript:|<style`)
	fs.WalkDir(templateFS, "templates", func(p string, d fs.DirEntry, _ error) error {
		if !d.IsDir() {
			data, _ := fs.ReadFile(templateFS, p)
			if m := inline.Find(data); m != nil {
				t.Errorf("%s: inline code the policy blocks: %s", p, m)
			}
		}
		return nil
	})
}

// A stolen or left-open login: once the password is not recent, the value
// and every change need it again; typing it opens a fixed window and moves
// the login to a new cookie, so a copied old cookie is dead.
func TestRecentPasswordIsNeeded(t *testing.T) {
	e := newSecretsEnv(t, revealOn, "")
	e.age(recentAuthWindow + time.Second)
	posts := map[string][]string{
		"value":   {"path", "shop/petstore", "use", "show"},
		"new":     {"path", "shop/new", "value", "x"},
		"details": {"path", "shop/petstore", "description", "changed"},
		"replace": {"path", "shop/petstore", "value", "x", "confirm", "yes"},
	}
	for p, fields := range posts {
		w := e.post("/dashboard/secrets/"+p, fields...)
		var got struct{ Reauth bool }
		json.Unmarshal(w.Body.Bytes(), &got)
		if w.Code != http.StatusUnauthorized || !got.Reauth {
			t.Errorf("%s with an old sign-in: %d %s", p, w.Code, w.Body)
		}
	}
	if got, _ := e.store.Get("shop/petstore"); got.Value != fakeValue || got.Metadata.Description != "Pet shop account" {
		t.Fatal("an old sign-in changed the secret")
	}

	stolen := *e.cookie
	before := payloadFromCookie(t, e.h, e.cookie)
	w := e.post("/dashboard/reauth", "password", "testpass")
	if w.Code != http.StatusOK {
		t.Fatalf("reauth: %d %s", w.Code, w.Body)
	}
	e.newCookie(t, w)
	if !e.cookie.HttpOnly || e.cookie.SameSite != http.SameSiteStrictMode || e.cookie.Path != "/dashboard/" {
		t.Errorf("new cookie attributes: %+v", e.cookie)
	}
	after := payloadFromCookie(t, e.h, e.cookie)
	if after.CSRF != before.CSRF || after.Exp != before.Exp || after.Nonce == before.Nonce {
		t.Error("reauth must keep the token and expiry and change the nonce")
	}
	if w := e.showValue(); w.Code != http.StatusOK {
		t.Errorf("after typing the password: %d", w.Code)
	}
	fresh := e.cookie
	e.cookie = &stolen
	if w := e.showValue(); w.Code == http.StatusOK {
		t.Error("the old cookie still works")
	}
	e.cookie = fresh

	// Use does not extend the window, and the old sign-in page still works.
	e.age(recentAuthWindow - time.Second)
	if w := e.showValue(); w.Code != http.StatusOK {
		t.Errorf("inside the window: %d", w.Code)
	}
	e.age(recentAuthWindow)
	if w := e.showValue(); w.Code != http.StatusUnauthorized {
		t.Errorf("window end: %d", w.Code)
	}

	// Signing out ends it.
	e.post("/dashboard/logout")
	if w := e.post("/dashboard/reauth", "password", "testpass"); w.Code != http.StatusSeeOther {
		t.Errorf("reauth after logout: %d", w.Code)
	}
}

// Wrong passwords at the re-ask count in the login limiter, per address and
// per login, so changing address does not help; the right one then waits too.
func TestReauthIsRateLimited(t *testing.T) {
	e := newSecretsEnv(t, revealOn, "")
	e.age(time.Hour)
	for i := 0; i < loginMaxFailures; i++ {
		form := url.Values{"_csrf": {e.csrf}, "password": {"wrong"}}
		if w := e.do("POST", "/dashboard/reauth", form, "X-Forwarded-For", "10.9.9."+string(rune('1'+i))); w.Code != http.StatusForbidden {
			t.Fatalf("wrong password %d: %d", i, w.Code)
		}
	}
	form := url.Values{"_csrf": {e.csrf}, "password": {"testpass"}}
	if w := e.do("POST", "/dashboard/reauth", form, "X-Forwarded-For", "10.9.9.99"); w.Code != http.StatusTooManyRequests {
		t.Errorf("after too many tries: %d", w.Code)
	}
	if w := e.showValue(); w.Code == http.StatusOK {
		t.Error("value shown after failed passwords")
	}
	entries := parseAuditEntries(e.audit)
	if entry := findAuditEntry(entries, "dashboard.reauth", "denied"); entry == nil || entry.Metadata["dashboard.login"] == "" {
		t.Errorf("failed re-ask not audited with its login: %+v", entry)
	}
	if strings.Contains(e.audit.String(), "wrong") || strings.Contains(e.audit.String(), "testpass") {
		t.Error("the audit log holds a typed password")
	}
}

// The server's rules hold here too: a sealed-only secret and one tied to
// other machines are not shown, a forged X-Forwarded-For does not help, and
// showing is off, without stopping edits, unless the config turns it on.
func TestRulesAndOffSwitch(t *testing.T) {
	for name, tc := range map[string]struct {
		cfg   *config.DashboardConfig // nil = revealOn
		rules string
	}{
		"sealed":    {rules: `{"attestation":{"shop/*":{"require_sealed":true}}}`},
		"source ip": {rules: `{"attestation":{"shop/*":{"source_ip":["10.1.2.3"]}}}`},
		"off":       {cfg: &config.DashboardConfig{}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := revealOn
			if tc.cfg != nil {
				cfg = *tc.cfg
			}
			e := newSecretsEnv(t, cfg, tc.rules)
			form := url.Values{"_csrf": {e.csrf}, "path": {"shop/petstore"}, "use": {"show"}}
			w := e.do("POST", "/dashboard/secrets/value", form, "X-Forwarded-For", "10.1.2.3")
			if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), fakeValue) {
				t.Fatalf("%d", w.Code)
			}
			if findAuditEntry(parseAuditEntries(e.audit), "read_value", "denied") == nil {
				t.Error("refusal not audited")
			}
			page := e.do("GET", "/dashboard/secrets/open?path=shop/petstore", nil).Body.String()
			if strings.Contains(page, `id="show"`) || strings.Contains(page, `id="copy-open"`) || !strings.Contains(page, `id="blocked"`) {
				t.Error("the page still offers the value")
			}
			// The rule guards the value, for writing too; details are not the
			// value and stay editable.
			e.audit.Reset()
			add := e.post("/dashboard/secrets/new", "path", "shop/new", "value", "x")
			replace := e.post("/dashboard/secrets/replace", "path", "shop/petstore", "value", "x", "confirm", "yes")
			if tc.rules != "" {
				got, _ := e.store.Get("shop/petstore")
				_, err := e.store.Get("shop/new")
				if add.Code != http.StatusForbidden || replace.Code != http.StatusForbidden || got.Value != fakeValue || err == nil {
					t.Errorf("writes under a rule: add %d, replace %d", add.Code, replace.Code)
				}
				if findAuditEntry(parseAuditEntries(e.audit), "write", "denied") == nil {
					t.Error("refused write not audited")
				}
			} else if add.Code != http.StatusOK || replace.Code != http.StatusOK {
				t.Errorf("writes with reveal off: add %d, replace %d", add.Code, replace.Code)
			}
			if w := e.post("/dashboard/secrets/details", "path", "shop/petstore", "description", "new words"); w.Code != http.StatusOK {
				t.Errorf("details: %d", w.Code)
			}
		})
	}
}

func TestAddReplaceAndDetails(t *testing.T) {
	e := newSecretsEnv(t, revealOn, "")

	if w := e.post("/dashboard/secrets/new", "path", "home/wifi", "value", " pasted-fake\n", "description", "Wifi", "tags", "home, net ,", "url", ""); w.Code != http.StatusOK {
		t.Fatalf("add: %d %s", w.Code, w.Body)
	}
	got, err := e.store.Get("home/wifi")
	if err != nil || got.Value != "pasted-fake" || got.Metadata.Description != "Wifi" || len(got.Metadata.Tags) != 2 || !strings.HasPrefix(got.Metadata.CreatedBy, "dashboard@") {
		t.Fatalf("added: %+v %v", got.Metadata, err)
	}
	if w := e.post("/dashboard/secrets/new", "path", "shop/petstore", "value", "x"); w.Code != http.StatusConflict {
		t.Errorf("add over an existing secret: %d", w.Code)
	}
	for _, bad := range []string{"", "noslash", "a/*", "a/b c", "a/../b", "/a/b", "a/b/", "a/-b", "a/b?x", "a/\u202eb"} {
		if w := e.post("/dashboard/secrets/new", "path", bad, "value", "x"); w.Code != http.StatusBadRequest {
			t.Errorf("name %q: %d", bad, w.Code)
		}
	}
	if w := e.post("/dashboard/secrets/new", "path", "a/b", "value", "x", "url", "javascript:alert(1)"); w.Code != http.StatusBadRequest {
		t.Errorf("bad link: %d", w.Code)
	}

	if w := e.post("/dashboard/secrets/replace", "path", "shop/petstore", "value", "v2"); w.Code != http.StatusBadRequest {
		t.Errorf("replace without confirm: %d", w.Code)
	}
	if w := e.post("/dashboard/secrets/replace", "path", "shop/none", "value", "v2", "confirm", "yes"); w.Code != http.StatusNotFound {
		t.Errorf("replace a missing secret: %d", w.Code)
	}
	if w := e.post("/dashboard/secrets/replace", "path", "shop/petstore", "value", "v2", "confirm", "yes"); w.Code != http.StatusOK {
		t.Fatalf("replace: %d %s", w.Code, w.Body)
	}
	// Details change only what was sent and keep the value and its authors.
	if w := e.post("/dashboard/secrets/details", "path", "shop/petstore", "username", "you@example.com", "tags", ""); w.Code != http.StatusOK {
		t.Fatalf("details: %d %s", w.Code, w.Body)
	}
	got, _ = e.store.Get("shop/petstore")
	if m := got.Metadata; got.Value != "v2" || m.Username != "you@example.com" || len(m.Tags) != 0 || m.Description != "Pet shop account" ||
		m.URL != "https://shop.example.com/login" || m.CreatedBy != "maker" || !strings.HasPrefix(m.UpdatedBy, "dashboard@") {
		t.Errorf("after edits: %+v", got.Metadata)
	}
	if strings.Contains(e.audit.String(), "pasted-fake") || strings.Contains(e.audit.String(), "you@example.com") {
		t.Error("the audit log holds values or details")
	}
	if entry := findAuditEntry(parseAuditEntries(e.audit), "describe", "allowed"); entry == nil || entry.Metadata["changed"] != "tags,username" {
		t.Errorf("describe audit: %+v", entry)
	}
}

// A link put in the store file by hand is never turned into a live one.
func TestBadStoredLinkIsNotALink(t *testing.T) {
	e := newSecretsEnv(t, revealOn, "")
	bad := "javascript:alert(1)"
	e.store.Describe("shop/petstore", store.MetadataChange{URL: &bad})
	if page := e.do("GET", "/dashboard/secrets/open?path=shop/petstore", nil).Body.String(); strings.Contains(page, `id="open-link"`) || strings.Contains(page, "copy-open") {
		t.Error("a bad link is offered")
	}
}

// The service worker stores only listed static files, all of which exist, and
// everything else it serves is marked as not to be stored.
func TestServiceWorkerStoresOnlyStaticFiles(t *testing.T) {
	e := newSecretsEnv(t, revealOn, "")
	e.cookie = nil
	w := e.do("GET", "/dashboard/sw.js", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("sw.js: %d %v", w.Code, w.Header())
	}
	js := w.Body.String()
	list := js[strings.Index(js, "var FILES"):strings.Index(js, "];")]
	files := regexp.MustCompile(`'([^']+)'`).FindAllStringSubmatch(list, -1)
	if len(files) < 5 {
		t.Fatalf("file list not found: %q", list)
	}
	for _, f := range files {
		if !strings.HasPrefix(f[1], "/dashboard/static/") {
			t.Errorf("%s is not a static file", f[1])
		}
		if w := e.do("GET", f[1], nil); w.Code != http.StatusOK {
			t.Errorf("%s: %d", f[1], w.Code)
		}
	}
	if puts, guards := strings.Count(js, ".put("), strings.Count(js, "if (storable("); puts != guards || strings.Contains(js, "addAll") {
		t.Errorf("%d cache writes, %d behind the storable check", puts, guards)
	}
	for _, f := range []string{"secrets.js", "dashboard.js", "sw.js"} {
		data, _ := fs.ReadFile(staticFS, "static/"+f)
		for _, storage := range []string{"localStorage", "sessionStorage", "indexedDB", "document.cookie"} {
			if strings.Contains(string(data), storage) {
				t.Errorf("%s uses %s", f, storage)
			}
		}
	}
}

// hookBackend runs hooks around a real backend, and can fail or hand out a
// shared list as the 1Password one does.
type hookBackend struct {
	store.SecretBackend
	onGet          func()
	list           []string
	listErr, mdErr error
}

func (b *hookBackend) Get(path string) (*store.Secret, error) {
	if b.onGet != nil {
		b.onGet()
	}
	return b.SecretBackend.Get("shop/petstore") // any spelling opens it
}

func (b *hookBackend) List(prefix string) ([]string, error) {
	if b.listErr != nil {
		return nil, b.listErr
	}
	if b.list != nil {
		return b.list, nil
	}
	return b.SecretBackend.List(prefix)
}

func (b *hookBackend) Metadata(path string) (*store.SecretMetadata, error) {
	if b.mdErr != nil {
		return nil, b.mdErr
	}
	return b.SecretBackend.Metadata("shop/petstore")
}

// signOutWriter is an audit log during whose writes every login ends.
type signOutWriter struct {
	h   *Handler
	out *bytes.Buffer
}

func (w signOutWriter) Write(p []byte) (int, error) {
	w.out.Write(p)
	for _, l := range w.h.logins.list(time.Now()) {
		w.h.logins.removeByID(l.ID)
	}
	return len(p), nil
}

// A login that ends, or moves to a new cookie, while the value is being read
// or the audit line written gets nothing, and the audit still names it.
func TestLoginEndsDuringSlowRead(t *testing.T) {
	e := newSecretsEnv(t, revealOn, "")
	hook := &hookBackend{SecretBackend: e.h.deps.Backend}
	e.h.deps.Backend = hook
	id := e.h.logins.list(time.Now())[0].ID

	hook.onGet = func() {
		e.h.logins.reauthenticate(payloadFromCookie(t, e.h, e.cookie).Nonce, "moved", time.Now())
		hook.onGet = nil
	}
	if w := e.showValue(); w.Code == http.StatusOK || strings.Contains(w.Body.String(), fakeValue) {
		t.Fatalf("cookie moved during the read: %d", w.Code)
	}
	if entry := findAuditEntry(parseAuditEntries(e.audit), "read_value", "denied"); entry == nil || entry.Metadata["dashboard.login"] != id {
		t.Errorf("audit entry: %+v", entry)
	}

	e.cookie = login(t, e.h)
	e.csrf = csrfFromCookie(t, e.h, e.cookie)
	e.audit.Reset()
	hook.onGet = func() {
		for _, l := range e.h.logins.list(time.Now()) {
			e.h.logins.removeByID(l.ID)
		}
	}
	if w := e.showValue(); w.Code == http.StatusOK || strings.Contains(w.Body.String(), fakeValue) {
		t.Errorf("signed out during the read: %d", w.Code)
	}
	if findAuditEntry(parseAuditEntries(e.audit), "read_value", "allowed") != nil {
		t.Error("an unserved read was audited as allowed")
	}

	hook.onGet = nil
	e.cookie = login(t, e.h)
	e.csrf = csrfFromCookie(t, e.h, e.cookie)
	id = e.h.logins.list(time.Now())[0].ID
	e.audit.Reset()
	e.h.deps.Audit = audit.NewWriterLogger(signOutWriter{e.h, e.audit})
	if w := e.showValue(); w.Code == http.StatusOK || strings.Contains(w.Body.String(), fakeValue) {
		t.Errorf("signed out during the audit write: %d", w.Code)
	}
	if entry := findAuditEntry(parseAuditEntries(e.audit), "read_value", "denied"); entry == nil || entry.Reason != "signed_out" || entry.Metadata["dashboard.login"] != id {
		t.Errorf("refusal after the audit write: %+v", entry)
	}
}

// A backend that also opens a secret under an unlisted spelling must not let
// that spelling slip past the listed name's rule; and an outage says so.
func TestUnlistedNamesAndOutages(t *testing.T) {
	e := newSecretsEnv(t, revealOn, "")
	hook := &hookBackend{SecretBackend: e.h.deps.Backend}
	e.h.deps.Backend = hook
	if w := e.post("/dashboard/secrets/value", "path", "Shop/Petstore", "use", "show"); w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), fakeValue) {
		t.Errorf("unlisted spelling: %d", w.Code)
	}
	for _, p := range []string{"open", "details", "replace"} {
		hook.listErr, hook.mdErr = errors.New("down"), nil
		if w := e.do("GET", "/dashboard/secrets/"+p+"?path=shop/petstore", nil); w.Code != http.StatusServiceUnavailable {
			t.Errorf("%s, list down: %d", p, w.Code)
		}
		hook.listErr, hook.mdErr = nil, errors.New("down")
		if w := e.do("GET", "/dashboard/secrets/"+p+"?path=shop/petstore", nil); w.Code != http.StatusServiceUnavailable {
			t.Errorf("%s, details down: %d", p, w.Code)
		}
	}
	if body := e.do("GET", "/dashboard/secrets", nil).Body.String(); !strings.Contains(body, "Some details could not be read") {
		t.Error("the list hides that details are missing")
	}
}

// The list page must not sort the backend's own slice.
func TestListIsNotSortedInPlace(t *testing.T) {
	e := newSecretsEnv(t, revealOn, "")
	shared := []string{"z/z", "a/a"}
	e.h.deps.Backend = &hookBackend{SecretBackend: e.h.deps.Backend, list: shared}
	e.do("GET", "/dashboard/secrets", nil)
	if shared[0] != "z/z" {
		t.Error("the page reordered the backend's list")
	}
}

// A page left open cannot pair a new password with the old site.
func TestCopyAndOpenChecksTheLink(t *testing.T) {
	e := newSecretsEnv(t, revealOn, "")
	shown := regexp.MustCompile(`data-link="([^"]*)"`).FindStringSubmatch(e.do("GET", "/dashboard/secrets/open?path=shop/petstore", nil).Body.String())[1]
	fields := []string{"path", "shop/petstore", "use", "copy", "link", shown}
	if w := e.post("/dashboard/secrets/value", fields...); w.Code != http.StatusOK {
		t.Fatalf("same link: %d %s", w.Code, w.Body)
	}
	link := "https://new.example.com/?a=1&b=2|3"
	e.store.Write("shop/petstore", "fake-new", "me", store.MetadataChange{URL: &link}, store.WriteExisting)
	if w := e.post("/dashboard/secrets/value", fields...); w.Code != http.StatusConflict || strings.Contains(w.Body.String(), "fake-new") {
		t.Errorf("changed link: %d", w.Code)
	}
}

// Parallel wrong passwords, at login and at the re-ask: only the first few
// are tried, whatever order they arrive in.
func TestParallelGuessesAreLimited(t *testing.T) {
	for _, path := range []string{"/dashboard/login", "/dashboard/reauth"} {
		e := newSecretsEnv(t, revealOn, "")
		form := url.Values{"_csrf": {e.csrf}, "password": {"wrong"}, "credential": {"wrong"}}
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 30; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				e.do("POST", path, form)
			}()
		}
		close(start)
		wg.Wait()
		tried := 0
		for _, entry := range parseAuditEntries(e.audit) {
			if entry.Reason == "invalid_credentials" {
				tried++
			}
		}
		if tried != loginMaxFailures {
			t.Errorf("%s: %d passwords tried, want %d", path, tried, loginMaxFailures)
		}
	}
}
