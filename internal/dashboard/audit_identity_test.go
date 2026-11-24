package dashboard

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/audit"
)

// The log page shows who, host, authority and attested as columns of their
// own, shows an old line with blanks, filters by the first three, and finds
// an identity's former names.
func TestAuditPageIdentityColumns(t *testing.T) {
	h, _, _ := testHandlerWithAudit(t)
	path := filepath.Join(t.TempDir(), "audit.log")
	os.WriteFile(path, []byte(`{"ts":"2026-01-02T03:04:05Z","agent":"old-bot","action":"read_value","path":"p/old","status":"allowed","sealed":false}`+"\n"), 0600)
	l, err := audit.NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Log(audit.Entry{Agent: "bot", Path: "p/token", Status: "allowed", Caller: audit.Caller{Who: "<robin>", Authority: "night-desk"}})
	l.Log(audit.Entry{Agent: "cam", Path: "p/seen", Status: "allowed", Caller: audit.Caller{Who: "sam", Host: "nas", Attested: true}})
	l.Close()
	a := acl.NewFromConfig(&acl.ACLConfig{Agents: map[string]acl.Agent{"bot": {Name: "bot", Labels: acl.Labels{Formerly: []string{"old-bot"}}}}})
	h.deps.AuditPath, h.deps.ACL = path, a

	login := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/dashboard/login", strings.NewReader("credential=testpass"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(login, req)
	tags := regexp.MustCompile(`<[^>]*>|\s+`)
	// rows returns each table row as its cells joined with "|".
	rows := func(query string) []string {
		req := httptest.NewRequest(http.MethodGet, "/dashboard/audit?"+query, nil)
		for _, c := range login.Result().Cookies() {
			req.AddCookie(c)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 200 || strings.Contains(w.Body.String(), "<robin>") {
			t.Fatalf("%s: %d\n%s", query, w.Code, w.Body.String())
		}
		var out []string
		for _, tr := range strings.Split(w.Body.String(), "<tr>")[1:] {
			cells := strings.ReplaceAll(tr, "</td>", "|")
			out = append(out, tags.ReplaceAllString(cells, ""))
		}
		if len(out) == 0 {
			return nil
		}
		return out[1:] // without the heading
	}
	has := func(query string, want ...string) {
		t.Helper()
		got := rows(query)
		if len(got) != len(want) {
			t.Fatalf("%s = %q, want %d rows", query, got, len(want))
		}
		for i := range want {
			if !strings.Contains(got[i], want[i]) {
				t.Errorf("%s row %d = %q, want %q", query, i, got[i], want[i])
			}
		}
	}
	old, declared, seen := "|old-bot|-|-|-|no|", "|bot|&lt;robin&gt;|-|night-desk|no(declared)|", "|cam|sam|nas|-|yes|"
	has("", seen, declared, old)
	has("who=sam", seen)
	has("host=nas", seen)
	has("authority=night-desk", declared)
	has("who=sam&authority=night-desk")
	has("agent=bot", declared, old)
	has("agent=old-bot", old)
}
