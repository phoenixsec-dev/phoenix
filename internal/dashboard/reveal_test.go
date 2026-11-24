package dashboard

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/phoenixsec/phoenix/internal/config"
)

// fakeNotifier records the pings the dashboard asked for.
type fakeNotifier struct {
	unset bool
	pings []string
}

func (f *fakeNotifier) NotifyConfigured() bool { return !f.unset }

func (f *fakeNotifier) NotifySecretUsed(path, verb, login, device, ip string) {
	f.pings = append(f.pings, fmt.Sprintf("%s %s %s %s", path, verb, device, ip))
	if login == "" {
		f.pings = append(f.pings, "no login")
	}
}

// openPage is the page of the test secret.
func (e *secretsEnv) openPage() string {
	return e.do("GET", "/dashboard/secrets/open?path=shop/petstore", nil).Body.String()
}

// Off, the page says so with the line to put in the config and the file it goes
// in. A rule that blocks the secret is what the page names, on or off, because
// turning showing on would not help.
func TestShowingIsOffUntilTheConfigSaysSo(t *testing.T) {
	e := newSecretsEnv(t, config.DashboardConfig{}, "")
	e.h.deps.ConfigPath = "/etc/phoenix/config.json"
	page := e.openPage()
	for _, want := range []string{`change <code>"reveal": false</code> to <code>true</code>`, `right after <code>"dashboard": {</code>:</p>`, `<pre class="config-line">"reveal": true,</pre>`, "/etc/phoenix/config.json"} {
		if !strings.Contains(page, want) {
			t.Errorf("page does not hold %s", want)
		}
	}
	if w := e.showValue(); w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), fakeValue) {
		t.Errorf("value handed out while off: %d", w.Code)
	}

	const rules = `{"attestation":{"shop/*":{"require_sealed":true}}}`
	for _, reveal := range []bool{false, true} {
		e := newSecretsEnv(t, config.DashboardConfig{Reveal: reveal}, rules)
		if page := e.openPage(); !strings.Contains(page, "only handled sealed") || strings.Contains(page, "config-line") {
			t.Errorf("reveal %v: the page does not name the rule", reveal)
		}
		if w := e.showValue(); w.Code != http.StatusForbidden {
			t.Errorf("reveal %v: rule did not hold: %d", reveal, w.Code)
		}
	}
}

// Each show and copy asks for a ping with the secret, login, device and
// address, never the value. A refusal, or the setting being off, asks for none.
func TestShowAndCopyPing(t *testing.T) {
	off := false
	for name, tc := range map[string]struct {
		cfg   config.DashboardConfig
		rules string
		want  int
	}{
		"on":             {cfg: revealOn, want: 2},
		"setting off":    {cfg: config.DashboardConfig{Reveal: true, NotifyOnReveal: &off}},
		"showing is off": {cfg: config.DashboardConfig{}},
		"rule":           {cfg: revealOn, rules: `{"attestation":{"shop/*":{"require_sealed":true}}}`},
	} {
		t.Run(name, func(t *testing.T) {
			e, f := newSecretsEnv(t, tc.cfg, tc.rules), &fakeNotifier{}
			e.h.deps.Notify = f
			e.showValue()
			e.post("/dashboard/secrets/value", "path", "shop/petstore", "use", "copy")
			e.post("/dashboard/secrets/value", "path", "shop/none", "use", "copy")
			if len(f.pings) != tc.want {
				t.Fatalf("%d pings, want %d", len(f.pings), tc.want)
			}
			if tc.want > 0 && (f.pings[0] != "shop/petstore shown Unknown browser 192.0.2.1" || f.pings[1] != "shop/petstore copied Unknown browser 192.0.2.1") {
				t.Error("wrong ping content")
			}
			// The audit line has no switch.
			if n := strings.Count(e.audit.String(), `"action":"read_value"`); n < 2 {
				t.Errorf("%d read_value audit lines", n)
			}
		})
	}
}

// Without notifications the value is still shown, and the page says nobody is
// pinged. With them, or with the ping switched off on purpose, it does not.
func TestPageSaysWhenNobodyIsPinged(t *testing.T) {
	off := false
	for _, tc := range []struct {
		cfg  config.DashboardConfig
		n    RevealNotifier
		note bool
		row  string
	}{
		{revealOn, nil, true, "with the password<"},
		{revealOn, &fakeNotifier{unset: true}, true, "with the password<"},
		{revealOn, &fakeNotifier{}, false, "and you are pinged"},
		{config.DashboardConfig{Reveal: true, NotifyOnReveal: &off}, &fakeNotifier{}, false, "no ping (switched off)"},
	} {
		e := newSecretsEnv(t, tc.cfg, "")
		e.h.deps.Notify = tc.n
		page := e.openPage()
		if got := strings.Count(page, "Nobody is pinged"); (got == 1) != tc.note || !strings.Contains(page, tc.row) {
			t.Errorf("%+v: %d notes, row %q present: %v", tc, got, tc.row, strings.Contains(page, tc.row))
		}
		if w := e.showValue(); w.Code != http.StatusOK {
			t.Errorf("show: %d", w.Code)
		}
	}
}

// The ping shows the address the dashboard believes, not one the visitor sent.
func TestPingAddressIsNotForged(t *testing.T) {
	for _, tc := range []struct {
		trusted []string
		want    string
	}{
		{nil, "192.0.2.1"},
		{[]string{"192.0.2.1"}, "203.0.113.9"},
	} {
		cfg := revealOn
		cfg.TrustedProxies = tc.trusted
		e, f := newSecretsEnv(t, cfg, ""), &fakeNotifier{}
		e.h.deps.Notify = f
		form := url.Values{"_csrf": {e.csrf}, "path": {"shop/petstore"}, "use": {"copy"}}
		e.do("POST", "/dashboard/secrets/value", form, "X-Forwarded-For", "198.51.100.7, 203.0.113.9")
		if len(f.pings) != 1 || !strings.HasSuffix(f.pings[0], " "+tc.want) {
			t.Errorf("trusted %v: the ping does not show %s", tc.trusted, tc.want)
		}
	}
}
