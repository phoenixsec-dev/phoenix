package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Who, authority, kind and former names of identities: phoenix agent set and
// show, and how they appear in whoami and audit output.

const serverTooOldForIdentity = "this server is too old for identity fields; update it first"

// identityView is one identity as the server describes it.
type identityView struct {
	Name      string   `json:"name"`
	Who       string   `json:"who"`
	Authority string   `json:"authority"`
	Kind      string   `json:"kind"`
	Formerly  []string `json:"formerly"`
}

// auditCaller is the caller part of an audit line.
type auditCaller struct {
	Who       string `json:"who"`
	Host      string `json:"host"`
	Authority string `json:"authority"`
	Attested  *bool  `json:"attested"` // nil from a server without these fields
}

// suffix is the caller part of a printed audit line, after the older columns
// so scripts that read those still work.
func (c auditCaller) suffix() string {
	if c.Attested == nil {
		return ""
	}
	out := ""
	for _, f := range [][2]string{{"who", c.Who}, {"host", c.Host}, {"authority", c.Authority}} {
		v := "-"
		if f[1] != "" {
			v = strconv.Quote(cleanServerText(f[1]))
		}
		out += "  " + f[0] + "=" + v
	}
	if *c.Attested {
		return out + "  attested=yes"
	}
	return out + "  attested=no"
}

// attestedText says in words what attested means.
func attestedText(attested bool) string {
	if attested {
		return "yes (Phoenix checked this caller itself)"
	}
	return "no (a token; who and authority are what an admin declared for it)"
}

// orDash shows a server text, or "-" when it is not set.
func orDash(s string) string {
	if s = cleanServerText(s); s == "" {
		return "-"
	}
	return s
}

// listOrDash shows names, or "-" when there are none.
func listOrDash(names []string) string {
	if len(names) == 0 {
		return "-"
	}
	return cleanList(names, ", ")
}

// labelOption reads one of --who, --authority, --kind and --formerly into
// fields, as the JSON the server takes. ok is false for any other option.
func labelOption(fields map[string]any, option, value string) (ok bool, err error) {
	switch option {
	case "--who", "--authority", "--kind":
		fields[strings.TrimPrefix(option, "--")] = value
		return true, nil
	case "--formerly":
		names := []string{}
		if value != "" { // "" clears the list
			for _, n := range strings.Split(value, ",") {
				if n = strings.TrimSpace(n); n == "" {
					return true, fmt.Errorf("--formerly: empty name in %q", value)
				}
				names = append(names, n)
			}
		}
		fields["formerly"] = names
		return true, nil
	}
	return false, nil
}

// cmdAgentSet changes an identity's who, authority, kind or former names.
func cmdAgentSet(args []string) error {
	usage := errors.New("usage: " + cmdSpecs["agent set"].usage)
	if len(args) < 3 || len(args)%2 == 0 {
		return usage
	}
	fields := map[string]any{}
	for i := 1; i < len(args); i += 2 {
		if ok, err := labelOption(fields, args[i], args[i+1]); err != nil {
			return err
		} else if !ok {
			return usage
		}
	}
	if err := requireAuth(); err != nil {
		return err
	}
	var res struct {
		Identity identityView `json:"identity"`
	}
	code, err := apiJSON("PATCH", "/v1/agents/"+url.PathEscape(args[0])+"/identity", fields, &res)
	if code == http.StatusMethodNotAllowed {
		return errors.New(serverTooOldForIdentity)
	}
	if err != nil {
		return err
	}
	printIdentity(res.Identity)
	return nil
}

// cmdAgentShow prints one identity, or all of them.
func cmdAgentShow(args []string) error {
	if len(args) > 1 {
		return errors.New("usage: " + cmdSpecs["agent show"].usage)
	}
	if err := requireAuth(); err != nil {
		return err
	}
	var res struct {
		Identities []identityView `json:"identities"`
	}
	if _, err := apiJSON("GET", "/v1/agents", nil, &res); err != nil {
		return err
	}
	if res.Identities == nil {
		return errors.New(serverTooOldForIdentity)
	}
	shown := false
	for _, id := range res.Identities {
		if len(args) == 1 && id.Name != args[0] {
			continue
		}
		if shown {
			fmt.Println()
		}
		printIdentity(id)
		shown = true
	}
	if !shown {
		return fmt.Errorf("agent not found")
	}
	return nil
}

// printIdentity prints one identity's fields.
func printIdentity(id identityView) {
	fmt.Printf("Agent:     %s\n", cleanPath(id.Name))
	fmt.Printf("Who:       %s\n", orDash(id.Who))
	fmt.Printf("Authority: %s\n", orDash(id.Authority))
	fmt.Printf("Kind:      %s\n", orDash(id.Kind))
	fmt.Printf("Formerly:  %s\n", listOrDash(id.Formerly))
}
