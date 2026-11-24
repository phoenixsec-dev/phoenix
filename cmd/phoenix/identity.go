package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
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
	Attested  bool   `json:"attested"`
}

// suffix is the caller part of a printed audit line, after the older columns
// so scripts that read those still work. Empty when nothing is known.
func (c auditCaller) suffix() string {
	out := ""
	for _, f := range [][2]string{{"who", c.Who}, {"host", c.Host}, {"authority", c.Authority}} {
		if f[1] != "" {
			out += fmt.Sprintf("  %s=%q", f[0], cleanServerText(f[1]))
		}
	}
	if c.Attested {
		return out + "  attested=yes"
	}
	if out != "" {
		out += "  attested=no"
	}
	return out
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

// takeLabelOptions pulls --who, --authority, --kind and --formerly out of
// args, as the JSON fields the server takes, and returns the other arguments.
func takeLabelOptions(args []string) (map[string]any, []string) {
	fields, rest := map[string]any{}, []string{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--who", "--authority", "--kind", "--formerly":
			if i+1 >= len(args) {
				rest = append(rest, args[i])
				continue
			}
			field, value := strings.TrimPrefix(args[i], "--"), args[i+1]
			i++
			if field != "formerly" {
				fields[field] = value
				continue
			}
			names := []string{}
			for _, n := range strings.Split(value, ",") {
				if n = strings.TrimSpace(n); n != "" {
					names = append(names, n)
				}
			}
			fields[field] = names
		default:
			rest = append(rest, args[i])
		}
	}
	return fields, rest
}

// cmdAgentSet changes an identity's who, authority, kind or former names.
func cmdAgentSet(args []string) error {
	fields, rest := takeLabelOptions(args)
	if len(rest) != 1 || len(fields) == 0 {
		return errors.New("usage: " + cmdSpecs["agent set"].usage)
	}
	if err := requireAuth(); err != nil {
		return err
	}
	var res struct {
		Identity identityView `json:"identity"`
	}
	code, err := apiJSON("PATCH", "/v1/agents/"+url.PathEscape(rest[0])+"/identity", fields, &res)
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
	formerly := "-"
	if len(id.Formerly) > 0 {
		formerly = cleanList(id.Formerly, ", ")
	}
	fmt.Printf("Formerly:  %s\n", formerly)
}
