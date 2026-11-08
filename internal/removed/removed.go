// Package removed finds settings that Phoenix no longer supports in a JSON
// file (config.json, policy.json), so startup can refuse them by name instead
// of silently ignoring them. A rule that quietly does nothing is worse than a
// startup error: someone would go on trusting it.
package removed

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Field is one removed setting. Path is the JSON key path; "*" matches any key
// (a role name, a policy pattern) and "[]" matches every element of an array.
// When Value is set, only an array element equal to Value counts (for removed
// choices such as bootstrap_trust "mtls"); otherwise the key being present at
// all counts, whatever its value.
type Field struct {
	Path    string
	Value   string
	Why     string
	Instead string
}

// Find returns one line per removed field present in data, sorted, each naming
// the concrete path, why it went, and what to use instead. Data that is not a
// JSON object returns nothing; the normal parser reports that error.
func Find(data []byte, fields []Field) []string {
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil
	}
	var out []string
	for _, f := range fields {
		for _, hit := range match(root, strings.Split(f.Path, "."), "", f.Value) {
			line := fmt.Sprintf("%s: removed, %s", hit, f.Why)
			if f.Instead != "" {
				line += "; " + f.Instead
			}
			out = append(out, line)
		}
	}
	sort.Strings(out)
	return out
}

// match walks node along keys and returns the concrete paths that exist.
func match(node any, keys []string, prefix, value string) []string {
	if len(keys) == 0 {
		if value == "" {
			return []string{prefix}
		}
		return nil
	}
	key, rest := keys[0], keys[1:]
	if key == "[]" {
		arr, ok := node.([]any)
		if !ok {
			return nil
		}
		var out []string
		for i, el := range arr {
			p := fmt.Sprintf("%s[%d]", prefix, i)
			if len(rest) == 0 && value != "" {
				if s, ok := el.(string); ok && s == value {
					out = append(out, fmt.Sprintf("%s %q", prefix, value))
				}
				continue
			}
			out = append(out, match(el, rest, p, value)...)
		}
		return out
	}
	obj, ok := node.(map[string]any)
	if !ok {
		return nil
	}
	join := func(k string) string {
		if prefix == "" {
			return k
		}
		return prefix + "." + k
	}
	if key == "*" {
		names := make([]string, 0, len(obj))
		for k := range obj {
			names = append(names, k)
		}
		sort.Strings(names)
		var out []string
		for _, k := range names {
			out = append(out, match(obj[k], rest, join(k), value)...)
		}
		return out
	}
	child, ok := obj[key]
	if !ok {
		return nil
	}
	return match(child, rest, join(key), value)
}

// Error joins Find's lines into one startup error, or returns nil when there
// are none. what names the file ("config", "policy file").
func Error(what string, lines []string) error {
	if len(lines) == 0 {
		return nil
	}
	return fmt.Errorf("%s uses settings Phoenix no longer has (delete them to start):\n  %s",
		what, strings.Join(lines, "\n  "))
}
