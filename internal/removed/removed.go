// Package removed finds settings that Phoenix no longer supports in a JSON
// file (config.json, policy.json), so startup can refuse them by name instead
// of silently ignoring them. A rule that quietly does nothing is worse than a
// startup error: someone would go on trusting it.
package removed

import (
	"bytes"
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
// the concrete path, why it went, and what to use instead. It reads the JSON
// the way the config decoder does: keys match case-insensitively, a key that
// appears twice is checked in every occurrence (the decoder merges repeated
// objects), and numbers of any size are fine. JSON it cannot read gives one
// refusal line, so a file is never treated as clean by accident. Empty or
// whitespace-only data returns nothing.
func Find(data []byte, fields []Field) []string {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	root, err := readNode(dec)
	if err != nil {
		return []string{fmt.Sprintf("(file): could not be checked for removed settings: %v", err)}
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range fields {
		for _, hit := range match(root, strings.Split(f.Path, "."), "", f.Value) {
			line := fmt.Sprintf("%s: removed. Why: %s.", hit, f.Why)
			if f.Instead != "" {
				line += " Instead: " + f.Instead + "."
			}
			if !seen[line] {
				seen[line] = true
				out = append(out, line)
			}
		}
	}
	sort.Strings(out)
	return out
}

// node is one JSON value. Objects keep every key in file order, duplicates
// included, which a Go map would lose.
type node struct {
	keys []string
	vals []*node
	arr  []*node
	str  *string
}

// readNode reads one JSON value from dec's token stream.
func readNode(dec *json.Decoder) (*node, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	n := &node{}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, _ := kt.(string)
				v, err := readNode(dec)
				if err != nil {
					return nil, err
				}
				n.keys, n.vals = append(n.keys, k), append(n.vals, v)
			}
		case '[':
			n.arr = []*node{}
			for dec.More() {
				v, err := readNode(dec)
				if err != nil {
					return nil, err
				}
				n.arr = append(n.arr, v)
			}
		}
		if _, err := dec.Token(); err != nil { // closing delimiter
			return nil, err
		}
	case string:
		n.str = &t
	}
	return n, nil
}

// match walks n along keys and returns the concrete paths that exist. A
// literal key matches case-insensitively, like the config decoder; "*"
// matches any key and "[]" every array element.
func match(n *node, keys []string, prefix, value string) []string {
	if len(keys) == 0 {
		if value == "" {
			return []string{prefix}
		}
		return nil
	}
	key, rest := keys[0], keys[1:]
	if key == "[]" {
		var out []string
		for i, el := range n.arr {
			if len(rest) == 0 && value != "" {
				if el.str != nil && *el.str == value {
					out = append(out, fmt.Sprintf("%s %q", prefix, value))
				}
				continue
			}
			out = append(out, match(el, rest, fmt.Sprintf("%s[%d]", prefix, i), value)...)
		}
		return out
	}
	var out []string
	for i, k := range n.keys {
		if key != "*" && !strings.EqualFold(k, key) {
			continue
		}
		p := k
		if prefix != "" {
			p = prefix + "." + k
		}
		out = append(out, match(n.vals[i], rest, p, value)...)
	}
	return out
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
