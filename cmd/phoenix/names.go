package main

import (
	"net/url"
	"strings"
)

// escapeName makes a secret path or folder safe to put in a request's URL path,
// so the server sees exactly the name that was typed. Every request that carries
// a name uses it, or escapeSegment for an agent name or ID (a name in a query
// string goes through url.QueryEscape instead). Unescaped, "app/key?v2" and "app/key#old" reach the
// server as "app/key", "app/%6bey" as "app/key", and the server redirects
// "app/./key" and "/app/key" to "app/key": another secret each time.
// Slashes between names stay plain, for proxies that refuse %2F.
func escapeName(name string) string {
	parts := strings.Split(name, "/")
	var b strings.Builder
	for i, p := range parts {
		if p == "." || p == ".." {
			b.WriteString(strings.ReplaceAll(p, ".", "%2E"))
		} else {
			b.WriteString(url.PathEscape(p))
		}
		if i == len(parts)-1 {
			break
		}
		// After an empty part a plain slash would make "//", which the server
		// redirects away. Escaped, the server sees it and refuses the name.
		if p == "" {
			b.WriteString("%2F")
		} else {
			b.WriteByte('/')
		}
	}
	return b.String()
}

// escapeSegment is escapeName for a name that is one part of the URL path, such
// as an agent's name or an ID: a slash in it is part of the name.
func escapeSegment(name string) string {
	return strings.ReplaceAll(escapeName(name), "/", "%2F")
}
