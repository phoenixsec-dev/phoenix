package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
)

const describeUsage = "phoenix describe <path> [-d desc] [--tags t1,t2] [--username name] [--url link]   (an empty value clears that field)"

// loginOptions collects the metadata options that set and describe share. A
// nil field was not given; an empty one clears what is stored.
type loginOptions struct {
	username, url *string
}

// take records opt's value if it is one of the shared options.
func (l *loginOptions) take(opt, value string) bool {
	switch opt {
	case "--username":
		l.username = &value
	case "--url":
		l.url = &value
	default:
		return false
	}
	return true
}

// addTo puts the given options in a request body.
func (l loginOptions) addTo(body map[string]interface{}) {
	if l.username != nil {
		body["username"] = *l.username
	}
	if l.url != nil {
		body["url"] = *l.url
	}
}

// notIn names the given options missing from changed, the fields the server
// says it stored. "" when all are there.
func (l loginOptions) notIn(changed []string) string {
	var missing []string
	if l.username != nil && !slices.Contains(changed, "username") {
		missing = append(missing, "username")
	}
	if l.url != nil && !slices.Contains(changed, "url") {
		missing = append(missing, "link")
	}
	return strings.Join(missing, " and ")
}

// splitTags turns "a, b" into tags. An empty string is an empty list, which
// clears them.
func splitTags(s string) []string {
	tags := []string{}
	for _, t := range strings.Split(s, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tags = append(tags, t)
		}
	}
	return tags
}

// cmdDescribe implements `phoenix describe <path>`: it changes a secret's
// description, tags, username or link without reading or writing its value.
// Needs write permission on the path.
func cmdDescribe(args []string) error {
	path := ""
	body := map[string]interface{}{}
	var login loginOptions
	for i := 0; i < len(args); i++ {
		if !isOption("describe", args[i]) {
			if path != "" {
				return fmt.Errorf("usage: %s", describeUsage)
			}
			path = args[i]
			continue
		}
		if i+1 >= len(args) {
			return fmt.Errorf("option %s needs a value\nusage: %s", args[i], describeUsage)
		}
		opt, value := args[i], args[i+1]
		i++
		switch opt {
		case "-d", "--description":
			body["description"] = value
		case "--tags":
			body["tags"] = splitTags(value)
		default:
			login.take(opt, value)
		}
	}
	login.addTo(body)
	if path == "" || strings.HasSuffix(path, "/") || len(body) == 0 {
		return fmt.Errorf("usage: %s", describeUsage)
	}
	if err := requireAuth(); err != nil {
		return err
	}
	sealPrivKey, err := loadSealKeyForRequest()
	if err != nil {
		return fmt.Errorf("loading seal key: %w", err)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := apiRequestWithHeaders("PATCH", "/v1/metadata/"+path, strings.NewReader(string(payload)), sealHeaders(sealPrivKey))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		// An older server's mux answers 404 or 405 in plain text.
		if !strings.HasPrefix(strings.TrimSpace(string(respBody)), "{") &&
			(resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed) {
			return fmt.Errorf("this Phoenix server is too old for phoenix describe; update phoenix-server")
		}
		resp.Body = io.NopCloser(strings.NewReader(string(respBody)))
		return handleErrorForPath(resp, path)
	}
	var result struct {
		Changed []string `json:"changed"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	fmt.Printf("ok: %s (%s changed; value untouched)\n", path, strings.Join(result.Changed, ", "))
	return nil
}
