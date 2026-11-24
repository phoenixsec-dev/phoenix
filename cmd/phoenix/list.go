package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// secretInfo is one entry from GET /v1/metadata: everything about a secret
// except its value.
type secretInfo struct {
	Path        string     `json:"path"`
	Description string     `json:"description"`
	Tags        []string   `json:"tags"`
	Created     *time.Time `json:"created"`
	Updated     *time.Time `json:"updated"`
	CreatedBy   string     `json:"created_by"`
	UpdatedBy   string     `json:"updated_by"`
	RotationDue string     `json:"rotation_due"`
	Username    string     `json:"username"`
	URL         string     `json:"url"`
}

// errNoMetadataRoute means the server predates /v1/metadata (its mux
// answers a plain-text 404, not our JSON one).
var errNoMetadataRoute = fmt.Errorf("this Phoenix server is too old for descriptions (no /v1/metadata); update phoenix-server")

// isMissingRoute tells a 404 from the server's mux (unknown route) apart
// from the handler's JSON "secret not found".
func isMissingRoute(resp *http.Response, body []byte) bool {
	return resp.StatusCode == http.StatusNotFound && !strings.HasPrefix(strings.TrimSpace(string(body)), "{")
}

// fetchSecretInfos asks the server for the metadata of every secret under
// prefix that the caller may list, optionally only those tagged tag.
func fetchSecretInfos(prefix, tag string) ([]secretInfo, error) {
	sealPrivKey, err := loadSealKeyForRequest()
	if err != nil {
		return nil, fmt.Errorf("loading seal key: %w", err)
	}
	path := "/v1/metadata/" + escapeName(prefix)
	if tag != "" {
		path += "?tag=" + url.QueryEscape(tag)
	}
	resp, err := apiRequestWithHeaders("GET", path, nil, sealHeaders(sealPrivKey))
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if isMissingRoute(resp, body) {
			return nil, errNoMetadataRoute
		}
		resp.Body = io.NopCloser(strings.NewReader(string(body)))
		return nil, handleError(resp)
	}
	var result struct {
		Secrets []secretInfo `json:"secrets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return result.Secrets, nil
}

// formatSecretList renders `phoenix list` output: each path, then its
// description (and tags) indented underneath, or "(no description)".
// Paths and descriptions go through listPath so stored text cannot inject
// lines or terminal escapes.
func formatSecretList(w io.Writer, infos []secretInfo) {
	for _, si := range infos {
		fmt.Fprintln(w, listPath(si.Path))
		desc := "(no description)"
		if si.Description != "" {
			desc = listPath(si.Description)
		}
		if len(si.Tags) > 0 {
			desc += "  [" + listPath(strings.Join(si.Tags, ", ")) + "]"
		}
		fmt.Fprintln(w, "  "+desc)
	}
}

// formatSecretInfo renders `phoenix info` output for one secret.
func formatSecretInfo(w io.Writer, si secretInfo) {
	line := func(label, v string) {
		if v != "" {
			fmt.Fprintf(w, "%-13s %s\n", label+":", listPath(v))
		}
	}
	stamp := func(t *time.Time, by string) string {
		s := ""
		if t != nil {
			s = t.Local().Format("2006-01-02 15:04 MST")
		}
		if by != "" {
			s = strings.TrimSpace(s + " by " + by)
		}
		return s
	}
	line("path", si.Path)
	desc := si.Description
	if desc == "" {
		desc = "(no description)"
	}
	line("description", desc)
	line("tags", strings.Join(si.Tags, ", "))
	line("username", si.Username)
	line("link", si.URL)
	line("created", stamp(si.Created, si.CreatedBy))
	line("updated", stamp(si.Updated, si.UpdatedBy))
	line("rotation due", si.RotationDue)
}

// cmdInfo implements `phoenix info <path>`: everything about one secret
// except its value. Needs only list permission on the path.
func cmdInfo(args []string) error {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") || args[0] == "" || strings.HasSuffix(args[0], "/") {
		return fmt.Errorf("usage: phoenix info <path>   (shows description, tags, username, link, dates; never the value)")
	}
	path := args[0]
	if err := requireAuth(); err != nil {
		return err
	}

	sealPrivKey, err := loadSealKeyForRequest()
	if err != nil {
		return fmt.Errorf("loading seal key: %w", err)
	}
	resp, err := apiRequestWithHeaders("GET", "/v1/metadata/"+escapeName(path), nil, sealHeaders(sealPrivKey))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		if isMissingRoute(resp, body) {
			return errNoMetadataRoute
		}
		resp.Body = io.NopCloser(strings.NewReader(string(body)))
		return handleErrorForPath(resp, path)
	}
	var si secretInfo
	if err := json.Unmarshal(body, &si); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	formatSecretInfo(os.Stdout, si)
	return nil
}
