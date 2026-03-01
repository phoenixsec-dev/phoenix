// Package phoenix provides a thin HTTP client for the Phoenix secrets
// management API. It supports health checks, single resolve, and batch
// resolve. No admin operations.
//
// Under 200 lines — if this grows beyond that, it's doing too much.
package phoenix

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Error represents a Phoenix API error.
type Error struct {
	Message string
	Status  int
}

func (e *Error) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("phoenix: HTTP %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("phoenix: %s", e.Message)
}

// ResolveResult contains the result of a batch resolve call.
type ResolveResult struct {
	Values map[string]string `json:"values"`
	Errors map[string]string `json:"errors,omitempty"`
}

// Client is a thin HTTP client for the Phoenix API.
type Client struct {
	Server     string
	Token      string
	HTTPClient *http.Client
}

// New creates a new Phoenix client. Server and token default to
// PHOENIX_SERVER and PHOENIX_TOKEN environment variables.
func New(server, token string) *Client {
	if server == "" {
		server = os.Getenv("PHOENIX_SERVER")
	}
	if server == "" {
		server = "http://127.0.0.1:9090"
	}
	server = strings.TrimRight(server, "/")

	if token == "" {
		token = os.Getenv("PHOENIX_TOKEN")
	}

	return &Client{
		Server: server,
		Token:  token,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Health checks server health. Returns the parsed JSON response.
func (c *Client) Health() (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := c.doRequest("GET", "/v1/health", nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Resolve resolves a single phoenix:// reference to its secret value.
func (c *Client) Resolve(ref string) (string, error) {
	result, err := c.ResolveBatch([]string{ref})
	if err != nil {
		return "", err
	}
	if errMsg, ok := result.Errors[ref]; ok {
		return "", &Error{Message: errMsg}
	}
	val, ok := result.Values[ref]
	if !ok {
		return "", &Error{Message: fmt.Sprintf("no value returned for %s", ref)}
	}
	return val, nil
}

// ResolveBatch resolves multiple phoenix:// references in one API call.
func (c *Client) ResolveBatch(refs []string) (*ResolveResult, error) {
	if len(refs) == 0 {
		return nil, &Error{Message: "refs must not be empty"}
	}

	body := map[string]interface{}{"refs": refs}
	var result ResolveResult
	if err := c.doRequest("POST", "/v1/resolve", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) doRequest(method, path string, body interface{}, out interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return &Error{Message: fmt.Sprintf("marshaling request: %v", err)}
		}
		bodyReader = strings.NewReader(string(data))
	}

	req, err := http.NewRequest(method, c.Server+path, bodyReader)
	if err != nil {
		return &Error{Message: fmt.Sprintf("building request: %v", err)}
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return &Error{Message: fmt.Sprintf("server unreachable: %v", err)}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return &Error{Message: fmt.Sprintf("reading response: %v", err), Status: resp.StatusCode}
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			return &Error{Message: errResp.Error, Status: resp.StatusCode}
		}
		return &Error{Message: fmt.Sprintf("HTTP %d", resp.StatusCode), Status: resp.StatusCode}
	}

	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return &Error{Message: fmt.Sprintf("decoding response: %v", err)}
		}
	}
	return nil
}
