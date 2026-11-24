package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
)

// How phoenix exec gets its values. One batch, all or nothing: exec runs no
// command unless every reference resolved, so the server is told not to hand
// over any of them (nor spend a "once") when one is refused.

// execResolved is the outcome of one resolve batch.
type execResolved struct {
	values map[string]string
	errs   map[string]string
	codes  map[string]refDenial
}

// ownToken is the agent's own token when this process is working through a
// role session minted from it, else "". Requests and grants belong to the
// agent, never to a session.
func ownToken() string {
	boot := os.Getenv("PHOENIX_TOKEN")
	if os.Getenv("PHOENIX_ROLE") == "" || boot == "" || strings.HasPrefix(boot, "phxs_") {
		return ""
	}
	return boot
}

// ownIdentityRequest sends one request as the agent itself, even when
// everything else goes through a role session.
func ownIdentityRequest(method, path string, body []byte, headers map[string]string) (*http.Response, error) {
	tok := ownToken()
	if tok == "" {
		tok = currentToken()
	}
	return sendAPIRequest(context.Background(), tok, method, path, body, body != nil, headers)
}

// resolveForExec resolves refs for phoenix exec. Under PHOENIX_ROLE, a secret
// the role may not read but a human approved for this agent is resolved as the
// agent: an approval was given to the agent, so it must not depend on whether a
// role happens to be set. Nothing else is read that way.
func resolveForExec(ctx context.Context, refs []string, sealKey *[32]byte) (execResolved, error) {
	res, err := resolveBatch(ctx, currentRoleSend, refs, sealKey)
	if err != nil || len(res.errs) == 0 || ownToken() == "" {
		return res, err
	}
	var refused, rest []string
	for _, r := range refs {
		switch {
		case res.errs[r] == "":
			rest = append(rest, r)
		case slices.Contains([]string{"SCOPE_EXCEEDED", "ACTION_DENIED", "ACL_DENIED"}, res.codes[r].Code):
			refused = append(refused, r)
		default:
			return res, nil
		}
	}
	approved := approvedPaths(ctx)
	for _, r := range refused {
		if !approved[strings.TrimPrefix(r, "phoenix://")] {
			return res, nil
		}
	}
	// Grants are sealed to the agent's registered key, not to the role's.
	own, err := loadSealKey()
	if err != nil {
		return res, fmt.Errorf("loading seal key: %w", err)
	}
	out := execResolved{values: map[string]string{}}
	if len(rest) > 0 {
		if out, err = resolveBatch(ctx, currentRoleSend, rest, sealKey); err != nil || len(out.errs) > 0 {
			return out, err
		}
	}
	// Last, because it may spend a use.
	mine, err := resolveBatch(ctx, ownSend, refused, own)
	if err != nil || len(mine.errs) > 0 {
		return mine, err
	}
	for r, v := range mine.values {
		out.values[r] = v
	}
	return out, nil
}

// resolveSender sends one resolve call as some identity.
type resolveSender func(ctx context.Context, body string, headers map[string]string) (*http.Response, error)

// currentRoleSend uses the token every other command uses.
func currentRoleSend(ctx context.Context, body string, headers map[string]string) (*http.Response, error) {
	return apiRequestCtx(ctx, "POST", "/v1/resolve", strings.NewReader(body), headers)
}

// ownSend uses the agent's own token.
func ownSend(ctx context.Context, body string, headers map[string]string) (*http.Response, error) {
	return sendAPIRequest(ctx, ownToken(), "POST", "/v1/resolve", []byte(body), true, headers)
}

// approvedPaths lists the exact paths humans approved for this agent: open
// grants to read a value and "always" entries. Empty when that cannot be read.
func approvedPaths(ctx context.Context) map[string]bool {
	out := map[string]bool{}
	resp, err := sendAPIRequest(ctx, ownToken(), "GET", "/v1/whoami", nil, false, nil)
	if err != nil {
		return out
	}
	defer resp.Body.Close()
	var w struct {
		ACL []struct {
			Path   string `json:"path"`
			Always bool   `json:"always"`
		} `json:"acl"`
		Grants []struct {
			Paths  []string `json:"paths"`
			Action string   `json:"action"`
		} `json:"grants"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&w) != nil {
		return out
	}
	for _, r := range w.ACL {
		if r.Always {
			out[r.Path] = true
		}
	}
	for _, g := range w.Grants {
		if g.Action == "read_value" {
			for _, p := range g.Paths {
				out[p] = true
			}
		}
	}
	return out
}

// resolveBatch resolves refs in one call, decrypting sealed values.
func resolveBatch(ctx context.Context, send resolveSender, refs []string, sealKey *[32]byte) (execResolved, error) {
	out := execResolved{values: map[string]string{}}
	body, _ := json.Marshal(map[string]any{"refs": refs, "all_or_nothing": true})
	resp, err := send(ctx, string(body), sealHeaders(sealKey))
	if err != nil {
		return out, fmt.Errorf("resolve request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, handleError(resp)
	}
	var result struct {
		Values       map[string]string    `json:"values"`
		SealedValues map[string]any       `json:"sealed_values"`
		Errors       map[string]string    `json:"errors"`
		ErrorCodes   map[string]refDenial `json:"error_codes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return out, fmt.Errorf("decoding resolve response: %w", err)
	}
	out.errs, out.codes = result.Errors, result.ErrorCodes
	if sealKey == nil {
		for r, v := range result.Values {
			out.values[r] = v
		}
		return out, nil
	}
	for ref, raw := range result.SealedValues {
		if envMap, ok := raw.(map[string]any); ok {
			if envRef, _ := envMap["ref"].(string); envRef != ref {
				return out, fmt.Errorf("sealed envelope ref mismatch: map key %q, envelope %q", ref, envRef)
			}
		}
		val, err := decryptSealedValue(raw, sealKey)
		if err != nil {
			return out, fmt.Errorf("decrypting %s: %w", displayRef(ref), err)
		}
		out.values[ref] = val
	}
	return out, nil
}
