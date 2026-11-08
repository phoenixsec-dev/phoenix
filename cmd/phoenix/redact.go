package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
)

// phoenix exec --redact-output (plan section 9).
//
// Normal phoenix exec replaces itself with the child (syscall.Exec). With
// --redact-output it stays as the parent instead, pipes the child's stdout
// and stderr, and replaces every resolved secret value with
// [REDACTED:<ENV_NAME>] before passing the output on. The child's exit code
// is passed through.
//
// This is a guard against ACCIDENTS (a script echoing its token, curl -v
// printing the Authorization header into an agent's transcript). It is not
// a guard against a hostile command: anything that encodes, splits or
// writes the value somewhere else (a file, the network, base64) is not
// caught.

// minRedactLen is the shortest value that is redacted. Shorter values
// ("1", "yes", "abc") would match all over normal output and garble it, so
// they are passed through and exec prints a warning naming the variable.
const minRedactLen = 4

// redactValue is one resolved secret and the env var it was mapped to.
type redactValue struct {
	Name  string
	Value string
}

type redactRule struct {
	value []byte
	repl  []byte
}

// redactor is an io.Writer that replaces secret values in a byte stream.
// A value can arrive split across two writes, so the tail of each write that
// could still be the start of a value is held back until the next write (or
// Flush). Output is otherwise passed on immediately.
type redactor struct {
	mu      sync.Mutex
	w       io.Writer
	rules   []redactRule // longest value first, so a longer secret wins over one it contains
	first   [256]bool    // first bytes of all values, for a fast skip
	pending []byte
}

// newRedactor builds a redactor for values (in mapping order). Values under
// minRedactLen are skipped; if two env vars hold the same value, the first
// name is used in the replacement.
func newRedactor(w io.Writer, values []redactValue) *redactor {
	r := &redactor{w: w}
	seen := map[string]bool{}
	for _, v := range values {
		if len(v.Value) < minRedactLen || seen[v.Value] {
			continue
		}
		seen[v.Value] = true
		r.rules = append(r.rules, redactRule{value: []byte(v.Value), repl: []byte("[REDACTED:" + v.Name + "]")})
		r.first[v.Value[0]] = true
	}
	sort.SliceStable(r.rules, func(i, j int) bool { return len(r.rules[i].value) > len(r.rules[j].value) })
	return r
}

// Write redacts p (plus any held-back tail) and writes the safe part.
func (r *redactor) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending = append(r.pending, p...)
	out, keep := r.scan(r.pending, false)
	r.pending = append(r.pending[:0], keep...)
	if len(out) > 0 {
		if _, err := r.w.Write(out); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// Flush writes whatever was held back. Call it once the child has exited.
func (r *redactor) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	out, _ := r.scan(r.pending, true)
	r.pending = r.pending[:0]
	if len(out) == 0 {
		return nil
	}
	_, err := r.w.Write(out)
	return err
}

// scan walks buf, replacing every complete value. Unless final, it stops at
// the first position where the rest of buf is a proper prefix of some value
// (it might complete in the next write) and returns that rest as keep.
func (r *redactor) scan(buf []byte, final bool) (out, keep []byte) {
	out = make([]byte, 0, len(buf))
	i := 0
scan:
	for i < len(buf) {
		if !r.first[buf[i]] {
			out = append(out, buf[i])
			i++
			continue
		}
		rest := buf[i:]
		for _, rule := range r.rules {
			if bytes.HasPrefix(rest, rule.value) {
				out = append(out, rule.repl...)
				i += len(rule.value)
				continue scan
			}
			if !final && len(rest) < len(rule.value) && bytes.HasPrefix(rule.value, rest) {
				return out, rest
			}
		}
		out = append(out, buf[i])
		i++
	}
	return out, nil
}

// exitCodeError carries a child's exit status out of cmdExec so main can
// exit with the same code without printing an error.
type exitCodeError int

func (e exitCodeError) Error() string { return fmt.Sprintf("command exited with status %d", int(e)) }

// childEnv is the child's environment: the current one minus Phoenix's own
// settings and credentials (and, with maskEnv, minus anything holding a
// phoenix:// ref). Every PHOENIX_* variable goes: the token, PHOENIX_ROLE
// (which would let the child mint its own session), PHOENIX_MCP_TOKEN,
// PHOENIX_MASTER_PASSPHRASE, the seal key path and the rest. The 1Password
// service account token goes too, under its default name and under the name
// PHOENIX_OP_TOKEN_ENV points at. cmdExec adds the --env mappings after this,
// so a value the user maps on purpose still reaches the child.
func childEnv(environ []string, maskEnv bool) []string {
	strip := map[string]bool{"OP_SERVICE_ACCOUNT_TOKEN": true}
	for _, e := range environ {
		if key, val, _ := strings.Cut(e, "="); key == "PHOENIX_OP_TOKEN_ENV" && val != "" {
			strip[val] = true
		}
	}
	var env []string
	for _, e := range environ {
		key, val, _ := strings.Cut(e, "=")
		if strings.HasPrefix(key, "PHOENIX_") || strip[key] {
			continue // strip Phoenix settings and broker credentials
		}
		if maskEnv && strings.Contains(val, "phoenix://") {
			continue // strip env vars containing phoenix:// refs
		}
		env = append(env, e)
	}
	return env
}

// runRedacted runs argv with env, piping its stdout/stderr through
// redactors, and returns the child's exit code (128+signal when it was
// killed by a signal, like a shell). SIGTERM and SIGHUP sent to exec are
// passed to the child; Ctrl-C (SIGINT/SIGQUIT) already reaches the child
// from the terminal, so exec only ignores it and waits to pass on the
// child's own exit code.
func runRedacted(binary string, argv, env []string, values []redactValue, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	outR, errR := newRedactor(stdout, values), newRedactor(stderr, values)
	cmd := &exec.Cmd{Path: binary, Args: argv, Env: env, Stdin: stdin, Stdout: outR, Stderr: errR}

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)

	if err := cmd.Start(); err != nil {
		return 127, fmt.Errorf("starting %s: %w", argv[0], err)
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case s := <-sigs:
				if s == syscall.SIGTERM || s == syscall.SIGHUP {
					_ = cmd.Process.Signal(s)
				}
			case <-done:
				return
			}
		}
	}()

	waitErr := cmd.Wait()
	flushErr := errors.Join(outR.Flush(), errR.Flush())

	var exitErr *exec.ExitError
	switch {
	case waitErr == nil:
		return 0, flushErr
	case errors.As(waitErr, &exitErr):
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), flushErr
		}
		return exitErr.ExitCode(), flushErr
	default:
		return 1, waitErr
	}
}
