package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/phoenixsec/phoenix/internal/crypto"
)

// errAgentCreateUsage is shown when agent create lacks a name or token. -t is left
// out on purpose: it works, but the token is then in the shell's history and
// readable by every user in the process list.
var errAgentCreateUsage = errors.New("usage: phoenix agent create <name> --acl <path:action,action;path:action> [--force]   (asks for the token)\n       phoenix agent create <name> --token-stdin --acl ... < token-file")

// promptToken asks on the terminal without echo; stdinIsTerminal says whether
// somebody can answer. Variables so tests can answer.
var (
	promptToken     = crypto.PromptPassphraseAllowEmpty
	stdinIsTerminal = crypto.IsTerminal
)

// readAgentToken gets a new agent's token without it being in the command line:
// from stdin, or asked for twice at a terminal.
func readAgentToken(name string, stdin bool) (string, error) {
	if stdin {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("reading stdin: %w", err)
		}
		return checkAgentToken(string(data))
	}
	if !stdinIsTerminal() {
		return "", errAgentCreateUsage
	}
	first, err := promptToken(fmt.Sprintf("Token for %s (input hidden): ", name))
	if err != nil {
		return "", err
	}
	tok, err := checkAgentToken(first)
	if err != nil {
		return "", err
	}
	again, err := promptToken("Type it again: ")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(again) != tok {
		return "", errors.New("the tokens do not match; nothing was created")
	}
	return tok, nil
}

// checkAgentToken trims the newline or spaces a paste or pipe adds, and refuses
// what could never be sent as a bearer token.
func checkAgentToken(raw string) (string, error) {
	tok := strings.TrimSpace(raw)
	if tok == "" {
		return "", errors.New("no token given; nothing was created")
	}
	if strings.ContainsFunc(tok, func(r rune) bool { return r <= ' ' || r > '~' }) {
		return "", errors.New("the token must be one line of plain characters without spaces; nothing was created")
	}
	return tok, nil
}
