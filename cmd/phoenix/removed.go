package main

import (
	"fmt"
	"os"
	"strings"
)

// removedCommand is a CLI command or flag Phoenix no longer has. The message
// says why it went and what to use instead, rather than a bare "unknown
// command", so old scripts and docs fail clearly.
type removedCommand struct {
	why     string
	instead string
}

// removedCommands is keyed by "command" or "command subcommand".
// clientCertRemovedNote is printed when PHOENIX_CLIENT_CERT or
// PHOENIX_CLIENT_KEY is still set, so a wrapper relying on them hears why
// they no longer do anything.
const clientCertRemovedNote = "warning: PHOENIX_CLIENT_CERT and PHOENIX_CLIENT_KEY are ignored: client certificates (mTLS) were removed. Use PHOENIX_TOKEN over https:// with PHOENIX_CA_CERT."

var removedCommands = map[string]removedCommand{
	"agent-sock": {
		why:     "the local agent socket ran inside phoenix-server, so it only worked on the server's own machine (its token and resolve subcommands minted short-lived tokens, also removed)",
		instead: "use phoenix get, resolve or exec; the local Phoenix service will replace the socket",
	},
	"cert": {
		why:     "client certificates (mTLS) were removed: hard to run, unused, and HTTPS already protects tokens in transit",
		instead: "give the agent a bearer token (phoenix agent create) and use https:// with PHOENIX_CA_CERT",
	},
	"token": {
		why:     "short-lived tokens trusted whatever process details the caller sent, so they proved nothing",
		instead: "use a role session (PHOENIX_ROLE) for a short-lived credential",
	},
	"resolve --signed": {
		why:     "the nonce challenge it answered only worked with client certificates, and nothing else could satisfy it",
		instead: "use phoenix resolve without --signed; source_ip rules still apply",
	},
	"init": {
		why:     "it only printed a pointer to the server command",
		instead: "run phoenix-server --init <dir>",
	},
	"policy test --time": {
		why: "time_window policy rules were removed, so there is no time to test",
	},
	"mcp-server --http": {
		why:     "MCP over HTTP was half-built (no sealed mode, no session renewal) and unused",
		instead: "run phoenix mcp-server over stdio, started by the agent's harness",
	},
	"exec --output-env": {
		why:     "it wrote secret values to a file in plain text, where they outlive the command and end up in backups",
		instead: "run the command under phoenix exec --env KEY=phoenix://ns/secret -- <command>, so the values only live in its environment",
	},
	"set --value": {
		why:     "a value on the command line lands in shell history and is visible to every user in the process list",
		instead: "run phoenix set <path> for a hidden prompt, add --multiline for PEM keys, or pipe the value in with --value-stdin",
	},
	"secret-provider": {
		why:     "it was a second name for the OpenClaw exec provider",
		instead: "use phoenix openclaw-exec-provider",
	},
	"resolve --stdin-json": {
		why:     "it was a second name for the OpenClaw exec provider",
		instead: "use phoenix openclaw-exec-provider",
	},
	"approve apr_": {
		why:     "step-up session approvals were removed",
		instead: "use access requests: the agent runs phoenix request <path> --reason \"...\" and you approve the req_ ID",
	},
}

// removedFlags lists removed flags per command (cmdSpecs key), each pointing
// at its removedCommands entry. checkArgs refuses them where they appear as
// options ("--flag" or "--flag=value"), rather than ignoring them, so an old
// script hears why. A value that merely looks like one (set -d --value) and
// anything after "--" are left alone.
var removedFlags = map[string]map[string]string{
	"mcp-server": {"--http": "mcp-server --http", "--tls-cert": "mcp-server --http",
		"--tls-key": "mcp-server --http", "--mcp-token": "mcp-server --http"},
	"exec":        {"--output-env": "exec --output-env"},
	"set":         {"-v": "set --value", "--value": "set --value"},
	"resolve":     {"--stdin-json": "resolve --stdin-json", "--signed": "resolve --signed"},
	"policy test": {"-t": "policy test --time", "--time": "policy test --time"},
}

// checkRemovedCommand exits with a short explanation when args name a removed
// command. It looks up "cmd sub" first, then "cmd".
func checkRemovedCommand(cmd string, args []string) {
	keys := []string{cmd}
	if len(args) > 0 {
		keys = []string{cmd + " " + args[0], cmd}
	}
	for _, k := range keys {
		if rc, ok := removedCommands[k]; ok {
			exitRemoved("phoenix "+k, rc)
		}
	}
}

// exitRemoved prints the removal message for name and exits 1.
func exitRemoved(name string, rc removedCommand) {
	msg := fmt.Sprintf("%s was removed: %s.", name, rc.why)
	if rc.instead != "" {
		msg += " " + strings.ToUpper(rc.instead[:1]) + rc.instead[1:] + "."
	}
	fmt.Fprintln(os.Stderr, msg)
	osExit(1)
}
