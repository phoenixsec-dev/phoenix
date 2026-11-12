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
	"approve apr_": {
		why:     "step-up session approvals were removed",
		instead: "use access requests: the agent runs phoenix request <path> --reason \"...\" and you approve the req_ ID",
	},
}

// removedMCPFlags belonged to MCP over HTTP. They are refused rather than
// ignored, so a launcher still passing them hears why.
var removedMCPFlags = []string{"--http", "--tls-cert", "--tls-key", "--mcp-token"}

// removedMCPFlag returns the first removed MCP-over-HTTP flag in args
// ("--flag" or "--flag=value"), or "".
func removedMCPFlag(args []string) string {
	for _, arg := range args {
		name, _, _ := strings.Cut(arg, "=")
		for _, f := range removedMCPFlags {
			if name == f {
				return f
			}
		}
	}
	return ""
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
	os.Exit(1)
}
