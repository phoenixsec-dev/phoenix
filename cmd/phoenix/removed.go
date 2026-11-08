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
var removedCommands = map[string]removedCommand{}

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
