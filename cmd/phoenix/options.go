package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// cmdSpec describes one command's options for checkArgs. opts maps each
// option name to whether it takes a value. child commands (exec, ssh) treat
// everything after "--" as the command they run, so it is never checked.
type cmdSpec struct {
	usage string
	opts  map[string]bool
	child bool
}

// cmdSpecs lists every command (or "command subcommand") and its options.
// A command that is missing here is not checked, so a new command must be
// added here too (TestEveryCommandRejectsUnknownOptions lists them all).
var cmdSpecs = map[string]cmdSpec{
	"get":     {usage: "phoenix get <path>"},
	"version": {usage: "phoenix version"},
	"help":    {usage: "phoenix help"},
	// Parents of subcommands: "phoenix agent --help" works, and an option
	// before the subcommand is refused rather than read as one.
	"agent":     {usage: "phoenix agent <create|list|delete>"},
	"policy":    {usage: "phoenix policy <show|test>"},
	"emergency": {usage: "phoenix emergency get <path> --data-dir <dir>"},
	"sessions":  {usage: "phoenix sessions <list|info|revoke>"},
	"keypair":   {usage: "phoenix keypair <generate|show>"},
	"delete":    {usage: "phoenix delete <path>"},
	"list":      {usage: "phoenix list [folder/]   (folder, folder/ and folder/* all list folder/)"},
	"set": {usage: "phoenix set <path> [-d desc] [--tags t1,t2] [--multiline | --value-stdin]",
		opts: map[string]bool{"-d": true, "--description": true, "--tags": true, "--multiline": false, "--value-stdin": false}},
	"export": {usage: "phoenix export <prefix> -f env", opts: map[string]bool{"-f": true, "--format": true}},
	"import": {usage: "phoenix import <file> -p <prefix> | phoenix import --from 1password --vault <v> --prefix <p> [--item <name>] [--dry-run] [--skip-existing]",
		opts: map[string]bool{"-p": true, "--prefix": true, "--from": true, "--vault": true, "--item": true, "--dry-run": false, "--skip-existing": false}},
	"audit": {usage: "phoenix audit [-n N] [-a agent] [-s RFC3339-time]",
		opts: map[string]bool{"-n": true, "--last": true, "-a": true, "--agent": true, "-s": true, "--since": true}},
	"agent create": {usage: "phoenix agent create <name> -t <token> --acl <path:actions;path:actions> [--force]",
		opts: map[string]bool{"-t": true, "--token": true, "--acl": true, "--force": false}},
	"agent list":             {usage: "phoenix agent list"},
	"agent delete":           {usage: "phoenix agent delete <name>"},
	"resolve":                {usage: "phoenix resolve <ref> [ref...]"},
	"openclaw-exec-provider": {usage: "phoenix openclaw-exec-provider   (OpenClaw SecretRef JSON on stdin/stdout)"},
	"exec": {usage: "phoenix exec --env KEY=phoenix://ns/secret [--timeout 5s] [--mask-env] [--redact-output] -- <command> [args...]",
		opts: map[string]bool{"-e": true, "--env": true, "--timeout": true, "--mask-env": false, "--redact-output": false}, child: true},
	"verify":      {usage: "phoenix verify <file> [--dry-run]", opts: map[string]bool{"--dry-run": false}},
	"status":      {usage: "phoenix status"},
	"policy show": {usage: "phoenix policy show <path>"},
	"policy test": {usage: "phoenix policy test -a <agent> -i <ip> <path>",
		opts: map[string]bool{"-a": true, "--agent": true, "-i": true, "--ip": true}},
	"rotate-master": {usage: "phoenix rotate-master"},
	"emergency get": {usage: "phoenix emergency get <path> --data-dir <dir> [--confirm] [--passphrase-stdin]",
		opts: map[string]bool{"--data-dir": true, "--confirm": false, "--passphrase-stdin": false}},
	"sessions list": {usage: "phoenix sessions list [--role R] [--agent A]",
		opts: map[string]bool{"-r": true, "--role": true, "-a": true, "--agent": true}},
	"sessions info":   {usage: "phoenix sessions info <session-id>"},
	"sessions revoke": {usage: "phoenix sessions revoke <session-id>"},
	"keypair generate": {usage: "phoenix keypair generate <agent-name> [-o <file>] [--force]",
		opts: map[string]bool{"-o": true, "--output": true, "--force": false}},
	"keypair show": {usage: "phoenix keypair show <agent-name>"},
	"request": {usage: `phoenix request <path>... --reason "why" [--ttl 30m] [--wait]`,
		opts: map[string]bool{"-r": true, "--reason": true, "--ttl": true, "--wait": false}},
	"request status": {usage: "phoenix request status <req_id>"},
	"ssh": {usage: `phoenix ssh <machine> --reason "why" [--ttl 15m] [--ask-again] [-- command...]`,
		opts: map[string]bool{"-r": true, "--reason": true, "--ttl": true, "--ask-again": false}, child: true},
	"whoami":  {usage: "phoenix whoami"},
	"pending": {usage: "phoenix pending"},
	"approve": {usage: "phoenix approve <req_id> [--ttl 15m] [--path p ...] [--yes]",
		opts: map[string]bool{"--ttl": true, "--path": true, "--yes": false, "-y": false}},
	"deny":          {usage: `phoenix deny <req_id> [--note "..."]`, opts: map[string]bool{"--note": true}},
	"grants":        {usage: "phoenix grants [--all] [--agent <name>]", opts: map[string]bool{"--all": false, "--agent": true}},
	"grants revoke": {usage: "phoenix grants revoke <gnt_id>"},
	"mcp-server":    {usage: "phoenix mcp-server   (MCP over stdio, started by the agent's harness)"},
}

// cmdAliases are other spellings main accepts for a command.
var cmdAliases = map[string]string{"--version": "version", "-V": "version", "--help": "help", "-h": "help"}

// osExit is os.Exit, replaceable in tests.
var osExit = os.Exit

// checkArgs checks a command's arguments before it runs, so a typo never
// reaches the server and comes back looking like a permission problem. It
// prints usage for -h/--help (exit 0), explains a removed flag (exit 1), and
// refuses any other option the command does not have (exit 2). A value after
// an option that takes one is a value, even if it starts with "-". "--" ends
// the options. It returns args with "subcommand" (if any) first, then the
// positional arguments, then the options, so the command's own parsing finds
// a path like "-x/y" given after "--". Commands not in cmdSpecs pass through.
func checkArgs(cmd string, args []string) []string {
	if alias, ok := cmdAliases[cmd]; ok {
		cmd = alias
	}
	key, rest, sub := cmd, args, []string(nil)
	if len(args) > 0 {
		if _, ok := cmdSpecs[cmd+" "+args[0]]; ok {
			key, rest, sub = cmd+" "+args[0], args[1:], args[:1]
		}
	}
	spec, ok := cmdSpecs[key]
	if !ok {
		return args
	}

	var positional, opts, after []string
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if a == "--" {
			if spec.child {
				after = rest[i:]
			} else {
				// Paths come first in what the command sees, and its own
				// parser would read one named like its option as that
				// option. Refuse that instead of guessing.
				for _, p := range rest[i+1:] {
					if isOption(key, p) {
						usageExit(key, spec, fmt.Sprintf("%q after -- is named like one of this command's options; a path cannot be", p))
					}
				}
				positional = append(positional, rest[i+1:]...)
			}
			break
		}
		// A lone "-" is not stdin for any command, so it is a mistyped
		// option, not a path.
		if a == "" || a[0] != '-' {
			positional = append(positional, a)
			continue
		}
		name, value, hasValue := strings.Cut(a, "=")
		if name == "-h" || name == "--help" {
			fmt.Println("usage: " + spec.usage)
			if len(spec.opts) > 0 {
				fmt.Println("options: " + strings.Join(optionNames(spec), " "))
			}
			osExit(0)
			return nil
		}
		if rkey, removed := removedFlags[key][name]; removed {
			exitRemoved("phoenix "+key+" "+name, removedCommands[rkey])
		}
		takesValue, known := spec.opts[name]
		switch {
		case !known:
			usageExit(key, spec, "no such option: "+a)
		case takesValue && !hasValue:
			if i+1 >= len(rest) {
				usageExit(key, spec, "option "+name+" needs a value")
			}
			i++
			value = rest[i]
		case !takesValue && hasValue:
			usageExit(key, spec, "option "+name+" takes no value")
		}
		opts = append(opts, name)
		if takesValue {
			opts = append(opts, value)
		}
	}
	out := append(append(append(sub, positional...), opts...), after...)
	return out
}

// usageExit prints a usage error for the command and exits 2.
func usageExit(key string, spec cmdSpec, msg string) {
	fmt.Fprintf(os.Stderr, "phoenix %s: %s\nusage: %s\nRun 'phoenix %s --help' for more\n", key, msg, spec.usage, key)
	osExit(2)
}

// optionNames lists a command's options, sorted, for its --help.
func optionNames(spec cmdSpec) []string {
	var names []string
	for n := range spec.opts {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// listFolder turns what someone typed for "phoenix list" (or the MCP
// phoenix_list prefix) into the folder to list. "services/browser",
// "services/browser/" and "services/browser/*" all mean "services/browser/".
// Any other wildcard is an error saying what works, instead of being sent as
// a secret name the server would answer with a misleading denial.
func listFolder(p string) (string, error) {
	if p == "" {
		return "", nil
	}
	folder := strings.TrimSuffix(p, "*")
	if strings.ContainsAny(folder, "*?[") || (folder != p && folder != "" && !strings.HasSuffix(folder, "/")) {
		return "", fmt.Errorf("%q: list takes a folder (services/browser, services/browser/ or services/browser/*); other wildcards are not supported", p)
	}
	if folder != "" && !strings.HasSuffix(folder, "/") {
		folder += "/"
	}
	return folder, nil
}

// isOption reports whether arg is one of the command's options. Commands
// whose first argument is optional (set, export, import, ...) use it to tell
// a path from an option, since checkArgs puts paths first.
func isOption(key, arg string) bool {
	name, _, _ := strings.Cut(arg, "=")
	_, ok := cmdSpecs[key].opts[name]
	return ok
}
