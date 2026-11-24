---
name: phoenix
description: Phoenix secrets manager. Use when you need a secret, API key, token or credential (phoenix exec, phoenix:// references), when Phoenix denies access and you must ask a human for temporary use, or when you need root or an SSH login on another machine (phoenix ssh, approved by a human).
---

# Phoenix Secrets Manager

Manage secrets securely through the Phoenix secrets management system.
Secrets are encrypted at rest (AES-256-GCM), access-controlled per agent,
and audited. Prefer `phoenix://` reference workflows to reduce raw secret exposure.

Important: Phoenix does not currently enforce global "reference-only" usage.
Agents with read-capable credentials can still retrieve plaintext via `phoenix get`,
`phoenix resolve`, or direct API reads.

Operational preference: use `phoenix exec` as the default secret-consumption path.
Use `phoenix get`/`phoenix resolve` only when explicitly needed for debugging or
manual inspection.

## Commands

Use the `phoenix` CLI for all operations. The CLI must be configured with
environment variables before use:

- `PHOENIX_SERVER` — server URL (default: `http://127.0.0.1:9090`)
- `PHOENIX_TOKEN` — bearer token for authentication
- `PHOENIX_CA_CERT` — CA certificate path (for HTTPS)
- `PHOENIX_SEAL_KEY` — seal private key file path (enables sealed mode)

### Preferred: run a command with secrets injected

```bash
phoenix exec --env KEY=phoenix://namespace/secret -- <command> [args...]
```

Resolves references and injects them as environment variables into the child
process. Phoenix broker credentials are stripped from the child environment.
Values live only in that process's environment; never write them to a file
(`--output-env` was removed for that reason). Add `--redact-output` to mask a
value the command prints by mistake.

### Store a secret

```bash
# Agents/scripts: pipe the value in
<command that outputs the value> | phoenix set <namespace/key> --value-stdin -d "description" --tags "tag1,tag2"

# Humans at a terminal: no value flag, Phoenix prompts with input hidden
phoenix set <namespace/key> -d "description"
```

There is no `-v`/`--value` flag: a value on the command line leaks to shell
history and the process list.

Always give `-d`: it is how people and other agents find the secret later.
For a login, also give `--username <name>` and `--url <page>`, so a person can
open it from the dashboard. Neither is secret; never put a password in them,
in `-d` or in a tag.

To add or fix a description, tags, username or link on a secret that exists:

```bash
phoenix describe <namespace/key> -d "what it is for" --username <name> --url <page>
```

It needs write on the path and never reads or writes the value. Use it instead
of setting the value again. `""` clears a field.

### Find the secret you need

```bash
phoenix list [folder/] [--tag <tag>]   # each path with its description
phoenix info <namespace/key>           # description, tags, username, link, dates
```

Use these to find a secret by what it is for. Neither shows the value, and
both need only list access. `phoenix list --names` prints bare paths for
scripts. MCP: `phoenix_list` returns the same descriptions, with usernames and links.

`services/browser`, `services/browser/` and `services/browser/*` all list
`services/browser/`; other wildcards are refused. There is no `--prefix`
option.

Every command refuses an option it does not have with
`no such option` and exit code 2, before contacting the server: that is a
typo, not a permission problem, so fix the command and retry. `phoenix
<command> --help` shows its options; `--` ends options (for a path that
starts with `-`).

### Delete a secret

```bash
phoenix delete <namespace/key>
```

### Resolve references

```bash
phoenix resolve phoenix://namespace/key [phoenix://namespace/key2 ...]
```

Resolves one or more `phoenix://` references to their values. Prefer
`phoenix exec` for normal operations; use explicit resolve for targeted debugging.

### Read a secret directly

```bash
phoenix get <namespace/key>
```

Returns the decrypted value. Use sparingly — prefer `phoenix exec` and references.

### Verify references in a file

```bash
phoenix verify <file>
```

Scans a file for `phoenix://` references and verifies each is resolvable
with the current credentials. Checks ACL and attestation. Exits with code 1
on any failure.

Use `--dry-run` to check that paths exist and are accessible without resolving
secret values. Dry-run uses the server-side `?dry_run=true` endpoint, which
exercises ACL and attestation policies without returning plaintext values.

### Check system status

```bash
phoenix status
```

Shows server health, secret count, agent count, policy summary, and recent
audit activity. Use this to verify what an agent has set up.

### Show attestation policy for a path

```bash
phoenix policy show <secret-path>
```

Requires `PHOENIX_POLICY` to point to the policy JSON file.

### Test attestation

```bash
phoenix policy test --agent <name> --ip <ip> <secret-path>
```

Dry-run attestation check against the local policy file.

### Create an agent

```bash
phoenix agent create <name> -t <token> --acl "namespace/*:list,read_value,write;other/*:list"
```

Creates a new agent with the specified ACL permissions (admin only).
Actions: `list` (see names), `read_value` (read values), `write`, `delete`,
`admin`. The old `read` shorthand was removed; write `list,read_value`.

### List agents

```bash
phoenix agent list
```

### Describe an agent

```bash
phoenix agent set <name> --who <w> --authority <a> --kind <k> --formerly <old1,old2>
phoenix agent show [name]
```

Records who uses an identity and in what role (admin only), so the audit log
can show them apart. Its token and sessions stay. These are labels: they grant
nothing, and no header or argument of yours can set them for your own calls.
`phoenix whoami` shows yours.

### Export secrets

```bash
phoenix export <prefix> -f env
```

Exports secrets under a prefix as `KEY=VALUE` pairs.

### Import secrets

```bash
phoenix import <envfile> -p <namespace/>
```

Imports `KEY=VALUE` pairs from a `.env` file into a namespace.

### Audit log

```bash
phoenix audit [-n 20] [-a agent-name] [-s 2025-01-01T00:00:00Z] [--who w] [--host h] [--authority a]
```

Query the audit log. Filter by count, agent, time range, or who, host and authority.

### Sealed mode

An admin makes your seal key; you cannot. If you get
`SEAL_KEY_NOT_REGISTERED`, ask the user for one. Set `PHOENIX_SEAL_KEY` to
the private key file they give you.

When sealed mode is active, `phoenix get`, `phoenix resolve`, and
`phoenix exec` transparently encrypt/decrypt values using NaCl box.

## Root on another machine

Phoenix can give you a short SSH login to another machine, once a human
approves it. Use this whenever you need root or a shell somewhere else.

1. `phoenix ssh --list` shows the machines you may ask for, and any approval
   you already have.
2. If the machine is listed:
   `phoenix ssh <machine> --reason "<why>" -- '<command>'`
   Quote the whole command as one string. Use `sudo -n` inside it for root.
3. A human approves on their side. That can take minutes; the command waits.
   Inside an active approval, later commands run at once and `--reason` is
   optional.
4. Never ask the user to open a terminal or run sudo for you. If the machine
   is not listed, or the human denies it, say so and stop.

If it says the machine needs approval although a human already approved it,
check that this command uses the same `PHOENIX_TOKEN` and runs from the same
machine as the one that asked. An approval belongs to one agent, token and IP.

## Safety Guardrails

- **Never ask the user to paste secrets into chat** — have them run
  `phoenix set <path>` in their own terminal (hidden prompt), or use
  `phoenix import`, so values never appear in conversation history
- Prefer `phoenix://` references in config files over hardcoded values
- Recommend least-privilege ACL scopes per agent (e.g. `namespace/*:list,read_value` not `*:admin`)
- Use `phoenix verify --dry-run` to validate references without exposing values
- Use `phoenix status` to review the security posture after setup
- All secret access is logged — use `phoenix audit` to review

## Runbook: Add a Secret and Grant Agent Access

Typical flow for setting up a new secret with proper access control:

```bash
# 1. Store the secret (human runs this and pastes at the hidden prompt)
phoenix set myapp/api-key -d "OpenAI API key"

# 2. Create an agent with scoped access
phoenix agent create deployer -t "$(openssl rand -hex 32)" --acl "myapp/*:list,read_value"

# 3. Verify the agent can access the secret
phoenix policy test --agent deployer --ip 10.0.0.5 myapp/api-key

# 4. Validate references in config files
phoenix verify --dry-run docker-compose.yml

# 5. Review the setup
phoenix status

# 6. Check audit trail
phoenix audit -n 10
```
