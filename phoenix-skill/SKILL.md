# Phoenix Secrets Manager

Manage secrets securely through the Phoenix secrets management system.
Secrets are encrypted at rest (AES-256-GCM), access-controlled per agent,
and audited. You work with `phoenix://` references — never raw secret values.

## Commands

Use the `phoenix` CLI for all operations. The CLI must be configured with
environment variables before use:

- `PHOENIX_SERVER` — server URL (default: `http://127.0.0.1:9090`)
- `PHOENIX_TOKEN` — bearer token for authentication
- `PHOENIX_CA_CERT` — CA certificate path (for TLS)
- `PHOENIX_CLIENT_CERT` / `PHOENIX_CLIENT_KEY` — mTLS client auth

### Read a secret

```bash
phoenix get <namespace/key>
```

Returns the decrypted value. Use sparingly — prefer `phoenix://` references.

### Store a secret

```bash
phoenix set <namespace/key> -v "<value>" -d "description" --tags "tag1,tag2"
```

### List secrets

```bash
phoenix list [prefix]
```

Returns accessible secret paths. Use a prefix to filter by namespace.

### Delete a secret

```bash
phoenix delete <namespace/key>
```

### Resolve references

```bash
phoenix resolve phoenix://namespace/key [phoenix://namespace/key2 ...]
```

Resolves one or more `phoenix://` references to their values.

### Run a command with secrets injected

```bash
phoenix exec --env KEY=phoenix://namespace/secret -- <command> [args...]
```

Resolves references and injects them as environment variables into the child
process. Phoenix broker credentials are stripped from the child environment.

To write resolved env vars to a file instead of exec'ing (for Docker init-container patterns):

```bash
phoenix exec --env KEY=phoenix://namespace/secret --output-env /path/to/envfile -- true
```

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
phoenix agent create <name> -t <token> --acl "namespace/*:read,write;other/*:read"
```

Creates a new agent with the specified ACL permissions (admin only).

### List agents

```bash
phoenix agent list
```

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
phoenix audit [-n 20] [-a agent-name] [-s 2025-01-01T00:00:00Z]
```

Query the audit log. Filter by count, agent, or time range.

## Safety Guardrails

- **Never ask the user to paste secrets into chat** — use `phoenix set --value-stdin`
  or `phoenix import` so values never appear in conversation history
- Prefer `phoenix://` references in config files over hardcoded values
- Recommend least-privilege ACL scopes per agent (e.g. `namespace/*:read` not `*:admin`)
- Use `phoenix verify --dry-run` to validate references without exposing values
- Use `phoenix status` to review the security posture after setup
- All secret access is logged — use `phoenix audit` to review

## Runbook: Add a Secret and Grant Agent Access

Typical flow for setting up a new secret with proper access control:

```bash
# 1. Store the secret (human runs this, value from stdin)
echo "sk-live-abc123" | phoenix set myapp/api-key --value-stdin -d "OpenAI API key"

# 2. Create an agent with scoped access
phoenix agent create deployer -t "$(openssl rand -hex 32)" --acl "myapp/*:read"

# 3. Verify the agent can access the secret
phoenix policy test --agent deployer --ip 10.0.0.5 myapp/api-key

# 4. Validate references in config files
phoenix verify --dry-run docker-compose.yml

# 5. Review the setup
phoenix status

# 6. Check audit trail
phoenix audit -n 10
```
