# Phoenix Secrets — CLI Usage

## Store and retrieve secrets

```bash
# Store secrets
phoenix set myapp/db-password -v "hunter2" -d "Production database password"
phoenix set myapp/api-key -v "sk-live-abc123" -d "Stripe API key"

# Read a secret
phoenix get myapp/db-password

# List secrets
phoenix list myapp/

# Delete a secret
phoenix delete myapp/old-key
```

## Reference resolution

Use `phoenix://...` references to keep plaintext out of configs and many prompt flows.

```bash
# Resolve a single reference (outputs raw value, pipeable)
phoenix resolve phoenix://myapp/db-password

# Resolve multiple references
phoenix resolve phoenix://myapp/db-password phoenix://myapp/api-key
```

## Exec wrapper

```bash
phoenix exec \
  --env DB_PASSWORD=phoenix://myapp/db-password \
  --env STRIPE_KEY=phoenix://myapp/api-key \
  -- node server.js
```

Phoenix resolves all references, strips its own credentials from the child
environment, and then `exec`s into the command. The child gets only the mapped
secret values, not the broker credentials.

Additional exec flags:
- `--timeout 5s`
- `--mask-env`
- `--output-env <path>`

## Secure secret input

```bash
echo "my-secret" | phoenix set myapp/api-key --value-stdin
```

Prefer `--value-stdin` over pasting secrets directly into command arguments.

## Audit log

```bash
phoenix audit --last 10
phoenix audit --agent deployer --since 2026-02-26T00:00:00Z
```

Secret values are never written to the audit log.

## Import and export

### Import from `.env`

```bash
phoenix import secrets.env --prefix myapp/
```

### Import from 1Password (one-time migration)

```bash
export OP_SERVICE_ACCOUNT_TOKEN="ops_..."
phoenix import --from 1password --vault Engineering --prefix myapp/
```

Options:
- `--item <name>` import a single 1Password item
- `--dry-run` preview mappings without writing
- `--skip-existing` skip paths that already exist in Phoenix

### Export as `.env`

```bash
phoenix export myapp/ --format env > .env
```

## Session management

```bash
# List active sessions (admin sees all, non-admin sees own)
phoenix sessions list
phoenix sessions list --role dev
phoenix sessions list --agent deployer

# Show session details
phoenix sessions info ses_abc123def456

# Revoke a session (immediate effect)
phoenix sessions revoke ses_abc123def456

# Approve a step-up session request
phoenix approve apr_xyz789
```

When `PHOENIX_ROLE` is set, the CLI auto-mints a session on the first request
and caches it for the session lifetime:

```bash
export PHOENIX_ROLE=dev
phoenix get dev/api-key  # mints session, then reads
phoenix get dev/db-pass  # reuses cached session
```

See [Session Identity](session-identity.md) for full details.

## Agent management

```bash
# Create an agent with scoped ACL (admin only)
phoenix agent create deployer \
  -t "$(openssl rand -hex 32)" \
  --acl "myapp/*:read;staging/*:read,write"

# Update an existing agent (re-create with --force)
phoenix agent create deployer \
  -t "$(openssl rand -hex 32)" \
  --acl "myapp/*:read,write" --force

# List all agents (admin only)
phoenix agent list

# Delete an agent (admin only)
phoenix agent delete deployer
```

## Certificate management

Requires `auth.mtls.enabled: true` in the server config.

```bash
# Issue a client certificate for an agent (admin only)
phoenix cert issue deployer -o /etc/phoenix/certs/

# Revoke a certificate by serial number (admin only)
phoenix cert revoke <serial-number>
```

## Sealed key pairs

```bash
# Generate a seal key pair for an agent
phoenix keypair generate myagent -o /etc/phoenix/keys/

# The private key is written to <name>.seal.key
# The public key is printed to stdout
```

Set `PHOENIX_SEAL_KEY` to the private key path to enable sealed mode.
See [Sealed Responses](sealed-responses.md).

## Server status

```bash
phoenix status
```

Shows server health, secret count, agent count, policy summary, and recent
audit activity.

## Reference verification

```bash
# Verify all phoenix:// references in a file are resolvable
phoenix verify config.yaml

# Dry-run — checks access without resolving values
phoenix verify --dry-run config.yaml
```

## Emergency access

Break-glass secret retrieval directly from disk when the server is down:

```bash
phoenix emergency get myapp/db-password --data-dir /data/phoenix
```

Requires direct access to the data directory. Logs the access to the audit
trail with agent `emergency-local`. See [Key Management](key-management.md).

## Master key management

```bash
# Rotate the master encryption key
phoenix rotate-master

# Add or change passphrase protection on the master key
phoenix-server --protect-key --config /data/phoenix/config.json
```

See [Key Management](key-management.md) for details.

## Policy testing

```bash
# Show attestation requirements for a path
phoenix policy show production/db-password

# Dry-run an attestation check
phoenix policy test --agent deployer --ip 192.168.0.110 production/db-password
```

Requires `PHOENIX_POLICY` to point to the policy JSON file.

## Related docs

- [Getting Started](getting-started.md)
- [Authentication](authentication.md)
- [Session Identity](session-identity.md)
- [Policy and Attestation](policy-and-attestation.md)
- [Integrations](integrations.md)
- [Sealed Responses](sealed-responses.md)
