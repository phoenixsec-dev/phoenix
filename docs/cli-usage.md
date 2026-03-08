# Phoenix CLI Usage

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

## Batch resolution API

```bash
curl -X POST https://localhost:9090/v1/resolve \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"refs": ["phoenix://myapp/db-password", "phoenix://myapp/api-key"]}'
```

Partial failures return per-ref errors without blocking successful resolutions.

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

## Related docs

- [Getting Started](getting-started.md)
- [Authentication](authentication.md)
- [Policy and Attestation](policy-and-attestation.md)
- [Integrations](integrations.md)
- [Sealed Responses](sealed-responses.md)
