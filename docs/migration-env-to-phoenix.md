# Migration Guide: `.env` Files to Phoenix

This guide moves a project from plaintext `.env` secrets to `phoenix://` references and policy-gated runtime resolution.

## 1) Inventory existing secrets

Identify secrets currently in:

- `.env` / `.env.production`
- CI variables
- Docker Compose env blocks
- framework config files

Group by namespace you want in Phoenix (for example `myapp/*`, `staging/*`, `production/*`).

## 2) Initialize Phoenix

Follow [Getting Started](getting-started.md) to install, initialize, and start
the server. Come back here once you have a running server and admin token.

## 3) Import secrets into Phoenix

Bulk import from an existing `.env` file:

```bash
phoenix import secrets.env --prefix myapp/
```

Or store individually:

```bash
phoenix set myapp/db-password -v "..." -d "DB password"
phoenix set myapp/api-key -v "..." -d "API key"
```

See [CLI Usage](cli-usage.md) for import options including 1Password migration
(`--from 1password`), `--dry-run`, and `--skip-existing`.

## 4) Create least-privilege agent identities

```bash
phoenix agent create myapp-runtime -t "runtime-token" --acl "myapp/*:read"
phoenix agent create myapp-deployer -t "deploy-token" --acl "myapp/*:read,write"
```

For production, prefer mTLS certs over bearer tokens.
See [Authentication](authentication.md) for mTLS setup.

## 5) Replace plaintext values with references

Before:

```env
DB_PASSWORD=super-secret
OPENAI_KEY=sk-live-abc
```

After:

```env
DB_PASSWORD=phoenix://myapp/db-password
OPENAI_KEY=phoenix://myapp/api-key
```

## 6) Resolve at runtime (without exposing broker creds to child)

```bash
phoenix exec \
  --env DB_PASSWORD=phoenix://myapp/db-password \
  --env OPENAI_KEY=phoenix://myapp/api-key \
  -- your-app-command
```

For init-container style workflows:

```bash
phoenix exec \
  --env DB_PASSWORD=phoenix://myapp/db-password \
  --env OPENAI_KEY=phoenix://myapp/api-key \
  --output-env /run/secrets/app.env
```

If your agent platform uses MCP over HTTP instead of local stdio, run Phoenix MCP in Streamable HTTP mode:

```bash
export PHOENIX_SERVER="https://localhost:9090"
export PHOENIX_TOKEN="<phoenix-agent-token>"
export PHOENIX_MCP_TOKEN="<mcp-client-token>"
phoenix mcp-server --http 127.0.0.1:8080
```

Use `http://127.0.0.1:8080/mcp` as the MCP endpoint. Keep `PHOENIX_MCP_TOKEN` separate from `PHOENIX_TOKEN`.

## 7) Validate and audit

- Verify app startup succeeds with references only.
- Confirm denied access for out-of-scope paths.
- Query audit log:

```bash
phoenix audit -n 50
```

## 8) Decommission plaintext

- Remove secrets from `.env` files and history where possible.
- Rotate old credentials that were previously committed or shared.
- Remove legacy env injection paths from CI/CD.

## Rollback strategy

If needed, keep a temporary rollback path:

1. retain old env source for one deployment window
2. switch runtime command from `phoenix exec` back to prior launcher
3. diagnose ACL/policy failures via audit logs
4. re-enable `phoenix exec` after fixes
