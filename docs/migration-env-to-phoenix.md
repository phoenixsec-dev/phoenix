# Migration Guide: `.env` Files to Phoenix

This guide moves a project from plaintext `.env` secrets to `phoenix://` references and policy-gated runtime resolution.

## 1) Inventory existing secrets

Identify secrets currently in:

- `.env` / `.env.production`
- CI variables
- Docker Compose env blocks
- framework config files

Group by namespace you want in Phoenix (for example `myapp/`, `staging/`, `production/`).

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
phoenix set myapp/db-password -d "DB password"   # paste the value when asked
phoenix set myapp/api-key -d "API key"
```

See [CLI Usage](cli-usage.md) for import options including 1Password migration
(`--from 1password`), `--dry-run`, and `--skip-existing`.

## 4) Create least-privilege agent identities

```bash
phoenix agent create myapp-runtime -t "runtime-token" --acl "myapp/**:list,read_value"
phoenix agent create myapp-deployer -t "deploy-token" --acl "myapp/**:list,read_value,write"
```

`myapp/**` grants access to everything under `myapp/`, including nested paths;
`myapp/*` would match one level only. See
[ACL path patterns](authentication.md#acl-path-patterns).

For production, give agents session roles (`PHOENIX_ROLE`) so day-to-day
requests use short-lived, scoped tokens, and use HTTPS for anything that
crosses a wire. See [Authentication](authentication.md).

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

For init-container style workflows, run the app's entrypoint under
`phoenix exec` too rather than writing an env file: the values then live only
in the process environment, never on disk.

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
