<p align="center">
  <img src="docs/branding/phoenix-v0-w-name-H-E-unique.svg" alt="Phoenix logo" width="420"/>
</p>

<p align="center">
  <strong>Phoenix: Attested secrets for agents. Reference-first by design.</strong><br/>
  <em>Like a phoenix, access is short-lived by design—attested, scoped, and reborn only when needed.</em><br/>
  <strong>Mission: use <code>references</code> first and minimize raw secret exposure.</strong>
</p>

[![CI](https://github.com/phoenixsec/phoenix/actions/workflows/ci.yml/badge.svg)](https://github.com/phoenixsec/phoenix/actions/workflows/ci.yml)

### Branding assets

- Full logo: `docs/branding/phoenix-v0-w-name-H-E-unique.svg`
- Dark-mode monochrome: `docs/branding/phoenix-monochrome-icon.jpg`
- Color icon only: `docs/branding/phoenix-v0-color-icon-only.svg`

---

# Phoenix

Phoenix is a single-binary secrets manager purpose-built for AI agent workflows. LLM agents are powerful but fundamentally untrusted — they can leak secrets through output, store them in context or memory, or be tricked into passing them to attacker-controlled tools. Phoenix is designed for reference-first secret workflows (`phoenix://...`) resolved through authenticated, attested, policy-checked API calls. Every access is audited.

Phoenix is designed to be set up and operated by your AI agent. The security is real — AES-256-GCM envelope encryption, mutual TLS, attestation policies — but the complexity is absorbed by the agent, not by you. Your agent configures policies, issues certificates, and manages access. You store the secrets and verify the result.

```
# Store a secret
phoenix set myapp/api-key -v "sk-abc123" -d "OpenAI API key"

# Run a command with secrets injected (reference-first workflow)
phoenix exec --env OPENAI_KEY=phoenix://myapp/api-key -- python app.py

# Optional manual/debug inspection (plaintext output)
phoenix resolve phoenix://myapp/api-key
```

---

## Start Here

- **New install / first setup:** continue with [Quick Start](#quick-start)
- **Migrating from `.env` files:** follow [Migration Guide: `.env` to Phoenix](docs/migration-env-to-phoenix.md)
- **Runnable integration examples:** see [examples/README.md](examples/README.md)

---

## Reality check (current behavior)

Phoenix supports reference-first secret handling, but it does **not** currently enforce
"reference-only" usage for all clients. Any identity with read-capable access can still
retrieve plaintext via:

- `phoenix get`
- `phoenix resolve`
- direct API calls (`GET /v1/secrets/*`, `POST /v1/resolve`)

Use scoped ACLs, mTLS/attestation, and operational guardrails to minimize plaintext exposure.

---

## Why Phoenix?

Existing secrets managers (Vault, Infisical, Doppler, SOPS) assume the consumer is a trusted process. The app fetches a secret, holds it in memory, and the developer is trusted not to leak it. That model breaks with AI agents.

Secret *reference* features in agent frameworks (like OpenClaw's `SecretRef`) are a step forward — they move plaintext out of config files. But they're config hygiene tools, not security infrastructure. They have no encryption at rest, no access control between agents, no attestation, and no audit trail of who accessed what at runtime.

Phoenix is the layer underneath. It provides the actual vault, the identity verification, the policy engine, and the audit trail. Agent frameworks can use Phoenix as their secret backend through the exec provider pattern, MCP, or direct API calls.

| | Config ref tools | Phoenix |
|---|---|---|
| Plaintext out of configs | Yes | Yes |
| Encrypted at rest | No | AES-256-GCM envelope encryption |
| Per-agent access control | No | Glob-pattern ACL per agent |
| Identity attestation | No | mTLS + source IP + cert fingerprint |
| Runtime audit trail | No | Every access logged with identity |
| Credential stripping | No | `phoenix exec` strips broker creds |
| Key rotation | No | Two-phase commit KEK rotation |
| Certificate infrastructure | No | Built-in CA with CRL revocation |

---

## Features

**Encrypted Storage** — AES-256-GCM envelope encryption with per-namespace data encryption keys (DEKs) wrapped by a master key (KEK). Secrets are never stored in plaintext.

**Mutual TLS** — Built-in certificate authority issues 90-day agent certificates. Agents authenticate with client certs instead of (or in addition to) bearer tokens. CRL-based revocation supported.

**Access Control** — Per-agent permissions with glob-pattern path matching. Agents only see what they're allowed to see.

**Configurable Attestation** — Each secret path can have its own attestation requirements, from no attestation to full lockdown. You choose the security level that fits each secret:

| Level | What it proves | Config |
|---|---|---|
| None | Agent has valid credentials | *(default)* |
| Network-bound | Request comes from expected host | `source_ip` |
| Identity-pinned | Specific certificate required | `cert_fingerprint` |
| mTLS-only | Cryptographic identity, no tokens | `require_mtls` + `deny_bearer` |

Levels compose — a production database password can require mTLS from a specific IP with a pinned cert, while a staging API key just needs a valid token.

**Reference Resolution** — `phoenix://namespace/secret` references are opaque tokens safe to store in configs, prompts, and logs. Resolved only through the authenticated API.

**Exec Wrapper** — `phoenix exec` resolves references and injects them as environment variables, then replaces itself with your command. Broker credentials are stripped from the child process — the child can only use the secrets you explicitly map.

**Crash-Safe Key Rotation** — Master key rotation uses two-phase commit with pre-rotation backups. If anything fails mid-rotation, the system recovers automatically.

**Full Audit Trail** — Every secret access, denial, and resolution attempt is logged with agent identity, action, path, IP, and reason. Audit logs are append-only JSON Lines. Secret values are never logged.

**Agent-Native Integration** — MCP server mode for Claude Code/Desktop. Works as an OpenClaw exec backend. SDK clients for Go, Python, and TypeScript. Your agent framework talks to Phoenix natively.

**Minimal Dependencies** — Single binary, no external services. Only `golang.org/x/crypto` (Argon2id) and `golang.org/x/term` (TTY passphrase input) — Go team semi-stdlib.

---

## Additional Docs

- [Public Roadmap](docs/roadmap.md)
- [Threat Model](docs/threat-model.md)
- [Migration Guide: `.env` to Phoenix](docs/migration-env-to-phoenix.md)
- [Admin Token Lifecycle](docs/admin-token-lifecycle.md)
- [API Reference Index](docs/api-reference-index.md)
- [Reference-Only Enforcement Design (WIP)](docs/reference-only-enforcement-design.md)
- [Release Runbook](docs/release-runbook.md)
- [Runnable Examples](examples/README.md)

---

## Quick Start

### Requirements

- Go 1.25+ (no external dependencies)
- Linux, macOS, or Windows

### Install from GitHub Releases

```bash
curl -fsSL https://raw.githubusercontent.com/phoenixsec/phoenix/main/scripts/install.sh | sh
```

Options:
- `PHOENIX_VERSION=vX.Y.Z` pin a specific release
- `INSTALL_DIR=/custom/bin` choose install path

### Build

```bash
git clone https://github.com/phoenixsec/phoenix.git
cd phoenix
go build -o bin/ ./cmd/...
```

This produces two binaries:
- `bin/phoenix` — CLI client
- `bin/phoenix-server` — API server

### Initialize

```bash
./bin/phoenix-server --init /data/phoenix
```

This generates:
- Master encryption key (`master.key`, mode `0600`)
- Admin bearer token — **save this, it is only shown once**
- Internal CA certificate and key
- Server TLS certificate (SANs: `localhost`, `127.0.0.1`)
- Default configuration file

> **Admin token handling (important):**
> 1. Store it immediately in a password manager or secure vault (not shell history, chat logs, or committed files).
> 2. Use it as a bootstrap credential only: create scoped agent identities/tokens and mTLS certs for regular workloads.
> 3. Remove it from your shell env after bootstrap (`unset PHOENIX_TOKEN`).
> 4. Review the full lifecycle guide: [docs/admin-token-lifecycle.md](docs/admin-token-lifecycle.md).

> **Deploying on a LAN?** The default server cert only covers localhost.
> After init, edit `config.json` to set `server.listen` to your host IP,
> then re-issue a server cert that includes it:
>
> ```bash
> phoenix cert issue phoenix-server -o .
> ```
>
> Alternatively, put Phoenix behind a reverse proxy that terminates TLS.

**File permissions:** The init command creates files with secure defaults, but verify:
```bash
chmod 700 /data/phoenix
chmod 600 /data/phoenix/master.key /data/phoenix/ca.key /data/phoenix/server.key
```

### Start the Server

```bash
./bin/phoenix-server --config /data/phoenix/config.json
```

```
Phoenix server starting on 127.0.0.1:9090
  Store: /data/phoenix/store.json (0 secrets)
  Key provider: file
  ACL: /data/phoenix/acl.json (1 agents)
  Audit: /data/phoenix/audit.log
  mTLS: enabled (require=false)
  Bearer: true
```

> **Binding to all interfaces:** The default listen address is `127.0.0.1:9090` (loopback only).
> To accept connections from other hosts, set `server.listen` to `0.0.0.0:9090` in your config file.
> Only do this with mTLS enabled or behind a firewall — the server should not be exposed without authentication on a public network.

### Store and Retrieve Secrets

```bash
export PHOENIX_SERVER="https://localhost:9090"
export PHOENIX_TOKEN="<your-admin-token>"
export PHOENIX_CA_CERT="/data/phoenix/ca.crt"

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

---

## Agent Authentication

### Bearer Tokens

The simplest method. Create an agent with specific permissions:

```bash
phoenix agent create deployer \
  -t "deploy-token-abc" \
  --acl "myapp/*:read;staging/*:read,write"
```

The `deployer` agent can read anything under `myapp/` and read/write under `staging/`.

### Mutual TLS (Recommended)

Issue a client certificate for an agent:

```bash
phoenix cert issue deployer -o /etc/phoenix/certs/
```

This writes `deployer.crt`, `deployer.key`, and `ca.crt`. Configure the agent:

```bash
export PHOENIX_SERVER="https://phoenix.home:9090"
export PHOENIX_CA_CERT="/etc/phoenix/certs/ca.crt"
export PHOENIX_CLIENT_CERT="/etc/phoenix/certs/deployer.crt"
export PHOENIX_CLIENT_KEY="/etc/phoenix/certs/deployer.key"

phoenix get myapp/db-password
```

No bearer token needed — the certificate CN identifies the agent.

---

## Reference Resolution

To minimize secret exposure in agent context, use `phoenix://` references instead of plaintext in configs/prompts:

```bash
# Resolve a single reference (outputs raw value, pipeable)
phoenix resolve phoenix://myapp/db-password
hunter2

# Resolve multiple references
phoenix resolve phoenix://myapp/db-password phoenix://myapp/api-key
phoenix://myapp/db-password	hunter2
phoenix://myapp/api-key	sk-live-abc123
```

### Batch Resolution API

```bash
curl -X POST https://localhost:9090/v1/resolve \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"refs": ["phoenix://myapp/db-password", "phoenix://myapp/api-key"]}'
```

```json
{
  "values": {
    "phoenix://myapp/db-password": "hunter2",
    "phoenix://myapp/api-key": "sk-live-abc123"
  }
}
```

Partial failures return per-ref errors without blocking successful resolutions.

---

## Exec Wrapper

Run commands with secrets injected as environment variables:

```bash
phoenix exec \
  --env DB_PASSWORD=phoenix://myapp/db-password \
  --env STRIPE_KEY=phoenix://myapp/api-key \
  -- node server.js
```

Phoenix resolves all references, strips its own credentials (`PHOENIX_TOKEN`, `PHOENIX_CLIENT_CERT`, etc.) from the child environment, and `exec`s into the command. The child process:
- Gets `DB_PASSWORD=hunter2` and `STRIPE_KEY=sk-live-abc123` in its environment
- Cannot call Phoenix directly (no broker credentials)
- Never sees `phoenix://` references

This enforces least-privilege: the child only gets the specific secrets you map.

Additional exec flags:
- `--timeout 5s` — fail if secret resolution exceeds the given duration
- `--mask-env` — also strip any inherited env vars whose values contain `phoenix://` references
- `--output-env <path>` — write resolved env to a file instead of exec'ing (for Docker init-container patterns)

**Secure secret input** — avoid pasting secrets in command arguments:

```bash
echo "my-secret" | phoenix set myapp/api-key --value-stdin
```

---

## Attestation Policies

Attestation policies let you configure security requirements per secret path. Every path can have different requirements — from completely open to fully locked down.

### Example: Graduated Security

```json
{
  "attestation": {
    "dev/*": {
      "require_mtls": false,
      "deny_bearer": false
    },
    "staging/*": {
      "require_mtls": true,
      "source_ip": ["192.168.0.0/24"]
    },
    "production/*": {
      "require_mtls": true,
      "deny_bearer": true,
      "source_ip": ["192.168.0.110", "192.168.0.115"],
      "cert_fingerprint": "sha256:A1B2C3..."
    }
  }
}
```

- `dev/*` — any valid credential works
- `staging/*` — must use mTLS, must be on the local network
- `production/*` — must use a specific certificate, from a specific IP, no bearer tokens

Add to your server config:

```json
{
  "policy": {
    "path": "/data/phoenix/policy.json"
  }
}
```

Attestation is enforced on secret reads, reference resolution, and path listing.

### Test Policies from the CLI

```bash
export PHOENIX_POLICY="/data/phoenix/policy.json"

# Show requirements for a path
phoenix policy show production/db-password

# Dry-run an attestation check
phoenix policy test --agent deployer --ip 192.168.0.110 production/db-password
```

`phoenix policy test` is a local approximation helper. It is useful for
policy sanity checks, but it does not fully simulate live cryptographic proof
paths (mTLS handshakes, nonce freshness/replay state, signed payload validation).

---

## Agent Framework Integration

### MCP Server (Claude Code / Claude Desktop)

Phoenix includes a built-in MCP server. Agents resolve secrets through tool calls, which can keep values out of prompt text in many workflows.

**Transport options:**
- `phoenix mcp-server` → stdio JSON-RPC (best for local Claude Code/Desktop setup)
- `phoenix mcp-server --http :8080 --mcp-token <token>` → Streamable HTTP on `/mcp` (best for remote/shared MCP clients)

```json
{
  "mcpServers": {
    "phoenix": {
      "command": "phoenix",
      "args": ["mcp-server"],
      "env": {
        "PHOENIX_SERVER": "https://phoenix:9090",
        "PHOENIX_TOKEN": "..."
      }
    }
  }
}
```

Streamable HTTP mode example:

```bash
export PHOENIX_SERVER="https://phoenix:9090"
export PHOENIX_TOKEN="<phoenix-agent-token>"
export PHOENIX_MCP_TOKEN="<separate-mcp-client-token>"
phoenix mcp-server --http 127.0.0.1:8080
```

Then point your MCP client to `http://127.0.0.1:8080/mcp` with:
- `Authorization: Bearer <PHOENIX_MCP_TOKEN>`
- `Mcp-Session-Id: <session-id>` after `initialize`

The agent can list available secrets, resolve references, and read values — all through the authenticated, policy-checked API. MCP tool calls include tool identity headers (`X-Phoenix-Tool`), enabling `allowed_tools`/`deny_tools` attestation policies to control which MCP tools can access which secrets.

> **Security note:** `phoenix_get` and `phoenix_resolve` return plaintext secret values in the MCP tool response. This may keep values out of prompt text, but the tool output is still visible to the MCP client process. Scope production tokens and ACLs tightly — grant agents only the minimum paths they need.

### Claude Code Skill (SKILL.md)

Phoenix also includes a reusable skill definition at `phoenix-skill/SKILL.md`.
Use it when you want command-driven integration without running MCP server mode.

The skill includes:
- operational commands (`set/get/list/resolve/status/policy/audit`)
- safety guardrails (avoid pasting secrets in chat, prefer `--value-stdin`)
- a runbook for adding secrets and granting scoped agent access

### OpenClaw Exec Backend

Phoenix works as an OpenClaw external secrets provider through the `exec` backend. OpenClaw's `SecretRef` system handles config-level reference mapping. Phoenix handles encryption, access control, attestation, and audit. Each layer does what it's good at.

**1. Configure the exec provider** in your OpenClaw config:

```json
{
  "secrets": {
    "providers": {
      "phoenix": {
        "type": "exec",
        "command": "phoenix",
        "args": ["resolve"]
      }
    }
  }
}
```

**2. Use SecretRefs backed by Phoenix** in your gateway config:

```yaml
api_keys:
  openai: ${{ secrets.phoenix.phoenix://myapp/openai-key }}
  anthropic: ${{ secrets.phoenix.phoenix://myapp/anthropic-key }}
```

**3. Set Phoenix credentials** for the OpenClaw process:

```bash
export PHOENIX_SERVER=https://phoenix:9090
export PHOENIX_TOKEN=openclaw-agent-token
# Or use mTLS:
export PHOENIX_CA_CERT=/etc/phoenix/ca.crt
export PHOENIX_CLIENT_CERT=/etc/phoenix/openclaw.crt
export PHOENIX_CLIENT_KEY=/etc/phoenix/openclaw.key
```

**4. Validate** before deploying:

```bash
# Dry-run: verify all refs are accessible without exposing values
phoenix verify --dry-run gateway-config.yaml

# Check that the OpenClaw agent has the right permissions
phoenix policy test --agent openclaw --ip 10.0.0.5 myapp/openai-key
```

**What each layer does:**

| Concern | OpenClaw | Phoenix |
|---------|----------|---------|
| Config reference mapping | SecretRef extraction and resolution | - |
| Encryption at rest | - | AES-256-GCM envelope encryption |
| Access control | - | Per-agent ACLs with glob matching |
| Runtime attestation | - | mTLS, IP-binding, process identity |
| Audit trail | - | Append-only JSON Lines audit log |
| Credential rotation | - | `phoenix rotate-master`, cert reissue |

### Python SDK

```bash
pip install phoenix-secrets  # or: pip install sdk/python
```

```python
from phoenix_secrets import PhoenixClient

client = PhoenixClient()  # reads PHOENIX_SERVER + PHOENIX_TOKEN from env

# Resolve a single secret
api_key = client.resolve("phoenix://myapp/api-key")

# Batch resolve
result = client.resolve_batch([
    "phoenix://myapp/openai-key",
    "phoenix://myapp/db-password",
])
for ref, value in result["values"].items():
    print(f"{ref} = {value[:4]}...")

# Dry-run verify (no plaintext returned)
check = client.verify(["phoenix://myapp/api-key"])

# Health check
client.health()  # {"status": "ok"}
```

### Direct API

For any agent framework, the HTTP API is straightforward:

```bash
# Resolve references
curl -X POST https://phoenix:9090/v1/resolve \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"refs": ["phoenix://myapp/api-key"]}'

# Read a secret
curl https://phoenix:9090/v1/secrets/myapp/api-key \
  -H "Authorization: Bearer $TOKEN"
```

---

## Key Rotation

Rotate the master encryption key without downtime:

```bash
phoenix rotate-master
```

```
Master key rotated successfully
  Namespaces re-wrapped: 5
  Old key backed up to: /data/phoenix/master.key.prev
```

This generates a new master key, re-wraps all namespace DEKs, and persists everything atomically. If the process crashes mid-rotation, the two-phase commit protocol ensures automatic recovery:

1. **Store save fails** — namespace entries roll back in memory, provider discards the pending key
2. **Key file write fails** — store file restored from pre-rotation backup via atomic rename
3. **Double failure** (store saved, key write failed, backup restore failed) — emergency key written to `.emergency-key` file for manual recovery

---

## Master Key Protection

The master key can be protected with a passphrase, similar to SSH key passphrases. This encrypts the key file at rest using Argon2id key derivation and AES-256-GCM. Existing unprotected deployments are completely unaffected — this feature is opt-in.

### Initialize with a passphrase

```bash
phoenix-server --init /data/phoenix --passphrase "my-strong-passphrase"
```

The generated `master.key` file will be JSON (passphrase-protected) instead of raw base64.

### Providing the passphrase at boot

When the master key is protected, the server needs the passphrase to start. Three methods, in priority order:

```bash
# 1. Pipe from stdin (automation, agents, systemd)
echo "my-passphrase" | phoenix-server --config /data/config.json --passphrase-stdin

# 2. Environment variable (containers, systemd EnvironmentFile)
PHOENIX_MASTER_PASSPHRASE="my-passphrase" phoenix-server --config /data/config.json

# 3. Interactive TTY prompt (human at terminal)
phoenix-server --config /data/config.json
# → Enter master key passphrase: ****
```

### Add or change passphrase on existing deployment

```bash
phoenix-server --protect-key --config /data/config.json
```

This prompts for the current passphrase (if protected), then the new passphrase. Enter an empty new passphrase to remove protection.

### Key rotation

Key rotation automatically preserves passphrase protection. If the current key is passphrase-protected, the rotated key file will be too, using the same passphrase.

> **Warning:** If you lose the passphrase, you lose your secrets. There is no recovery mechanism. Back up both the passphrase and the key file.

---

## Emergency Access

Break-glass offline secret retrieval when the server is down:

```bash
phoenix emergency get myapp/db-password --data-dir /data/phoenix
```

```
*** EMERGENCY ACCESS ***
Secret:   myapp/db-password
Data dir: /data/phoenix
This bypasses the server and will be logged to the audit trail.
Continue? [y/N] y

*** Access logged to /data/phoenix/audit.log ***
hunter2
```

For automation, use `--confirm` to skip the interactive prompt:

```bash
phoenix emergency get myapp/db-password --data-dir /data/phoenix --confirm
```

Emergency mode:
- Reads `store.json` and `master.key` directly from disk — no server needed
- Single secret only — no wildcards, no batch export, no listing
- Requires explicit confirmation — interactive `[y/N]` prompt or `--confirm` flag
- Prompts for passphrase if the master key is protected (via `--passphrase-stdin` or env/TTY)
- Logs the access to `audit.log` with agent `emergency-local`

This is a last resort for when the server is unavailable. It inherently requires filesystem access to the data directory, which limits it to the machine owner.

---

## Audit Log

Every operation is logged:

```bash
phoenix audit --last 10
```

```
2026-02-26T10:00:01Z  admin      write    myapp/db-password  allowed  192.168.0.117
2026-02-26T10:00:05Z  deployer   read     myapp/db-password  allowed  192.168.0.110
2026-02-26T10:00:08Z  scanner    read     myapp/db-password  denied   10.0.0.5       acl
2026-02-26T10:00:12Z  deployer   resolve  myapp/api-key      allowed  192.168.0.110
2026-02-26T10:00:15Z  rogue      resolve  production/key     denied   10.0.0.99      attestation
```

Filter by agent or time range:

```bash
phoenix audit --agent deployer --since 2026-02-26T00:00:00Z
```

Secret values are never written to the audit log.

---

## Import and Export

### Import from .env files

```bash
phoenix import secrets.env --prefix myapp/
```

```
imported: DB_PASSWORD -> myapp/db-password
imported: API_KEY -> myapp/api-key
imported 2 secrets
```

### Import from 1Password (one-time migration into Phoenix store)

```bash
export OP_SERVICE_ACCOUNT_TOKEN="ops_..."
phoenix import --from 1password --vault Engineering --prefix myapp/
```

Options:
- `--item <name>` import a single 1Password item
- `--dry-run` preview mappings without writing
- `--skip-existing` skip paths that already exist in Phoenix

Token env override for import:
- `PHOENIX_OP_TOKEN_ENV` — env var name containing the 1Password service account token (default: `OP_SERVICE_ACCOUNT_TOKEN`)

### Export as .env format

```bash
phoenix export myapp/ --format env > .env
```

```
DB_PASSWORD=hunter2
API_KEY=sk-live-abc123
```

---

## Architecture

```
+-----------+     phoenix://     +---------+     AES-256-GCM     +-------+
|  Agent /  | ---- resolve ----> | Phoenix | ---- envelope ----> | Store |
|   Tool    |     (mTLS/ACL/     | Server  |    encryption       | (JSON)|
+-----------+      attestation)  +---------+                     +-------+
                                      |
                                      v
                                 +---------+
                                 | Audit   |
                                 | Log     |
                                 +---------+
```

**Encryption model:** Each namespace gets its own DEK (data encryption key) generated on first write. DEKs are wrapped with the master KEK (key encryption key) and stored alongside encrypted secrets. The KEK never touches disk in plaintext — it's stored in a separate key file with restricted permissions.

**Authentication flow:** Request -> mTLS cert verification (if available) -> bearer token fallback -> ACL authorization -> attestation policy check -> secret access -> audit log.

### Package Structure

```
cmd/
  phoenix/           CLI client (includes MCP server mode)
  phoenix-server/    API server

internal/
  acl/               Access control lists with glob matching
  api/               REST API handlers and middleware
  audit/             Append-only structured audit logging
  ca/                Internal certificate authority (ECDSA P-256)
  config/            Server configuration loading and validation
  crypto/            AES-256-GCM encryption, key wrapping, key providers
  policy/            Attestation policy engine
  ref/               phoenix:// reference parsing and formatting
  store/             Encrypted secret storage with namespace isolation
```

---

## Configuration

The server reads a JSON config file. `config.example.json` is a starter template;
use the table below as the authoritative field reference.

Key settings:

| Field | Description | Default |
|-------|-------------|---------|
| `server.listen` | Bind address | `127.0.0.1:9090` |
| `store.path` | Encrypted store file | `/data/store.json` |
| `store.master_key` | Master key file | `/data/master.key` |
| `store.backend` | Secret backend (`file` or `1password`) | `file` |
| `acl.path` | ACL definition file | `/data/acl.json` |
| `audit.path` | Audit log file | `/data/audit.log` |
| `auth.bearer.enabled` | Allow bearer token auth | `true` |
| `auth.mtls.enabled` | Enable mTLS | `false` |
| `auth.mtls.require` | Reject connections without client cert | `false` |
| `policy.path` | Attestation policy file (optional) | — |
| `attestation.nonce.enabled` | Enable nonce challenge-response | `false` |
| `attestation.nonce.max_age` | Nonce TTL (e.g. `"30s"`) | `30s` |
| `attestation.token.enabled` | Enable short-lived token minting | `false` |
| `attestation.token.ttl` | Token lifetime (e.g. `"15m"`) | `15m` |
| `attestation.local_agent.enabled` | Enable local Unix-socket attestation agent | `false` |
| `attestation.local_agent.socket_path` | Unix socket path for local attestation agent (required when enabled) | — |
| `onepassword.vault` | 1Password vault name (required when `store.backend=1password`) | — |
| `onepassword.service_account_token_env` | Token env var name for server runtime backend | `OP_SERVICE_ACCOUNT_TOKEN` |
| `onepassword.cache_ttl` | Runtime read/list cache duration | `60s` |

### 1Password Runtime Backend (Broker Mode, Read-Only)

Phoenix can broker access to secrets stored in 1Password:

```json
{
  "store": {
    "backend": "1password"
  },
  "onepassword": {
    "vault": "Engineering",
    "service_account_token_env": "OP_SERVICE_ACCOUNT_TOKEN",
    "cache_ttl": "60s"
  }
}
```

Behavior:
- `GET/resolve/list` go through Phoenix ACL + attestation + audit, then read from 1Password
- `set/delete` are blocked (`read-only backend`)
- path mapping: `phoenix://myapp/api-key` -> `op://Engineering/myapp/api-key`

Rollback to managed mode:
1. set `store.backend` back to `"file"`
2. restart `phoenix-server`

Troubleshooting:
- missing `op` binary or token: server fails fast at startup with a clear error
- runtime list/read failures: request fails, audit still records access attempt
- `onepassword.cache_ttl` must be a duration string (for example `"60s"`). A
  bare number like `60` is invalid.

### Environment Variables (CLI)

| Variable | Description |
|----------|-------------|
| `PHOENIX_SERVER` | Server URL (default: `http://127.0.0.1:9090`) |
| `PHOENIX_TOKEN` | Bearer token for authentication |
| `PHOENIX_CA_CERT` | CA certificate for TLS verification |
| `PHOENIX_CLIENT_CERT` | Client certificate for mTLS |
| `PHOENIX_CLIENT_KEY` | Client key for mTLS |
| `PHOENIX_POLICY` | Policy file path (for `phoenix policy` commands) |
| `PHOENIX_OP_TOKEN_ENV` | (Import only) env var name holding 1Password token |

---

## Docker

```bash
docker pull phoenixsec/phoenix:latest

# First run: initialize the data directory
docker run --rm -v phoenix-data:/data phoenixsec/phoenix:latest --init /data

# Note the admin token printed to stdout — save it!

# Start the server
docker run -d --name phoenix \
  -v phoenix-data:/data \
  -p 9090:9090 \
  --restart unless-stopped \
  phoenixsec/phoenix:latest
```

Tag strategy:
- `latest` (most recent release)
- `vX.Y.Z` (exact release tag)
- `vX.Y` (minor line)

Or with Docker Compose:

```yaml
services:
  phoenix:
    image: phoenixsec/phoenix:latest
    ports:
      - "9090:9090"
    volumes:
      - phoenix-data:/data
    restart: unless-stopped

volumes:
  phoenix-data:
```

```bash
# First-time setup
docker compose run --rm phoenix --init /data

# Then start normally
docker compose up -d
```

> **Docker note:** The generated config inside the container defaults to `127.0.0.1:9090`.
> For Docker port mapping (`-p 9090:9090`) to work, set `server.listen` to `0.0.0.0:9090`
> in the container's config file, or use the provided `config.example.json` which already does this.

---

## Security Model

**What Phoenix protects against:**
- Secret exfiltration risk reduction via reference-first workflows (`phoenix://` + `phoenix exec`)
- Unauthorized access (ACL + configurable attestation policy per path)
- Credential replay from wrong network location (source IP binding)
- Stolen bearer tokens accessing sensitive paths (deny_bearer + mTLS)
- Data at rest exposure (AES-256-GCM envelope encryption)
- Audit trail gaps (append-only log, values never logged, every access recorded)
- Crash corruption during key rotation (two-phase commit + emergency recovery)
- Lateral movement between agents (per-agent ACL with namespace isolation)

**What Phoenix does NOT protect against:**
- Root/kernel compromise on the Phoenix host
- Side-channel or hardware attacks
- Malicious admin with direct file system access to the key file

Phoenix provides real security infrastructure — encryption, identity, access control, attestation, audit — in a package simple enough for an AI agent to deploy and manage. It is not a replacement for HSMs or cloud KMS in high-security enterprise environments.

---

## Development

```bash
# Run all tests
go test ./... -count=1

# Run tests with verbose output
go test ./... -count=1 -v

# Build both binaries
go build -o bin/ ./cmd/...
```

External dependencies: `golang.org/x/crypto` (Argon2id for passphrase KDF) and `golang.org/x/term` (TTY passphrase input).

---

## License

MIT
