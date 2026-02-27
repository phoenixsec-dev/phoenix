# Phoenix

**Secrets management for homelabs and AI agents.**

Phoenix is a single-binary secrets manager built for small infrastructure: homelabs, self-hosted services, and AI agent workflows. It provides encrypted-at-rest storage, mutual TLS authentication, fine-grained access control, and an attestation policy engine — without the operational overhead of HashiCorp Vault or the limitations of dotenv files.

Agents and tools never see raw secrets. They work with `phoenix://` references that are resolved only through authenticated, policy-checked API calls. Every access is audited.

```
# Store a secret
phoenix set openclaw/api-key -v "sk-abc123" -d "OpenAI API key"

# Agents use references, not values
phoenix resolve phoenix://openclaw/api-key
sk-abc123

# Run a command with secrets injected as environment variables
phoenix exec --env OPENAI_KEY=phoenix://openclaw/api-key -- python app.py
```

---

## Features

**Encrypted Storage** — AES-256-GCM envelope encryption with per-namespace data encryption keys (DEKs) wrapped by a master key (KEK). Secrets are never stored in plaintext.

**Mutual TLS** — Built-in certificate authority issues 90-day agent certificates. Agents authenticate with client certs instead of (or in addition to) bearer tokens. CRL-based revocation supported.

**Access Control** — Per-agent permissions with glob-pattern path matching. Agents only see what they're allowed to see. Admin escalation grants all actions.

**Attestation Policies** — Bind secrets to specific network locations and identities:
- Deny bearer token access for sensitive paths (force mTLS)
- Source IP binding with CIDR support
- Certificate fingerprint pinning
- Per-path policy evaluation on every access

**Reference Resolution** — `phoenix://namespace/secret` references are opaque tokens safe to store in configs, prompts, and logs. Resolved only through the authenticated API.

**Exec Wrapper** — `phoenix exec` resolves references and injects them as environment variables, then replaces itself with your command. Broker credentials are stripped from the child process — the child can only use the secrets you explicitly map.

**Crash-Safe Key Rotation** — Master key rotation uses two-phase commit with pre-rotation backups. If anything fails mid-rotation, the system recovers automatically. Emergency key persistence handles even double-failure scenarios.

**Full Audit Trail** — Every secret access, denial, and resolution attempt is logged with agent identity, action, path, IP, and reason. Audit logs are append-only JSON Lines.

**Zero Dependencies** — Pure Go standard library. Single binary. No external services required.

---

## Quick Start

### Requirements

- Go 1.25+ (no external dependencies)
- Linux, macOS, or Windows

### Build

```bash
git clone https://github.com/youruser/phoenix.git
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

> **Deploying on a LAN?** The default server cert only covers localhost.
> After init, edit `config.json` to set `server.listen` to your host IP,
> then re-issue a server cert that includes it:
>
> ```bash
> # From your Phoenix data directory
> phoenix cert issue phoenix-server -o .
> # Or regenerate manually with your CA tooling, adding SANs like:
> #   192.168.0.110, phoenix.home, etc.
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
Phoenix server starting on 0.0.0.0:9090
  Store: /data/phoenix/store.json (0 secrets)
  Key provider: file
  ACL: /data/phoenix/acl.json (1 agents)
  Audit: /data/phoenix/audit.log
  mTLS: enabled (require=false)
  Bearer: true
```

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

Agents should never handle raw secrets in their context. Instead, they work with `phoenix://` references:

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

---

## Attestation Policies

Attestation policies add security requirements beyond ACL checks. Create a policy file:

```json
{
  "attestation": {
    "production/*": {
      "require_mtls": true,
      "deny_bearer": true,
      "source_ip": ["192.168.0.110", "192.168.0.115"],
      "cert_fingerprint": "sha256:A1B2C3..."
    },
    "staging/*": {
      "require_mtls": true,
      "source_ip": ["192.168.0.0/24"]
    }
  }
}
```

Add to your server config:

```json
{
  "policy": {
    "path": "/data/phoenix/policy.json"
  }
}
```

Now `production/*` secrets:
- Require mTLS (bearer tokens rejected)
- Only resolve from two specific IPs
- Only resolve for a specific certificate fingerprint

Attestation is enforced on secret reads, reference resolution, and path listing.

### Test Policies from the CLI

```bash
export PHOENIX_POLICY="/data/phoenix/policy.json"

# Show requirements for a path
phoenix policy show production/db-password

# Dry-run an attestation check
phoenix policy test --agent deployer --ip 192.168.0.110 production/db-password
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
  phoenix/           CLI client
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

The server reads a JSON config file. See `config.example.json` for a full reference.

Key settings:

| Field | Description | Default |
|-------|-------------|---------|
| `server.listen` | Bind address | `0.0.0.0:9090` |
| `store.path` | Encrypted store file | `/data/store.json` |
| `store.master_key` | Master key file | `/data/master.key` |
| `acl.path` | ACL definition file | `/data/acl.json` |
| `audit.path` | Audit log file | `/data/audit.log` |
| `auth.bearer.enabled` | Allow bearer token auth | `true` |
| `auth.mtls.enabled` | Enable mTLS | `false` |
| `auth.mtls.require` | Reject connections without client cert | `false` |
| `policy.path` | Attestation policy file (optional) | — |

### Environment Variables (CLI)

| Variable | Description |
|----------|-------------|
| `PHOENIX_SERVER` | Server URL (default: `http://127.0.0.1:9090`) |
| `PHOENIX_TOKEN` | Bearer token for authentication |
| `PHOENIX_CA_CERT` | CA certificate for TLS verification |
| `PHOENIX_CLIENT_CERT` | Client certificate for mTLS |
| `PHOENIX_CLIENT_KEY` | Client key for mTLS |
| `PHOENIX_POLICY` | Policy file path (for `phoenix policy` commands) |

---

## Docker

```bash
docker build -t phoenix .

# First run: initialize the data directory
docker run --rm -v phoenix-data:/data phoenix --init /data

# Note the admin token printed to stdout — save it!

# Start the server
docker run -d --name phoenix \
  -v phoenix-data:/data \
  -p 9090:9090 \
  --restart unless-stopped \
  phoenix
```

Or with Docker Compose:

```yaml
services:
  phoenix:
    build: .
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

---

## Security Model

**What Phoenix protects against:**
- Secret exfiltration via agent output (agents never see raw values)
- Unauthorized access (ACL + attestation policy)
- Credential replay from wrong network location (source IP binding)
- Stolen bearer tokens accessing sensitive paths (deny_bearer + mTLS)
- Data at rest exposure (AES-256-GCM envelope encryption)
- Audit trail tampering (append-only log, values never logged)
- Crash corruption during key rotation (two-phase commit + emergency recovery)

**What Phoenix does NOT protect against:**
- Root/kernel compromise on the Phoenix host
- Side-channel or hardware attacks
- Malicious admin with direct file system access to the key file

Phoenix is designed for trusted-network, small-infrastructure deployments where the operator controls the machines. It is not a replacement for HSMs or cloud KMS in high-security enterprise environments.

---

## Development

```bash
# Run all tests (126 tests across 9 packages)
go test ./... -count=1

# Run tests with verbose output
go test ./... -count=1 -v

# Build both binaries
go build -o bin/ ./cmd/...
```

The project has zero external dependencies — only the Go standard library.

---

## License

MIT

---

*Built for the [OpenClaw](https://github.com/openclaw) homelab.*
