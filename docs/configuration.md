# Phoenix Secrets — Configuration and Operations

## Configuration reference

The server reads a JSON config file. `config.example.json` is a starter template.

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
| `attestation.nonce.max_age` | Nonce TTL | `30s` |
| `attestation.token.enabled` | Enable short-lived token minting | `false` |
| `attestation.token.ttl` | Token lifetime | `15m` |
| `attestation.local_agent.enabled` | Enable local Unix-socket attestation agent | `false` |
| `attestation.local_agent.socket_path` | Unix socket path when enabled | — |
| `session.enabled` | Enable session identity | `false` |
| `session.ttl` | Default session lifetime | `1h` |
| `session.roles` | Named role definitions (see below) | — |
| `onepassword.vault` | 1Password vault name | — |
| `onepassword.service_account_token_env` | Token env var name | `OP_SERVICE_ACCOUNT_TOKEN` |
| `onepassword.cache_ttl` | Runtime read/list cache duration | `60s` |

## Session identity

Session identity replaces static tokens with short-lived, role-scoped sessions.
See [Session Identity](session-identity.md) for the full guide.

```json
{
  "session": {
    "enabled": true,
    "ttl": "1h",
    "roles": {
      "dev": {
        "namespaces": ["dev/*", "staging/*"],
        "actions": ["list", "read_value"],
        "bootstrap_trust": ["bearer"]
      },
      "deploy": {
        "namespaces": ["prod/*"],
        "actions": ["list", "read_value"],
        "bootstrap_trust": ["mtls"],
        "require_seal_key": true,
        "step_up": true,
        "step_up_ttl": "15m",
        "elevates_acl": true
      }
    }
  }
}
```

Each role defines: `namespaces` (required), `bootstrap_trust` (required),
`actions` (default: list + read_value), and optional fields for seal key
requirements, attestation, and step-up approval.

## Dashboard

The operator dashboard provides a browser-based UI for approvals, sessions,
audit, and role inspection. All assets are embedded — no CDN or build step.

Generate a password hash first:

```bash
phoenix-server --hash-password
# Enter dashboard password: ****
# Confirm dashboard password: ****
# $2a$10$...
```

Then add it to config:

```json
{
  "dashboard": {
    "enabled": true,
    "password_hash": "$2a$10$...",
    "session_ttl": "4h"
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `dashboard.enabled` | `bool` | Enable the dashboard at `/dashboard/` |
| `dashboard.password_hash` | `string` | bcrypt hash of operator password (generate with `phoenix-server --hash-password`) |
| `dashboard.pin` | `string` | Alternative: login PIN (constant-time compare, loopback only) |
| `dashboard.session_ttl` | `string` | Dashboard session lifetime (default `4h`) |
| `dashboard.allow_multi_login` | `bool` | Allow concurrent dashboard sessions (default `false`) |

Either `password_hash` or `pin` is required when the dashboard is enabled.
The password is stored as a bcrypt hash — the plaintext never appears in config.
Validation rejects non-bcrypt values in `password_hash` to prevent accidental
plaintext storage.

The dashboard uses cookie-based auth with HMAC-signed tokens and CSRF protection.
Login attempts are rate-limited with exponential backoff (5 failures before lockout,
up to 60s delay, per source IP). Failed login attempts are logged to the audit trail.

**Transport security:** When the server runs with mTLS enabled or behind a TLS
reverse proxy (detected via `X-Forwarded-Proto: https`), the session cookie is
set with `Secure` flag automatically. For production use:

- Run behind a TLS reverse proxy (e.g., Nginx Proxy Manager), or
- Use the built-in mTLS mode (`auth.mtls.enabled: true`), or
- Restrict to loopback access only (`server.listen: "127.0.0.1:9090"`)

Do not expose the dashboard over plain HTTP on a network you do not control.

## 1Password runtime backend (broker mode, read-only)

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
- `set/delete` are blocked
- path mapping: `phoenix://myapp/api-key` -> `op://Engineering/myapp/api-key`

## Transport security

The default configuration starts the server on plain HTTP at `127.0.0.1:9090`.
This is safe for local-only use — the server is not reachable from the network.

`phoenix-server --init` generates a CA and server certificate, but does **not**
enable TLS by default. To enable TLS, set `auth.mtls.enabled: true` in the
config. This activates server-side TLS using the generated certificate. You can
set `auth.mtls.require: false` to accept TLS connections without requiring
client certificates (agents can still use bearer tokens).

| Deployment | Config | Result |
|-----------|--------|--------|
| Local only | Default (`127.0.0.1`, mTLS disabled) | Plain HTTP on loopback — safe |
| LAN / remote | `0.0.0.0`, `auth.mtls.enabled: true` | TLS with optional client certs |
| Production | `0.0.0.0`, `auth.mtls.enabled: true`, `require: true` | Full mTLS required |
| Behind reverse proxy | `127.0.0.1`, proxy terminates TLS | Plain HTTP on loopback, TLS to clients |

See [LAN Deployment](lan-deployment.md) for the full multi-host setup.

## Architecture summary

```text
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

Authentication flow:
- request
- mTLS cert verification (if available)
- bearer fallback (if allowed)
- ACL authorization
- attestation policy check
- secret access
- audit log write

## Docker

Docker images are published to Docker Hub as `phoenixsecdev/phoenix`.

```bash
docker pull phoenixsecdev/phoenix:latest

# First run: initialize the data directory
docker run --rm -v phoenix-data:/data phoenixsecdev/phoenix:latest --init /data

# Start the server
docker run -d --name phoenix \
  -v phoenix-data:/data \
  -p 9090:9090 \
  --restart unless-stopped \
  phoenixsecdev/phoenix:latest
```

Docker Compose example:

```yaml
services:
  phoenix:
    image: phoenixsecdev/phoenix:latest
    ports:
      - "9090:9090"
    volumes:
      - phoenix-data:/data
    restart: unless-stopped

volumes:
  phoenix-data:
```

**Important:** The generated config defaults to `127.0.0.1:9090`. For Docker port
mapping to work, set `server.listen` to `0.0.0.0:9090` in the config.

## Related docs

- [Getting Started](getting-started.md)
- [Authentication](authentication.md)
- [Session Identity](session-identity.md)
- [Dashboard](dashboard.md) — operator UI deployment and security model
- [Key Management](key-management.md)
- [API Reference Index](api-reference-index.md)
