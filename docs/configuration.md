# Phoenix Secrets — Configuration and Operations

## Configuration reference

The server reads a JSON config file. `config.example.json` is a starter template.
The example binds to loopback (`127.0.0.1`), where plaintext HTTP is the safe,
supported default. Binding a non-loopback address means requests cross a wire:
enable the `tls` block. The server starts either way, but logs a prominent
`INSECURE TRANSPORT` warning when a non-loopback bind would put bearer tokens
and secret values on the network in cleartext.

| Field | Description | Default |
|-------|-------------|---------|
| `server.listen` | Primary bind address | `127.0.0.1:9090` |
| `tls.enabled` | Serve HTTPS on the primary address (independent of mTLS) | `false` |
| `tls.cert` | Server certificate path | `auth.mtls.server_cert` (the `--init` leaf) |
| `tls.key` | Server private key path | `auth.mtls.server_key` |
| `https_listener.enabled` | Add a separate HTTPS endpoint | `false` |
| `https_listener.listen` | Additional bind address; required when enabled | — |
| `https_listener.cert` | Additional endpoint's server certificate; required when enabled | — |
| `https_listener.key` | Additional endpoint's private key; required when enabled | — |
| `store.path` | Encrypted store file | `/data/store.json` |
| `store.master_key` | Master key file | `/data/master.key` |
| `store.backend` | Secret backend (`file` or `1password`) | `file` |
| `acl.path` | ACL definition file | `/data/acl.json` |
| `audit.path` | Audit log file | `/data/audit.log` |
| `audit.rotate_mb` | Rotate the audit log at this size; archives are kept forever. Negative = never rotate. See [Audit log rotation](#audit-log-rotation) | `50` |
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
| `access_requests.*` | Request-use grants: agents ask a human for temporary use of exact secrets (see below) | block missing = off |
| `ssh_ca.*` | Short-lived SSH login certificates, approved through grants. See [SSH certificates](ssh-certificates.md) | block missing = off |
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
        "namespaces": ["dev/**", "staging/**"],
        "actions": ["list", "read_value"],
        "bootstrap_trust": ["bearer"]
      },
      "deploy": {
        "namespaces": ["prod/**"],
        "actions": ["list", "read_value"],
        "bootstrap_trust": ["mtls"],
        "require_seal_key": true,
        "step_up": true,
        "step_up_ttl": "15m",
        "elevates_acl": true,
        "allowed_agents": ["deployer"]
      }
    }
  }
}
```

Each role defines: `namespaces` (required), `bootstrap_trust` (required),
`actions` (default: list + read_value), and optional fields for seal key
requirements, attestation, step-up approval and `allowed_agents`.

`allowed_agents` binds a role to named ACL agents. It is checked at mint,
at step-up approval and at renewal (`403 ROLE_NOT_ALLOWED`). Empty means any
agent whose auth method is in `bootstrap_trust`. The server logs a `WARNING`
at startup for each `step_up` role without it, and for listed names that are
not in the ACL. The next release makes it required for `elevates_acl` roles.
See [Session Identity](session-identity.md#binding-a-role-to-agents-allowed_agents).

## Access requests

Agents that are denied a secret can ask a human for temporary use of exact
paths. Off when the block is missing (upgraded installs); on in
`config.example.json` and `--init`. Full guide, config reference and
troubleshooting: [Access Requests](access-requests.md).

```json
{
  "access_requests": {
    "enabled": true,
    "request_ttl": "15m",
    "default_grant_ttl": "1h",
    "max_grant_ttl": "8h",
    "grantable_actions": ["read_value"],
    "require_sealed": true,
    "bind_source_ip": true,
    "approvers": [],
    "deny_paths": ["phoenix/**"],
    "notify_url": "https://ntfy.example.net/phoenix-approvals",
    "notify_token_ref": "phoenix://phoenix/ntfy-token",
    "notify_include_paths": false,
    "notify_dashboard_url": "https://phoenix.example.net"
  }
}
```

The `notify_*` keys are optional. `notify_url` gets one POST per new request
(ntfy-style; agent, action, path count, request id, dashboard link; never the
reason). `notify_token_ref` names a secret in this Phoenix store that is sent
as a bearer token; never put the token itself in the config. The server
refuses to start if `notify_url` or `notify_dashboard_url` is not a plain
`http(s)://` URL or contains a `user:password@` part, or if
`notify_token_ref` is not a `phoenix://` reference.

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

**Transport security:** When a request arrives over TLS (the primary or optional
HTTPS endpoint) or through a TLS reverse proxy (detected via
`X-Forwarded-Proto: https`),
the session cookie is set with `Secure` flag automatically. For production use:

- Restrict to loopback access only (`server.listen: "127.0.0.1:9090"`), or
- Enable native TLS (`"tls": {"enabled": true}` — no client certs needed), or
- Run behind a TLS reverse proxy (e.g., Nginx Proxy Manager)

Do not expose the dashboard over plain HTTP on a network you do not control —
the server logs a loud startup warning if you do.

## Audit log rotation

When `audit.log` passes `audit.rotate_mb` (default 50), Phoenix renames it to a
dated archive in the same directory and starts a new `audit.log`:

```text
audit.log                                  current file
audit-20261108T120000.000Z.log             newest archive, plain text
audit-20261101T093000.000Z.log.gz          older archives, gzipped
```

- **Nothing is ever deleted.** Removing old archives is your decision.
- **No line is lost.** The rename happens while writers wait, so every line is
  in exactly one file. The archive name is the UTC time of the rotation.
- **The newest archive stays plain** until the next rotation, so the dashboard
  and `GET /v1/audit` can read it backwards when the current file is too short.
  Older archives are gzipped in the background; the plain file is removed only
  after its `.gz` is complete. Read them with `zcat`.
- An existing log larger than the limit is rotated on the first write after
  upgrading.
- Set `"rotate_mb": -1` only if you rotate the file another way, and then
  only while Phoenix is stopped. Phoenix keeps its file open, and
  copy-and-truncate on a running server can lose a line written between the
  copy and the truncate.

Queries (dashboard Audit page, Overview, `GET /v1/audit`, `phoenix audit`)
read from the end of the log and stop once they have enough entries, so they
stay fast however large the log grows. They search only the current file and
the newest archive, and at most 64 MB per query. When that cut a search short
the dashboard says so and the API returns `"truncated": true`.

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

Phoenix is LAN-scoped by design — internet/WAN exposure is out of scope and
unsupported (see [Threat Model](threat-model.md)). Within that envelope:

The default configuration starts the server on plain HTTP at `127.0.0.1:9090`.
This is safe for local-only use — loopback traffic never reaches a NIC, so the
server is not reachable from the network and TLS would add nothing.

The moment the listener crosses a wire, enable TLS. `phoenix-server --init`
generates a CA and server certificate; `"tls": {"enabled": true}` serves HTTPS
with them — no client certificates, no mTLS required:

```json
{
  "server": { "listen": "0.0.0.0:9090" },
  "tls": { "enabled": true }
}
```

`tls.cert` / `tls.key` override the certificate paths; when unset, the `--init`
server leaf (`auth.mtls.server_cert` / `server_key` paths) is used. mTLS is a
separate, optional layer for client-certificate authentication — enabling
`auth.mtls` also serves TLS, as it always has, but plain HTTPS no longer
requires it.

If you bind a non-loopback address without TLS, the server still starts but
logs a prominent `INSECURE TRANSPORT` warning: bearer tokens and every secret
value it returns would cross the network in cleartext.

| Deployment | Config | Result |
|-----------|--------|--------|
| Local only | Default (`127.0.0.1`, TLS disabled) | Plain HTTP on loopback — safe |
| LAN / remote | `0.0.0.0`, `"tls": {"enabled": true}` | HTTPS, bearer tokens still work |
| LAN + client certs | add `auth.mtls.enabled: true` (`require: false`) | HTTPS with optional client certs |
| Locked down | `auth.mtls.enabled: true`, `require: true` | Full mTLS required |
| Behind reverse proxy | `127.0.0.1`, proxy terminates TLS | Plain HTTP on loopback, TLS to clients |

See [LAN Deployment](lan-deployment.md) for the full multi-host setup,
including re-issuing the server certificate with LAN IP/hostname SANs.

### Optional HTTPS alongside the existing endpoint

Use `https_listener` to add HTTPS while existing consumers keep their HTTP
address and configuration. Both endpoints use the same handler, secret store,
ACLs, policies, sessions, rate limiter, and audit logger. The additional listener
uses the direct client address for source-IP policy, just like the primary.
HTTP requests are not redirected.

This fragment adds HTTPS on port 9443 while keeping HTTP on port 9090:

```json
{
  "server": { "listen": "0.0.0.0:9090" },
  "tls": { "enabled": false },
  "auth": {
    "bearer": { "enabled": true },
    "mtls": { "enabled": false }
  },
  "https_listener": {
    "enabled": true,
    "listen": "0.0.0.0:9443",
    "cert": "/data/server.crt",
    "key": "/data/server.key"
  }
}
```

Merge the fragment into your existing configuration. The checked-in example
keeps the additional listener disabled and bound to loopback. When enabled,
`listen`, `cert`, and `key` must all be explicit; this block does not inherit
certificate paths from `tls` or `auth.mtls`.

The certificate must cover the hostname or IP selected clients use. For a
private CA, install its public trust certificate on those clients and set
`PHOENIX_CA_CERT` alongside their new HTTPS `PHOENIX_SERVER` URL. Verify the
certificate before sending credentials; do not disable certificate checks.
Other consumers need no configuration changes. HTTP remains unencrypted and
continues to produce the existing warning on non-loopback binds. Tokens retain
their existing permissions on both transports; there are no HTTPS-only tokens.

The original settings retain their meaning: `tls.enabled` converts the primary
address to HTTPS. Enabling `auth.mtls` also converts the primary and applies its
client-certificate verification and revocation checks to both listeners. When
`auth.mtls.require` is true, both endpoints require a valid client certificate.
Leave both settings false for the HTTP-plus-HTTPS example above.

An omitted or disabled `https_listener` opens no additional socket. When it is
enabled, a configuration mistake stops startup, the same as any other config
error: a blank `listen`, `cert`, or `key`, or a certificate and key that cannot
be loaded. Phoenix exits with `invalid config: ...` instead of starting without
the HTTPS endpoint you asked for. Problems with the host rather than the config
(the address is in use or cannot be bound, or the listener stops accepting
connections) are logged as `Optional HTTPS listener ... primary endpoint
continues` and HTTP keeps serving. The primary reserves its port first, so an
overlapping optional address cannot take it. HTTPS never falls back to
plaintext.

The existing HTTP health check only checks HTTP. Monitor HTTPS separately with
certificate verification and expiry alerts. An optional HTTPS outage should not
cause a restart loop for working HTTP consumers. Certificates load at startup;
replacing a certificate requires a restart. In-memory sessions are lost on restart.

For Docker, retain the existing port mapping and add a mapping for the selected
HTTPS port, for example `9443:9443`, plus certificate mounts if needed. The
server must bind a container-reachable address for a published port. The default
Compose mapping and HTTP health check are unchanged.

To stop using the additional endpoint, restore the selected clients' previous
URLs and disable `https_listener.enabled`, then restart during a planned window.
Keep the original endpoint's settings and other consumers' configuration intact.

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

Docker images are published to Docker Hub as `phoenixsecdev/phoenix`
(`linux/amd64` and `linux/arm64`). Tags: `latest` (newest final release),
`X.Y.Z`, `vX.Y.Z`, and `X.Y`. The image runs as uid 1000 and keeps all
state in the `/data` volume.

```bash
# First run: initialize the volume (prints the admin token once)
docker run --rm -v phoenix-data:/data phoenixsecdev/phoenix --init /data

# Start the server
docker run -d --name phoenix -v phoenix-data:/data \
  --restart unless-stopped phoenixsecdev/phoenix

# Use the CLI inside the container
export PHOENIX_TOKEN=<admin token>
docker exec -e PHOENIX_TOKEN phoenix phoenix status
```

The generated config listens on `127.0.0.1:9090` *inside the container*,
so a `-p 9090:9090` port mapping reaches nothing until you change it. To
use Phoenix from the host or other machines, set `server.listen` to
`0.0.0.0:9090` **and** `"tls": {"enabled": true}` together: traffic now
crosses the Docker bridge, which Phoenix treats as an untrusted network.
The exact commands (a tested `sed` one-liner, then `docker cp` of `ca.crt`
for `PHOENIX_CA_CERT`) are in
[Quickstart: reaching the container from the host](quickstart.md#reaching-the-container-from-the-host).

The image healthcheck probes `/v1/health` over plain HTTP and falls back
to HTTPS, so it stays green after TLS is enabled. With
`auth.mtls.require: true` it cannot present a client certificate and will
report unhealthy; override it with `--health-cmd` in that setup.

The repo's `docker-compose.yml` builds the image from source and follows
the same flow (`docker compose run --rm phoenix --init /data`, then
`docker compose up -d`).

## Related docs

- [Getting Started](getting-started.md)
- [Authentication](authentication.md)
- [Session Identity](session-identity.md)
- [Access Requests](access-requests.md)
- [Dashboard](dashboard.md) — operator UI deployment and security model
- [Key Management](key-management.md)
- [API Reference Index](api-reference-index.md)
