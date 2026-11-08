# Phoenix Secrets — Configuration and Operations

## Configuration reference

The server reads a JSON config file. `config.example.json` is a starter template.
The example binds to loopback (`127.0.0.1`), where plaintext HTTP is the safe,
supported default. `server.listen` always serves plain HTTP; anything that
crosses a wire uses the HTTPS endpoint, `https_listener`. The server starts
either way, but logs a prominent `INSECURE TRANSPORT` warning when
`server.listen` is a non-loopback address, because bearer tokens and secret
values would cross the network in cleartext.

Check a config file without starting the server (see
[Checking a config](#checking-a-config-and-removed-settings)):

```bash
phoenix-server --check-config --config /data/config.json
```

| Field | Description | Default |
|-------|-------------|---------|
| `server.listen` | Plain HTTP bind address; keep it on loopback | `127.0.0.1:9090` |
| `https_listener.enabled` | Serve HTTPS (the only way to turn it on) | `false` |
| `https_listener.listen` | HTTPS bind address; required when enabled | `--init`: `0.0.0.0:9443` |
| `https_listener.cert` | Server certificate; required when enabled | `--init`: `<dir>/server.crt` |
| `https_listener.key` | Server private key; required when enabled | `--init`: `<dir>/server.key` |
| `https_listener.ca_cert` | Internal CA certificate; used only by `--reissue-cert` | `--init`: `<dir>/ca.crt` |
| `https_listener.ca_key` | Internal CA key; used only by `--reissue-cert` | `--init`: `<dir>/ca.key` |
| `store.path` | Encrypted store file | `/data/store.json` |
| `store.master_key` | Master key file | `/data/master.key` |
| `store.backend` | Secret backend (`file` or `1password`) | `file` |
| `acl.path` | ACL definition file | `/data/acl.json` |
| `audit.path` | Audit log file | `/data/audit.log` |
| `audit.rotate_mb` | Rotate the audit log at this size; archives are kept forever. Negative = never rotate. See [Audit log rotation](#audit-log-rotation) | `50` |
| `auth.bearer.enabled` | Bearer token auth; must stay `true` (it is the only way to log in) | `true` |
| `policy.path` | Attestation policy file (optional) | — |
| `attestation.local_agent.enabled` | Local Unix-socket agent (off; groundwork for a future local Phoenix service) | `false` |
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
        "bootstrap_trust": ["bearer"],
        "require_seal_key": true,
        "max_ttl": "15m"
      }
    }
  }
}
```

Each role defines: `namespaces` (required), `bootstrap_trust` (required:
`bearer` and/or `local`), `actions` (default: list + read_value), and
optional `require_seal_key`, `max_ttl` and `attestation` (`source_ip` =
loopback callers only, `require_sealed`).

A role does not raise an agent above its own ACL. To give an agent temporary
access to more, approve an [access request](access-requests.md).

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

**Transport security:** When a request arrives over HTTPS (`https_listener`)
or through a TLS reverse proxy (detected via
`X-Forwarded-Proto: https`),
the session cookie is set with `Secure` flag automatically. For production use:

- Restrict to loopback access only (`server.listen: "127.0.0.1:9090"`), or
- Use the HTTPS endpoint (`"https_listener": {"enabled": true}`), or
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

The moment traffic crosses a wire, use HTTPS. There is one way to turn it
on: `https_listener`. `phoenix-server --init` generates an internal CA and a
server certificate and writes the block for you, switched off:

```json
{
  "server": { "listen": "127.0.0.1:9090" },
  "https_listener": {
    "enabled": true,
    "listen": "0.0.0.0:9443",
    "cert": "/data/server.crt",
    "key": "/data/server.key",
    "ca_cert": "/data/ca.crt",
    "ca_key": "/data/ca.key"
  }
}
```

Set `"enabled": true` and point clients at `https://<host>:9443` with
`PHOENIX_CA_CERT` set to `ca.crt`. Keep `server.listen` on loopback for local
tools and health checks. `ca_cert` and `ca_key` are only read by
`phoenix-server --reissue-cert`, which signs a new server certificate with
extra names (SANs).

If you bind `server.listen` to a non-loopback address, the server still
starts but logs a prominent `INSECURE TRANSPORT` warning: bearer tokens and
every secret value it returns would cross the network in cleartext.

| Deployment | Config | Result |
|-----------|--------|--------|
| Local only | Default (`127.0.0.1`, HTTPS off) | Plain HTTP on loopback — safe |
| LAN / remote | `127.0.0.1` + `https_listener.enabled: true` | HTTPS for the network, HTTP for local tools |
| Behind reverse proxy | `127.0.0.1`, proxy terminates TLS | Plain HTTP on loopback, TLS to clients |

Client certificates (mTLS) and the separate `tls` block were removed; see
[removed settings](#checking-a-config-and-removed-settings).

See [LAN Deployment](lan-deployment.md) for the full multi-host setup,
including re-issuing the server certificate with LAN IP/hostname SANs.

### How the HTTPS endpoint works

`https_listener` adds HTTPS while existing consumers keep their HTTP
address and configuration. Both endpoints use the same handler, secret store,
ACLs, policies, sessions, rate limiter, and audit logger. The additional listener
uses the direct client address for source-IP policy, just like the primary.
HTTP requests are not redirected.

When enabled, `listen`, `cert`, and `key` must all be set (`--init` writes
them).

The certificate must cover the hostname or IP selected clients use. For a
private CA, install its public trust certificate on those clients and set
`PHOENIX_CA_CERT` alongside their new HTTPS `PHOENIX_SERVER` URL. Verify the
certificate before sending credentials; do not disable certificate checks.
Other consumers need no configuration changes. HTTP remains unencrypted and
continues to produce the existing warning on non-loopback binds. Tokens retain
their existing permissions on both transports; there are no HTTPS-only tokens.

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
|   Tool    |  (token/session/   | Server  |    encryption       | (JSON)|
+-----------+  ACL/attestation)  +---------+                     +-------+
                                      |
                                      v
                                 +---------+
                                 | Audit   |
                                 | Log     |
                                 +---------+
```

Authentication flow:
- request
- session token (`phxs_`) or bearer token
- ACL authorization (plus session scope, then grants)
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
so a `-p 9090:9090` port mapping reaches nothing. To use Phoenix from the
host or other machines, turn on `https_listener` (`--init` already bound it
to `0.0.0.0:9443`) and publish port 9443: traffic crosses the Docker bridge,
which Phoenix treats as an untrusted network. The exact commands (a `sed`
one-liner, then `docker cp` of `ca.crt` for `PHOENIX_CA_CERT`) are in
[Quickstart: reaching the container from the host](quickstart.md#reaching-the-container-from-the-host).

The image healthcheck probes `/v1/health` over plain HTTP on the
container's loopback, which stays on when HTTPS is turned on.

The repo's `docker-compose.yml` builds the image from source and follows
the same flow (`docker compose run --rm phoenix --init /data`, then
`docker compose up -d`).

## Checking a config and removed settings

`phoenix-server --check-config` runs the checks startup runs on the config
file, the policy file it names, and the HTTPS certificate, then exits. It
does not open the store or bind a port, so you can run it before deploying a
new version:

```bash
phoenix-server --check-config --config /data/config.json
# policy OK: /data/policy.json (21 rules)
# config OK: /data/config.json
```

Exit status is 0 when the config would start, 1 otherwise, with the reason.

Settings that Phoenix no longer has are never silently ignored. If the
config, the policy file, or a role still uses one, startup (and
`--check-config`) stops with one line per field saying what was removed, why,
and what to use instead, for example:

```text
invalid config: config uses settings Phoenix no longer has (delete them to start):
  auth.mtls: removed. Why: client certificates (mTLS) were removed: .... Instead: use bearer tokens over https_listener; ....
  session.roles.ops.step_up: removed. Why: step-up approvals were folded into access requests. Instead: turn on access_requests; ....
```

Removed in this release (see `RELEASE_NOTES.md` for why each went):

| Where | Removed | Use instead |
|---|---|---|
| config | `tls` | `https_listener` |
| config | `auth.mtls` | bearer tokens over `https_listener`; move `ca_cert`/`ca_key` into `https_listener` to keep `--reissue-cert` |
| config | `attestation.token`, `attestation.nonce` | session roles; `source_ip` rules |
| config | `onepassword.enabled` | `store.backend: "1password"` (the connector stays) |
| role | `step_up`, `step_up_ttl`, `elevates_acl`, `allowed_agents` | [access requests](access-requests.md) |
| role | `bootstrap_trust` `"mtls"` / `"token"`; `attestation` `"require_mtls"` / `"cert_fingerprint"` | `"bearer"` / `"local"`; `"source_ip"` / `"require_sealed"` |
| policy | `require_mtls`, `cert_fingerprint`, `deny_bearer`, `process`, `require_fresh_attestation`, `credential_ttl`, `allowed_tools`, `deny_tools`, `require_nonce`, `nonce_max_age`, `require_signed`, `time_window`, `time_zone` | `source_ip`, `require_sealed` |

Removed API routes (`/v1/token/mint`, `/v1/challenge`, `/v1/proxy`,
`/v1/certs/*`, `/v1/approvals`, `/v1/approval/...`) answer `410 Gone` with the
reason. Removed CLI commands and flags (`phoenix token`, `phoenix cert`,
`phoenix init`, `phoenix agent-sock token|resolve`, `phoenix resolve --signed`,
`phoenix mcp-server --http`, `phoenix policy test --time`, `phoenix approve
apr_...`) print a short explanation and exit 1.

## Related docs

- [Getting Started](getting-started.md)
- [Authentication](authentication.md)
- [Session Identity](session-identity.md)
- [Access Requests](access-requests.md)
- [Dashboard](dashboard.md) — operator UI deployment and security model
- [Key Management](key-management.md)
- [API Reference Index](api-reference-index.md)
