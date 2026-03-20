# Phoenix Secrets — Getting Started

First-run guide: install, initialize, start the server, store your first secret.

## Requirements

- Go 1.25+ (if building from source)
- Linux, macOS, or Windows
- No external runtime dependencies (no database, no cloud KMS, no Redis)

## Install from GitHub Releases

```bash
curl -fsSL https://raw.githubusercontent.com/phoenixsec-dev/phoenix/main/scripts/install.sh | sh
```

Options:
- `PHOENIX_VERSION=vX.Y.Z` pin a specific release
- `INSTALL_DIR=/custom/bin` choose install path

## Build from source

```bash
git clone https://github.com/phoenixsec-dev/phoenix.git
cd phoenix
go build -o bin/ ./cmd/...
```

This produces:
- `bin/phoenix` — CLI client
- `bin/phoenix-server` — API server

## Initialize

```bash
phoenix-server --init /data/phoenix
```

This generates:
- master encryption key (`master.key`, mode `0600`)
- admin bearer token — **save this, it is only shown once**
- internal CA certificate and key
- server TLS certificate (SANs: `localhost`, `127.0.0.1`)
- default configuration file

### Admin token handling

1. Store it in a password manager or secure vault immediately.
2. Use it as a bootstrap credential only — create scoped agents for real workloads.
3. Remove it from your shell env after bootstrap (`unset PHOENIX_TOKEN`).
4. See [Admin Token Lifecycle](admin-token-lifecycle.md) for the full lifecycle.

### Deploying on a LAN?

The default config listens on `127.0.0.1` (loopback only) over plain HTTP.
If other machines need to reach this server:

1. Set `server.listen` to `0.0.0.0:9090` and `auth.mtls.enabled` to `true`
2. Re-issue the server cert with your LAN IP:
   ```bash
   phoenix-server --reissue-cert --san 192.168.1.10 --config /data/phoenix/config.json
   ```
3. Restart the server

For the full multi-host setup walkthrough, see [LAN Deployment](lan-deployment.md).

## Verify file permissions

```bash
chmod 700 /data/phoenix
chmod 600 /data/phoenix/master.key /data/phoenix/ca.key /data/phoenix/server.key
```

## Start the server

```bash
./bin/phoenix-server --config /data/phoenix/config.json
```

Example startup output (default config, plain HTTP on loopback):

```text
Phoenix server starting on 127.0.0.1:9090
  Store: /data/phoenix/store.json (0 secrets)
  ACL: /data/phoenix/acl.json (1 agents)
  Audit: /data/phoenix/audit.log
```

> **Binding to all interfaces:** The default listen address is `127.0.0.1:9090`.
> To accept connections from other hosts, enable TLS and set `server.listen`
> to `0.0.0.0:9090`. See [LAN Deployment](lan-deployment.md).

## First secret operations

```bash
export PHOENIX_SERVER="http://127.0.0.1:9090"
export PHOENIX_TOKEN="<your-admin-token>"

phoenix set myapp/api-key -v "sk-live-abc123" -d "Stripe API key"
phoenix get myapp/api-key
```

> **Note:** The default config starts the server on plain HTTP at `127.0.0.1:9090`.
> This is safe for local-only use — the server is not reachable from the network.
> For LAN or production deployment, enable TLS first. See [LAN Deployment](lan-deployment.md).

For the full command reference (`set`, `get`, `list`, `delete`, `resolve`, `exec`,
`import`, `export`, `audit`), see [CLI Usage](cli-usage.md).

## Enable the operator dashboard (optional)

The dashboard provides a browser-based UI for approvals, sessions, audit, and
roles. It is especially useful for step-up approval workflows where a human
needs to approve agent access from a phone or browser.

Generate a password hash and add to your config:

```bash
phoenix-server --hash-password
```

```json
{
  "dashboard": {
    "enabled": true,
    "password_hash": "$2a$10$..."
  }
}
```

After restarting, open `http://127.0.0.1:9090/dashboard/` in a browser.

**Important:** The dashboard is safe over plain HTTP only when the server
listens on loopback (`127.0.0.1`). If the server is reachable over a
network, put it behind a TLS reverse proxy or enable mTLS first. Do not
serve the dashboard over plain HTTP on a network you do not control.
See [Dashboard](dashboard.md) for the full deployment guide and security model.

## Next steps

- [CLI Usage](cli-usage.md) — full command reference
- [Authentication](authentication.md) — bearer tokens, mTLS, sealed key pairs
- [Dashboard](dashboard.md) — browser-based operator UI
- [Policy and Attestation](policy-and-attestation.md) — per-path security rules
- [LAN Deployment](lan-deployment.md) — multi-host setup
- [Configuration](configuration.md) — server config reference and Docker
- [Sealed Responses](sealed-responses.md) — context-safe encrypted delivery
