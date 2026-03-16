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

The default server cert only covers `localhost` and `127.0.0.1`. If other machines need to reach this server, you need a cert that includes the server's LAN IP or hostname.

```bash
# Edit config.json: set server.listen to "0.0.0.0:9090"
# Then re-issue a server cert with the correct SANs:
phoenix cert issue phoenix-server -o /data/phoenix/
```

Or put Phoenix behind a reverse proxy that terminates TLS.

For full multi-host deployment, see [LAN Deployment](lan-deployment.md).

## Verify file permissions

```bash
chmod 700 /data/phoenix
chmod 600 /data/phoenix/master.key /data/phoenix/ca.key /data/phoenix/server.key
```

## Start the server

```bash
./bin/phoenix-server --config /data/phoenix/config.json
```

Example startup output:

```text
Phoenix server starting on 127.0.0.1:9090
  Store: /data/phoenix/store.json (0 secrets)
  Key provider: file
  ACL: /data/phoenix/acl.json (1 agents)
  Audit: /data/phoenix/audit.log
  mTLS: enabled (require=false)
  Bearer: true
```

> **Binding to all interfaces:** The default listen address is `127.0.0.1:9090`.
> To accept connections from other hosts, set `server.listen` to `0.0.0.0:9090`.
> Only do this with authentication and network controls in place.

## First secret operations

```bash
export PHOENIX_SERVER="https://localhost:9090"
export PHOENIX_TOKEN="<your-admin-token>"
export PHOENIX_CA_CERT="/data/phoenix/ca.crt"

phoenix set myapp/api-key -v "sk-live-abc123" -d "Stripe API key"
phoenix get myapp/api-key
```

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

After restarting, open `http://localhost:9090/dashboard/` (or your server's
address) in a browser.

**Important:** If the server is reachable over a network, put it behind a TLS
reverse proxy or use mTLS. Do not serve the dashboard over plain HTTP on a
network you do not control. See [Dashboard](dashboard.md) for the full
deployment guide and security model.

## Next steps

- [CLI Usage](cli-usage.md) — full command reference
- [Authentication](authentication.md) — bearer tokens, mTLS, sealed key pairs
- [Dashboard](dashboard.md) — browser-based operator UI
- [Policy and Attestation](policy-and-attestation.md) — per-path security rules
- [LAN Deployment](lan-deployment.md) — multi-host setup
- [Configuration](configuration.md) — server config reference and Docker
- [Sealed Responses](sealed-responses.md) — context-safe encrypted delivery
