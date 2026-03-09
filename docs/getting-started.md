# Phoenix Secrets — Getting Started

First-run guide: install, initialize, start the server, store your first secret.

## Requirements

- Go 1.25+ (if building from source)
- Linux, macOS, or Windows
- No external runtime dependencies (no database, no cloud KMS, no Redis)

## Install from GitHub Releases

```bash
curl -fsSL https://raw.githubusercontent.com/phoenixsec/phoenix/main/scripts/install.sh | sh
```

Options:
- `PHOENIX_VERSION=vX.Y.Z` pin a specific release
- `INSTALL_DIR=/custom/bin` choose install path

## Build from source

```bash
git clone https://github.com/phoenixsec/phoenix.git
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

## Next steps

- [CLI Usage](cli-usage.md) — full command reference
- [Authentication](authentication.md) — bearer tokens, mTLS, sealed key pairs
- [Policy and Attestation](policy-and-attestation.md) — per-path security rules
- [LAN Deployment](lan-deployment.md) — multi-host setup
- [Configuration](configuration.md) — server config reference and Docker
- [Sealed Responses](sealed-responses.md) — context-safe encrypted delivery
