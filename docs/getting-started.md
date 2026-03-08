# Phoenix Getting Started

This guide is the first-run path for Phoenix: install/build, initialize the data
store, start the server, and perform the first secret operations.

## Requirements

- Go 1.25+ (if building from source)
- Linux, macOS, or Windows

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
./bin/phoenix-server --init /data/phoenix
```

This generates:
- master encryption key (`master.key`, mode `0600`)
- admin bearer token — **save this, it is only shown once**
- internal CA certificate and key
- server TLS certificate (SANs: `localhost`, `127.0.0.1`)
- default configuration file

> **Admin token handling:**
> 1. Store it in a password manager or secure vault.
> 2. Use it as a bootstrap credential only.
> 3. Create scoped agent identities/tokens and mTLS certs for regular workloads.
> 4. Remove it from your shell env after bootstrap (`unset PHOENIX_TOKEN`).
> 5. See the full [Admin Token Lifecycle](admin-token-lifecycle.md).

> **Deploying on a LAN?** The default server cert only covers localhost.
> After init, edit `config.json` to set `server.listen` to your host IP, then
> re-issue a server cert that includes it:
>
> ```bash
> phoenix cert issue phoenix-server -o .
> ```
>
> Or put Phoenix behind a reverse proxy that terminates TLS.

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

phoenix set myapp/db-password -v "hunter2" -d "Production database password"
phoenix set myapp/api-key -v "sk-live-abc123" -d "Stripe API key"

phoenix get myapp/db-password
phoenix list myapp/
phoenix delete myapp/old-key
```

## Next steps

- [Authentication](authentication.md)
- [CLI Usage](cli-usage.md)
- [Policy and Attestation](policy-and-attestation.md)
- [Configuration and Operations](configuration.md)
- [Sealed Responses](sealed-responses.md)
