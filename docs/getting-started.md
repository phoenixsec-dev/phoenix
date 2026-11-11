# Phoenix Secrets — Getting Started

First-run guide: install, initialize, start the server, store your first secret.
Just want it running? [Quickstart](quickstart.md) gets you to a first secret
in under two minutes, with binaries or Docker.

## Requirements

- Go 1.25+ (if building from source)
- Linux, macOS, or Windows
- No external runtime dependencies (no database, no cloud KMS, no Redis)

## Install from GitHub Releases

```bash
curl -fsSL https://raw.githubusercontent.com/phoenixsec-dev/phoenix/main/scripts/install.sh | sh
```

The script verifies the download against the release `checksums.txt` and
refuses to install on a mismatch. Options:
- `PHOENIX_VERSION=vX.Y.Z` pin a specific release
- `INSTALL_DIR=/custom/bin` choose install path (default `/usr/local/bin`,
  or `~/.local/bin` if that is not writable)

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
phoenix-server --init ~/.phoenix
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
That is the supported default: loopback traffic never touches the network, so
TLS adds nothing on a single machine. If other machines need to reach this
server, requests will cross a wire — use HTTPS:

1. Set `https_listener.enabled` to `true` (`--init` already wrote the rest:
   `0.0.0.0:9443` and the server certificate it generated). Keep
   `server.listen` on `127.0.0.1:9090`.
2. Re-issue the server cert with your LAN IP:
   ```bash
   phoenix-server --reissue-cert --san 192.168.1.10 --config ~/.phoenix/config.json
   ```
3. Restart the server

If you bind a non-loopback address without TLS, the server starts anyway but
logs a prominent `INSECURE TRANSPORT` warning — bearer tokens and secret
values would cross the network in cleartext. Phoenix is LAN-scoped by design:
a LAN is as far as the supported envelope goes, and exposing Phoenix to the
internet is out of scope entirely (see [Threat Model](threat-model.md)).

For the full multi-host setup walkthrough, see [LAN Deployment](lan-deployment.md).
Upgrading a server that already has HTTP clients? HTTPS runs on its own
port next to HTTP, so you can migrate clients gradually; see
[How the HTTPS endpoint works](configuration.md#how-the-https-endpoint-works).

## Verify file permissions

```bash
chmod 700 ~/.phoenix
chmod 600 ~/.phoenix/master.key ~/.phoenix/ca.key ~/.phoenix/server.key
```

## Start the server

```bash
phoenix-server --config ~/.phoenix/config.json
```

Example startup output (default config, plain HTTP on loopback):

```text
Phoenix server starting on 127.0.0.1:9090
  Store: /home/you/.phoenix/store.json (0 secrets)
  ACL: /home/you/.phoenix/acl.json (1 agents)
  Audit: /home/you/.phoenix/audit.log
```

> **Accepting connections from other hosts:** The default listen address is
> `127.0.0.1:9090`. Leave it there and turn on `https_listener` (HTTPS on
> `0.0.0.0:9443`). See [LAN Deployment](lan-deployment.md).

## First secret operations

```bash
export PHOENIX_SERVER="http://127.0.0.1:9090"
export PHOENIX_TOKEN="<your-admin-token>"

phoenix set myapp/api-key -d "Stripe API key"   # paste at the hidden prompt
phoenix get myapp/api-key
```

> **Note:** The default config starts the server on plain HTTP at `127.0.0.1:9090`.
> This is safe for local-only use — the server is not reachable from the network,
> and plain `http://` to loopback is the expected setup here. For LAN deployment,
> turn on `https_listener` first. See [LAN Deployment](lan-deployment.md).

For the full command reference (`set`, `get`, `list`, `delete`, `resolve`, `exec`,
`import`, `export`, `audit`), see [CLI Usage](cli-usage.md).

## Enable the operator dashboard (optional)

The dashboard provides a browser-based UI for approvals, sessions, audit, and
roles. It is especially useful for access requests, where a human approves
agent access from a phone or browser.

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
listens on loopback (`127.0.0.1`). If the server is reachable over a network,
enable the `tls` block (or put it behind a TLS reverse proxy) first — the
server warns loudly at startup if the dashboard is enabled on a non-loopback
bind without TLS. Do not serve the dashboard over plain HTTP on a network you
do not control.
See [Dashboard](dashboard.md) for the full deployment guide and security model.

## Let agents ask for temporary access

New installs (`--init`) include an `access_requests` block with
`"enabled": true`. An agent that is denied a secret can ask for temporary use
of that exact path, and a human approves or denies it. See
[Access Requests](access-requests.md). Configs from older releases have no
block, so the feature stays off until you add it.

## Next steps

- [CLI Usage](cli-usage.md) — full command reference
- [Authentication](authentication.md) — bearer tokens, sessions, sealed key pairs
- [Dashboard](dashboard.md) — browser-based operator UI
- [Policy and Attestation](policy-and-attestation.md) — per-path security rules
- [LAN Deployment](lan-deployment.md) — multi-host setup
- [Configuration](configuration.md) — server config reference and Docker
- [Sealed Responses](sealed-responses.md) — context-safe encrypted delivery
