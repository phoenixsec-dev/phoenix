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
| `onepassword.vault` | 1Password vault name | — |
| `onepassword.service_account_token_env` | Token env var name | `OP_SERVICE_ACCOUNT_TOKEN` |
| `onepassword.cache_ttl` | Runtime read/list cache duration | `60s` |

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

## Docker (planned)

> Docker images are not yet published. The examples below show the intended usage
> for when `phoenixsec/phoenix` is available on Docker Hub. For now, build from
> source or use the install script.

```bash
docker pull phoenixsec/phoenix:latest

# First run: initialize the data directory
docker run --rm -v phoenix-data:/data phoenixsec/phoenix:latest --init /data

# Start the server
docker run -d --name phoenix \
  -v phoenix-data:/data \
  -p 9090:9090 \
  --restart unless-stopped \
  phoenixsec/phoenix:latest
```

Docker Compose example:

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

**Important:** The generated config defaults to `127.0.0.1:9090`. For Docker port
mapping to work, set `server.listen` to `0.0.0.0:9090` in the config.

## Related docs

- [Getting Started](getting-started.md)
- [Authentication](authentication.md)
- [Key Management](key-management.md)
- [API Reference Index](api-reference-index.md)
