# Phoenix API Reference Index

Base path: `/v1`  
Content type: JSON  
Auth: bearer token and/or mTLS depending on server config.

This index is a concise map of currently implemented endpoints in `internal/api/api.go`.

## Health and status

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/health` | Basic server health + secret count |
| GET | `/v1/status` | Admin status summary (uptime, policy summary, audit snapshot) |

## Secrets

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/secrets/{path}` | Read secret by path |
| GET | `/v1/secrets/` or `/v1/secrets/{prefix}/` | List visible paths under prefix |
| PUT | `/v1/secrets/{path}` | Create/update secret |
| DELETE | `/v1/secrets/{path}` | Delete secret |
| POST | `/v1/resolve` | Batch resolve `phoenix://` refs |

`POST /v1/resolve` request fields:
- `refs` (required): list of reference strings
- `nonce` (optional): challenge nonce
- `timestamp` (optional, required for signed resolve)
- `signature` (optional): detached base64 ECDSA signature

## Audit

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/audit` | Query audit entries (admin-only) |

Query params:
- `since` (RFC3339)
- `agent`
- `limit`

## Agent and ACL management

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/agents` | Create agent + permissions (admin-only) |
| GET | `/v1/agents` | List agent names (admin-only) |

`POST /v1/agents` body:
- `name` (required)
- `token` (required)
- `permissions` (array of `{path, actions[]}`; validated server-side)

## Certificate lifecycle

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/certs/issue` | Issue agent certificate bundle (admin-only, mTLS enabled) |
| POST | `/v1/certs/revoke` | Revoke cert by serial number (admin-only, mTLS enabled) |

`POST /v1/certs/issue` body:
- `agent_name` (required)

`POST /v1/certs/revoke` body:
- `serial_number` (required, decimal string)
- `agent_name` (optional metadata)

## Key and attestation controls

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/rotate-master` | Rotate master key (admin-only, file backend) |
| POST | `/v1/challenge` | Get one-time nonce for challenge-response |
| POST | `/v1/token/mint` | Mint short-lived token (admin-only, when enabled) |

`POST /v1/token/mint` body:
- `agent` (required)
- `process_uid` (optional)
- `binary_hash` (optional)

## Common error shape

Most failures return:

```json
{ "error": "message" }
```

Common status codes: `400`, `401`, `403`, `404`, `405`, `500`, `501`.

