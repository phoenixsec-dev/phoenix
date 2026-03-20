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
| POST | `/v1/agents` | Create or update agent + permissions (admin-only) |
| GET | `/v1/agents` | List agent names (admin-only) |
| DELETE | `/v1/agents/{name}` | Delete an agent (admin-only) |

`POST /v1/agents` body (use `?force=true` to update an existing agent):
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

## Policy checks

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/policy/check` | Query server-authoritative policy for a path |

Query params:
- `path` (required): secret path to check
- `check` (required): policy check to perform (currently only `allow_unseal`)

Response:
```json
{ "path": "myapp/key", "check": "allow_unseal", "allowed": true }
```

## Session identity

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/session/mint` | Mint session token for a role |
| POST | `/v1/session/renew` | Renew current session token |
| GET | `/v1/sessions` | List active sessions |
| GET | `/v1/sessions/{id}` | Get session details |
| POST | `/v1/sessions/{id}/revoke` | Revoke a session |

`POST /v1/session/mint` body:
- `role` (required): role name to mint
- `seal_public_key` (optional): base64-encoded X25519 public key

`GET /v1/sessions` query params:
- `role` — filter by role name
- `agent` — filter by agent name (admin only)

Session-token callers see only their own session. Bearer/mTLS callers see
sessions for their agent. Admins see all.

## Step-up approvals

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/approvals` | List pending approvals (admin-only) |
| GET | `/v1/approval/{id}` | Get approval status |
| POST | `/v1/approval/{id}/approve` | Approve step-up request |
| POST | `/v1/approval/{id}/deny` | Deny step-up request |

See [Session Identity](session-identity.md) for the approval workflow.

## Sealed responses

When a request includes the `X-Phoenix-Seal-Key` header (base64-encoded
X25519 public key), secret-returning endpoints respond with `sealed_values`
instead of `values`. Each value is a sealed envelope encrypted to the
provided public key using NaCl box (X25519 + XSalsa20-Poly1305).

Affected endpoints:
- `GET /v1/secrets/{path}` — returns `sealed_value` instead of `value`
- `POST /v1/resolve` — returns `sealed_values` map instead of `values`

`POST /v1/resolve?dry_run=true` always returns plaintext `"ok"` status
values regardless of seal key presence.

All secret-returning responses include `Cache-Control: no-store`.

See [Sealed Responses](sealed-responses.md) for the full guide.

## Operator dashboard

The dashboard is served at `/dashboard/` and is **not** part of the `/v1/` API.
It uses cookie-based auth (not bearer/mTLS) and returns HTML (not JSON).

Dashboard routes are only registered when `dashboard.enabled` is `true` in
config. They do not appear in the API mux otherwise.

See [Dashboard](dashboard.md) for the full reference.

## Common error shape

Most failures return:

```json
{ "error": "message" }
```

Common status codes: `400`, `401`, `403`, `404`, `405`, `500`, `501`.

## Structured denials

Session and access control failures return machine-readable denial responses:

```json
{
  "error": "access_denied",
  "code": "SCOPE_EXCEEDED",
  "detail": "path \"prod/key\" is outside session scope for role \"dev\"",
  "remediation": "request a session with a role that includes this namespace"
}
```

Denial codes:

| Code | HTTP | Meaning |
|------|------|---------|
| `SESSION_EXPIRED` | 401 | Session TTL elapsed |
| `SESSION_REVOKED` | 401 | Session was explicitly revoked |
| `SESSION_INVALID` | 401 | Token malformed or signature invalid |
| `SCOPE_EXCEEDED` | 403 | Path outside role's namespace scope |
| `ACTION_DENIED` | 403 | Action not permitted by role |
| `APPROVAL_REQUIRED` | 202 | Step-up approval needed |
| `BOOTSTRAP_FAILED` | 403 | Auth method not accepted for this role |
| `ROLE_NOT_FOUND` | 404 | Requested role does not exist |
| `ATTESTATION_FAILED` | 403 | Attestation requirements not met |
| `SEAL_KEY_REQUIRED` | 403 | Role requires seal key at mint |
| `SEAL_KEY_MISMATCH` | 403 | Seal key doesn't match session binding |
| `SESSION_REQUIRED` | 400 | Operation requires a session token |
| `ADMIN_AUTH_REQUIRED` | 403 | Session tokens cannot perform this action |

