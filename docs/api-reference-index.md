# Phoenix API Reference Index

Base path: `/v1`  
Content type: JSON  
Auth: bearer token or session token (`phxs_`).

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
| GET | `/v1/metadata/` or `/v1/metadata/{prefix}/` | Visible secrets with description, tags, username, link, times, authors; `?tag=` filters. Never values |
| GET | `/v1/metadata/{path}` | Same for one secret (`phoenix info`). Never the value |
| PATCH | `/v1/metadata/{path}` | Change description, tags, username or link of an existing secret (`phoenix describe`). Never the value |
| PUT | `/v1/secrets/{path}` | Create/update secret; optional `username` and `url` |
| DELETE | `/v1/secrets/{path}` | Delete secret |
| POST | `/v1/resolve` | Batch resolve `phoenix://` refs |

`/v1/metadata` needs only `list` permission on a path, is audited as `list`,
and never returns the value. (With the 1Password backend, finding the paths
reads the vault's items, exactly as the list route does.) Each entry has `path`, `description` (may be
empty), `tags`, `created`, `updated`, `created_by` and `updated_by` (who wrote
the current value; on secrets last written before it existed it is the same as
`created_by`), plus `username` and `url` when the secret has them. Those two are
never in a value read (`GET /v1/secrets/{path}`). A server without the route answers a plain-text 404; the CLI
then lists bare paths. `PUT /v1/secrets/{path}` returns `has_description`
(true or false, never the text) to callers who may list the path, so the CLI
can nudge when it is false, and `changed`, the metadata fields the write set.

`PATCH /v1/metadata/{path}` takes a JSON object with any of `description`,
`tags` (array), `username` and `url`. A field left out keeps what is stored, an
empty one clears it; `PUT` treats `username` and `url` the same way. It needs
`write` on the path (and passes the path's attestation rule), answers `404` for
a secret that does not exist and `400` for an unknown field, and is audited as
`describe` with the changed field names. The reply is `{"status", "path",
"changed"}`: no metadata, because `write` does not include `list`.

`POST /v1/resolve` request fields:
- `refs` (required): list of reference strings

A body that still sends `nonce` or `signature` (nonce challenges and signed
resolve were removed) gets `400` saying so.

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

Deleting an agent, or updating it with a different token, ends its role sessions
(see [Session identity](session-identity.md#ended-with-the-agents-token)).

## Key management

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/rotate-master` | Rotate master key (admin-only, file backend) |

## Policy checks

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/policy/check` | Query server-authoritative policy for a path |

Query params:
- `path` (required): secret path to check
- `check` (required): policy check to perform (currently only `allow_unseal`)

Any authenticated identity, including session tokens, gets `200`.
`allow_unseal` is `true` only when the caller can read the path without
grants (its ACL, or a session's scope + action + ACL) **and** the
path's policy sets `allow_unseal`. Unreadable paths return `{"allowed": false}`.

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

Session-token callers see only their own session. Bearer callers see
sessions for their agent. Admins see all.

## Removed routes

These answer `410 Gone` with a one-line reason, so an old client learns what
happened instead of getting a bare 404:

| Method | Path | Was | Use instead |
|---|---|---|---|
| POST | `/v1/token/mint` | Short-lived tokens | `POST /v1/session/mint` |
| POST | `/v1/challenge` | Nonce challenge | `source_ip` policy |
| POST | `/v1/proxy` | Never built (always 501) | — |
| POST | `/v1/certs/issue`, `/v1/certs/revoke` | Client certificates (mTLS) | Bearer tokens over HTTPS |
| GET | `/v1/approvals` | Step-up approvals | `GET /v1/access-requests` |
| any | `/v1/approval/...` | Step-up approvals | `/v1/access-requests/{id}` |

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
It uses cookie-based auth (not bearer tokens) and returns HTML (not JSON).

Dashboard routes are only registered when `dashboard.enabled` is `true` in
config. They do not appear in the API mux otherwise.

See [Dashboard](dashboard.md) for the full reference.

## Access requests and grants

See [Access Requests](access-requests.md). Agent side uses the agent's own
identity (sessions get `403 SESSION_CANNOT_REQUEST`); approve/deny need an
identity listed in `access_requests.approvers`. New requests can also send
a notification to `access_requests.notify_url` (no endpoint; see
[Notifications](access-requests.md#notifications)).

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/access-requests` | Ask for temporary `read_value` on exact paths |
| GET | `/v1/access-requests` | Own requests (approvers: all) |
| GET | `/v1/access-requests/{id}` | One request with `next_step` |
| POST | `/v1/access-requests/{id}/approve` | Approve, optionally narrowing paths / TTL (approvers) |
| POST | `/v1/access-requests/{id}/deny` | Deny with optional note (approvers) |
| GET | `/v1/grants` | Own grants (approvers: all) |
| POST | `/v1/grants/{id}/revoke` | Revoke (owner or approver) |
| GET | `/v1/whoami` | Caller identity, ACL rules, grants, pending requests |

## SSH certificates

See [ssh-certificates.md](ssh-certificates.md).

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/ssh/sign` | Sign `{"host","public_key"}` with an active `ssh_login` grant on `ssh/<host>`. Own identity only, never a session |
| GET | `/v1/ssh/ca` | The CA's public key. No login |
| GET | `/v1/ssh/machines` | Machines this server can sign logins for: `{"agent","enabled","machines":[{"name","approved_until"?}]}`. `approved_until` appears where the caller's own approval (same agent, token and IP) is active. Never addresses or users. Any signed-in caller, sessions included (they never see an approval). With `ssh_ca` off: `enabled: false`, empty list and a `note`, still 200. Audited as `ssh.list` |
| GET | `/v1/ssh/window/{host}/{grant}` | `{"open":true/false}`: whether this approval is active for this machine. Anything unknown or switched off is false. No login; machines ask at every login and for each open session |

## Common error shape

Most failures return:

```json
{ "error": "message" }
```

Common status codes: `400`, `401`, `403`, `404`, `405`, `500`, `501`.

## Structured denials

Access control, attestation and session failures return machine-readable
denial responses with a `code` and a `next_step`. `POST /v1/resolve` reports
per-ref failures in `error_codes`. Full contract and client rules:
[denial-codes.md](denial-codes.md).

```json
{
  "error": "access_denied",
  "code": "SCOPE_EXCEEDED",
  "detail": "path \"prod/key\" is outside session scope for role \"dev\"",
  "remediation": "request a session with a role that includes this namespace",
  "next_step": "remint_session"
}
```

Denial codes:

| Code | HTTP | Meaning |
|------|------|---------|
| `ACL_DENIED` | 403 | ACL does not allow the action on this path |
| `ATTESTATION_REQUIRED` | 403 | Path attestation policy not met |
| `SEALED_REQUIRED` | 403 | Path is only served sealed; use `phoenix exec --redact-output` |
| `SESSION_EXPIRED` | 401 | Session TTL elapsed |
| `SESSION_REVOKED` | 401 | Session was explicitly revoked |
| `SESSION_INVALID` | 401 | Token malformed, signature invalid, or session ended because its agent was deleted or the agent's token was replaced |
| `SCOPE_EXCEEDED` | 403 | Path outside role's namespace scope |
| `ACTION_DENIED` | 403 | Action not permitted by role |
| `BOOTSTRAP_FAILED` | 403 | Auth method not accepted for this role |
| `ROLE_NOT_FOUND` | 404 | Requested role does not exist |
| `SEAL_KEY_REQUIRED` | 403 | Role requires seal key at mint |
| `SEAL_KEY_MISMATCH` | 403 | Seal key doesn't match session binding |
| `SESSION_REQUIRED` | 400 | Operation requires a session token |
| `ADMIN_AUTH_REQUIRED` | 403 | Session tokens cannot perform this action |
