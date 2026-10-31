# Access Requests (request-use grants)

An agent gets told "no" for a secret. Instead of a human editing the ACL, the
agent asks Phoenix for temporary use of **that exact secret**. A human approves
or denies. An approval becomes a **grant**: this agent, with this credential,
from this IP, may read this path until a clock runs out. A human can revoke it
at any time. Every step is in the audit log.

A grant holds no secret and no token. The agent keeps using its own identity
(bearer token, mTLS certificate or short-lived token). **Session tokens
(`phxs_`) can never request or use a grant.**

> Status: server API and enforcement (P2). The dashboard approval page, CLI
> commands (`phoenix request`, `phoenix approve req_...`, `phoenix grants`) and
> `phoenix exec --redact-output` come in the next phases. Until then approvals
> go through the API with an identity listed in `approvers`.

## Configuration

```json
"access_requests": {
  "enabled": true,
  "request_ttl": "15m",
  "default_grant_ttl": "1h",
  "max_grant_ttl": "8h",
  "grantable_actions": ["read_value"],
  "require_sealed": true,
  "bind_source_ip": true,
  "approvers": [],
  "deny_paths": [],
  "store_path": ""
}
```

| Key | Meaning |
|---|---|
| `enabled` | Off when the whole block is missing (every upgraded install). `phoenix-server --init` and `config.example.json` turn it on. |
| `request_ttl` | How long a request waits for a decision (min `1m`). |
| `default_grant_ttl` / `max_grant_ttl` | Grant length when the agent does not ask / the ceiling. `1m <= default <= max <= 24h`. |
| `grantable_actions` | Must be `["read_value"]`. `write` is a startup error ("write grants are not supported yet"); `list`, `delete`, `admin` are never grantable. |
| `require_sealed` | Granted values are served only sealed to the agent's **registered** seal key. Agents without one get `SEAL_KEY_NOT_REGISTERED` when they ask. |
| `bind_source_ip` | The grant only works from the IP that made the request. |
| `approvers` | ACL agent names allowed to approve over the API. Empty = dashboard only. ACL `admin` alone is **not** enough, and nobody can approve their own request. The name must also still be in the ACL: a deleted approver's leftover short-lived token or certificate approves nothing. Unknown names only warn at startup. |
| `deny_paths` | Globs (`phoenix/**`, `infra/*`, exact paths) that can never be requested. |
| `store_path` | Where grants live. Empty = `grants.json` next to the ACL file (mode `0600`). This path is checked at every start, even without an `access_requests` block: if it (or its temp files) is the same file as the ACL, audit log, secrets data file, master key, policy or CRL file, resolved through relative paths and symlinks, the server refuses to start and touches nothing. The grants file itself must not be a symlink. Set `store_path` to a separate regular file to fix either problem. |

Turning it off (`enabled: false`) stops new requests (`501 REQUESTS_DISABLED`)
**and** all grant-backed access. Records stay on disk; listing and revoking
still work. Turning it back on resumes only grants that have not expired or
been revoked.

The server warns at startup when the feature is on but there is no dashboard
and no `approvers` (nobody could approve).

## Endpoints

All responses are JSON with `Cache-Control: no-store`. Errors use the denial
shape and codes in [denial-codes.md](denial-codes.md#access-requests-and-grants).

Agent side (own bearer / mTLS / short-lived token; sessions get `403 SESSION_CANNOT_REQUEST`):

| Method + path | Does |
|---|---|
| `POST /v1/access-requests` | `{"paths":[...],"action":"read_value","reason":"...","ttl":"30m"}` -> `201` new, `200` identical one already pending |
| `GET /v1/access-requests[?status=pending]` | Your own requests |
| `GET /v1/access-requests/{id}` | One of yours (anything else is `404`), with `next_step` and `message` |
| `GET /v1/grants[?include=inactive]` | Your own grants |
| `POST /v1/grants/{id}/revoke` | Give up your own grant early |
| `GET /v1/whoami` | Identity, your ACL rules, active grants, pending requests, feature summary |

Approver side (an identity in `approvers`, not a session):

| Method + path | Does |
|---|---|
| `GET /v1/access-requests[?status=&agent=]` | Every agent's requests, with source IP, auth method and `already_allowed_paths` |
| `POST /v1/access-requests/{id}/approve` | Optional `{"paths":[subset],"ttl":"15m"}`: may narrow paths and shorten TTL, never widen |
| `POST /v1/access-requests/{id}/deny` | Optional `{"note":"..."}`; starts a 10-minute cooldown on those paths |
| `GET /v1/grants?agent=&include=inactive` | Every grant |
| `POST /v1/grants/{id}/revoke` | Revoke any grant (idempotent) |

Approval re-checks the **current** config: feature on, action grantable, no
path in `deny_paths`, TTL clamped to `max_grant_ttl`, `require_sealed` and
`bind_source_ip`, the agent still exists, at most 10 active grants.

Limits: 3 pending per agent, 50 in total, 10 new requests per agent per hour,
10-minute cooldown after a deny. Each `429` carries `Retry-After`.

## How a grant is used

`phoenix exec --env NAME=phoenix://<path> -- <command>` with the agent's own
`PHOENIX_TOKEN` (or cert) and `PHOENIX_SEAL_KEY`. Exec resolves sealed,
decrypts in its own process, and gives the child the value but no Phoenix
credentials. A plain `GET` or `resolve` without the registered seal key gets
`SEALED_REQUIRED` while `require_sealed` is on.

What a grant never does:

- It is never consulted for session tokens, for `list`, `write` or `delete`.
- It never waives the path's attestation policy (mTLS, IP, nonce, ...).
- It never makes `GET /v1/policy/check?check=allow_unseal` true, so an
  envelope cached while the grant was active cannot be unsealed by plugin
  unseal tools later.
- Revoking cannot take back a value already delivered. Rotate the secret if
  that matters.

Expiry and revoke are checked on every request (no cache). Rotating an agent's
bearer token or certificate ends its grants. Deleting an agent revokes its
grants and records a tombstone first, so a recreated agent with the same name
cannot use the old grants with old credentials.

## Status and audit

`GET /v1/status` (admin) shows `access_requests.state` (`ok` / `degraded`,
for example a quarantined or unwritable grants file) and `audit.state`
(`degraded` while committed grant events wait to reach the audit log; they
are retried every 30 seconds). Grant events are audit actions such as
`access_request.created`, `access_request.approved`, `grant.revoked`, each
preceded by an `....attempt` line. Reads through a grant are normal
`read_value` / `resolve` entries with metadata `grant_id`.
