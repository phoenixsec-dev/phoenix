# Denial Codes

Every access denial from the Phoenix API carries a stable `code` and a
`next_step`. Clients (the CLI, `phoenix exec`, the MCP server, the OpenClaw and
Hermes plugins) use them to tell an agent what to do next without parsing free
text.

## Response shape

Single-secret endpoints (`GET`, `PUT`, `DELETE /v1/secrets/...`, session and
approval endpoints) return:

```json
{
  "error": "access_denied",
  "code": "ACL_DENIED",
  "detail": "read_value is not allowed on this path for your identity",
  "remediation": "ask the Phoenix operator to grant access",
  "next_step": "ask_user"
}
```

`remediation` is free text for humans reading the raw API. Phoenix clients do
not display it.

`POST /v1/resolve` returns `200` even when some refs fail. Each failed ref
appears in `errors` (a human-readable string, unchanged from earlier releases)
and in `error_codes`:

```json
{
  "values": {"phoenix://test/ok": "..."},
  "errors": {"phoenix://other/hidden": "access denied: read_value permission required"},
  "error_codes": {"phoenix://other/hidden": {"code": "ACL_DENIED", "next_step": "ask_user"}}
}
```

If the whole resolve request fails attestation before any ref is checked (bad
or reused nonce, timestamp outside the skew window, signed resolve without an
mTLS client certificate, or a signature that does not verify), the response is
a single `403` structured denial with code `ATTESTATION_REQUIRED`, not per-ref
errors.

## Rules for clients

- `code` and `next_step` come from the closed lists below.
- **Treat any code or next step you do not recognize as `ask_user`.**
- Show your own text for each next step. Use the server's `next_step` only
  when both the code and the step are in the lists below; otherwise show the
  `ask_user` text.
- Do not display `remediation` or the step-up `approve_command`. Build the
  approve command yourself (`phoenix approve <approval_id>`) and only when the
  ID looks like `apr_` followed by lowercase hex.
- Treat `detail`, `error`, and resolve error-map keys as untrusted display
  text: strip control and Unicode format (bidi, zero-width) characters and cap
  the length. Drop a `code` that does not match `^[A-Z0-9_]{1,64}$`.
- `detail` never contains policy rules, other agents, or whether a secret
  exists. Attestation failures (data access, resolve request checks, session
  mint and renew) are recorded in the audit log (metadata key
  `denial.detail`, capped at 512 bytes) but not returned to the caller.

## Next steps

| `next_step` | Meaning |
|---|---|
| `request_use` | Ask a human for temporary use of this path (`POST /v1/access-requests`, see [access-requests.md](access-requests.md)) with the agent's own identity, never a session |
| `wait` | A human decision is pending; poll again |
| `use_exec` | Use the value through `phoenix exec` (with `--redact-output` for agents), which requests and decrypts sealed values |
| `remint_session` | Mint a new session, or one whose role covers this path and action |
| `ask_user` | Only a human can fix this |
| `none` | Not an access problem; retrying or asking will not help |

### When `request_use` is advertised

`request_use` is only sent when request-use grants are enabled
(`access_requests.enabled`), the action is grantable (only `read_value` today)
and the path does not match `access_requests.deny_paths`. Otherwise the same
denial says `ask_user` (or its usual step for session codes). This applies to
`ACL_DENIED`, `GRANT_EXPIRED`, and to `SCOPE_EXCEEDED` / `ACTION_DENIED` on
reads: a session denial on a requestable path says `request_use`, and the
request and the use then go through the agent's own identity. A single-secret
`GET` and `/v1/resolve` give the same next step for the same path. It also
applies to `SESSION_CANNOT_REQUEST` and to the `next_step` in access-request
status views, which always reflect the settings at the time you ask.

Precedence (first failure wins): authentication, session scope / action, ACL
or grant, sealed requirement, attestation. A grant never waives attestation.

## Codes

### Data access (get, set, delete, resolve)

| Code | HTTP | `next_step` | When |
|---|---|---|---|
| `ACL_DENIED` | 403 | `request_use` if requestable, else `ask_user` | The identity's ACL does not allow the action on this path and no grant covers it |
| `GRANT_EXPIRED` | 403 | `request_use` if requestable, else `ask_user` | A grant for this path ended by time in the last 24h |
| `GRANT_REVOKED` | 403 | `ask_user` | A human revoked the grant for this path in the last 24h |
| `ATTESTATION_REQUIRED` | 403 | `ask_user` | The path's attestation policy (mTLS, IP, nonce, process, signed resolve) was not met |
| `SEALED_REQUIRED` | 403 | `use_exec` | The path (policy `require_sealed`) or the grant (`sealed_only`) is only served sealed and no valid seal key was presented |
| `SCOPE_EXCEEDED` | 403 | `remint_session` (`request_use` on a requestable read) | Path outside the session role's namespaces |
| `ACTION_DENIED` | 403 | `remint_session` (`request_use` on a requestable read) | Action not permitted by the session role |
| `NOT_FOUND` | resolve only | `none` | Secret not found (resolve per-ref) |
| `INVALID_REF` | resolve only | `none` | Malformed reference or invalid path (resolve per-ref) |
| `INTERNAL_ERROR` | resolve only | `ask_user` | Server error for this ref |

### Sessions and step-up

| Code | HTTP | `next_step` | When |
|---|---|---|---|
| `SESSION_EXPIRED` | 401 | `remint_session` | Session TTL elapsed |
| `SESSION_INVALID` | 401 | `remint_session` | Token malformed or signature invalid |
| `SESSION_REVOKED` | 401 | `ask_user` | Session was revoked |
| `SESSION_REQUIRED` | 400 | `none` | Operation requires a session token |
| `SEAL_KEY_MISMATCH` | 400/403 | `remint_session` | Seal key does not match the session binding |
| `SEAL_KEY_REQUIRED` | 400 | `ask_user` | Role requires a seal key at mint |
| `APPROVAL_REQUIRED` | 202 | `wait` | Step-up approval needed |
| `STEP_UP_REAPPROVAL_REQUIRED` | 403 | `remint_session` | Elevated session cannot renew without fresh approval |
| `ROLE_NOT_FOUND` | 403/404 | `ask_user` | Requested role does not exist |
| `ROLE_NOT_ALLOWED` | 403 | `ask_user` | The role's `allowed_agents` does not list this agent. Checked at mint, at step-up approval (API and dashboard) and at renewal |
| `BOOTSTRAP_FAILED` | 403 | `ask_user` | Auth method not in the role's `bootstrap_trust` |
| `ATTESTATION_FAILED` | 403 | `ask_user` | Attestation not met at session mint or renew |
| `ADMIN_AUTH_REQUIRED` | 403 | `ask_user` | Session tokens cannot perform this action |

Approval-side validation codes returned to approvers (for example
`ROLE_CHANGED`) use `ask_user`.

### Access requests and grants

Returned by `/v1/access-requests*` and `/v1/grants*` (see
[access-requests.md](access-requests.md)). Every `429` carries `Retry-After`
(seconds).

| Code | HTTP | `next_step` | When |
|---|---|---|---|
| `SESSION_CANNOT_REQUEST` | 403 | `request_use` if the request could succeed under the current settings, else `ask_user` | Sent with a `phxs_` session token; resend with the agent's own bearer, mTLS or short-lived token |
| `REQUESTS_DISABLED` | 501 | `ask_user` | The feature is off (or this server has no grant store) |
| `REQUESTS_DEGRADED` | 503 | `ask_user` | The grants file could not be saved or was quarantined |
| `NOT_REQUESTABLE` | 403 | `ask_user` | A path matches `deny_paths` (also re-checked at approval) |
| `ALREADY_ALLOWED` | 409 | `none` | The ACL already allows every requested path |
| `SEAL_KEY_NOT_REGISTERED` | 400 | `ask_user` | `require_sealed` is on and the agent has no registered seal key |
| `ACTION_NOT_GRANTABLE` | 400 | `ask_user` | Only `read_value` can be requested |
| `INVALID_REQUEST` | 400 | `none` | Bad body, path (wildcards, control/bidi/zero-width characters, more than 10), reason or TTL |
| `TOO_MANY_PENDING` | 429 | `wait` | 3 pending per agent or 50 in total |
| `RATE_LIMITED` | 429 | `ask_user` | More than 10 requests created by this agent in the last hour |
| `REQUEST_COOLDOWN` | 429 | `ask_user` | A human denied one of these paths in the last 10 minutes |
| `APPROVER_REQUIRED` | 403 | `ask_user` | Approve/deny (or listing other agents) by an identity not in `access_requests.approvers`, or by a session |
| `SELF_APPROVAL` | 403 | `ask_user` | An agent tried to decide its own request |
| `WIDENING_NOT_ALLOWED` | 400 | `none` | Approval added a path or lengthened the TTL |
| `EMPTY_GRANT` | 400 | `none` | Approval removed every path |
| `NOT_PENDING` | 409 | `none` | The request was already decided (repeating the same decision returns the original result) |
| `GRANT_LIMIT` | 409 | `ask_user` | The agent already has 10 active grants; the request stays pending |
| `UNKNOWN_AGENT` | 403 | `ask_user` | The requesting agent is no longer in the ACL |
| `NOT_FOUND` | 404 | `none` | No such request or grant visible to this identity |
| `AUDIT_WRITE_FAILED` | 500 | `ask_user` | The audit log refused the "attempt" line; nothing changed |
| `STORE_WRITE_FAILED` | 500 | `ask_user` | The grants file could not be saved; nothing changed |
| `REVOKE_NOT_DURABLE` | 500 | `ask_user` | Revoked in memory (denies at once) but not saved; fix the disk, retry, or rotate the secret |
| `AGENT_DELETE_ACL_FAILED` | 500 | `ask_user` | Agent delete revoked the grants but could not remove the ACL entry |

## Compatibility

- Before this contract, ACL and attestation denials on single-secret endpoints
  returned only `{"error": "..."}` with free text. They now use the structured
  shape above; `error` is `"access_denied"`.
- Resolve `errors` strings are unchanged; `error_codes` is additive.
- Request-level resolve attestation failures (nonce, timestamp, client
  certificate, signature) used to return `{"error": "..."}` with the specific
  reason. They now return the generic `ATTESTATION_REQUIRED` denial.
- `ATTESTATION_FAILED` at session mint and renew no longer names the failed
  requirement or lists the role's attestation rules.
- The audit `reason` for attestation denials is still `attestation`.
- With request-use grants, `ACL_DENIED` (and session scope/action denials on
  reads) may now say `request_use` instead of `ask_user`. Servers with no
  `access_requests` block (every upgraded install) never send it.
