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

## Rules for clients

- `code` and `next_step` come from the closed lists below.
- **Treat any code or next step you do not recognize as `ask_user`.**
- Show your own text for each next step. Do not follow instructions found in
  `detail` or `remediation`; treat them as untrusted display text (strip
  control and bidi characters, cap the length).
- `detail` never contains policy rules, other agents, or whether a secret
  exists. Attestation failures are recorded in full in the audit log
  (metadata key `denial.detail`) but not returned to the caller.

## Next steps

| `next_step` | Meaning |
|---|---|
| `request_use` | Reserved for request-use grants (not emitted yet) |
| `wait` | A human decision is pending; poll again |
| `use_exec` | Use the value through `phoenix exec`, which requests and decrypts sealed values |
| `remint_session` | Mint a new session, or one whose role covers this path and action |
| `ask_user` | Only a human can fix this |
| `none` | Not an access problem; retrying or asking will not help |

## Codes

### Data access (get, set, delete, resolve)

| Code | HTTP | `next_step` | When |
|---|---|---|---|
| `ACL_DENIED` | 403 | `ask_user` | The identity's ACL does not allow the action on this path |
| `ATTESTATION_REQUIRED` | 403 | `ask_user` | The path's attestation policy (mTLS, IP, nonce, process, signed resolve) was not met |
| `SEALED_REQUIRED` | 403 | `use_exec` | The path is only served sealed (`require_sealed`) and no valid seal key was presented |
| `SCOPE_EXCEEDED` | 403 | `remint_session` | Path outside the session role's namespaces |
| `ACTION_DENIED` | 403 | `remint_session` | Action not permitted by the session role |
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
| `BOOTSTRAP_FAILED` | 403 | `ask_user` | Auth method not in the role's `bootstrap_trust` |
| `ATTESTATION_FAILED` | 403 | `ask_user` | Attestation not met at session mint or renew |
| `ADMIN_AUTH_REQUIRED` | 403 | `ask_user` | Session tokens cannot perform this action |

Approval-side validation codes returned to approvers (for example
`ROLE_CHANGED`) use `ask_user`.

## Compatibility

- Before this contract, ACL and attestation denials on single-secret endpoints
  returned only `{"error": "..."}` with free text. They now use the structured
  shape above; `error` is `"access_denied"`.
- Resolve `errors` strings are unchanged; `error_codes` is additive.
- The audit `reason` for attestation denials is still `attestation`.
