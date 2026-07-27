# Release Notes

## v0.16.0 (2026-07-27)

### Hermes Caller Metadata Audit Capture

- Captures the sanitized `X-Hermes-Profile`, `X-Hermes-Session-Id`,
  `X-Hermes-Channel`, `X-Hermes-Tool`, and `X-Hermes-Task-Id` headers as
  audit-only metadata under `hermes.*` keys, for the `hermes-phoenix` plugin.
- Generalized the OpenClaw-specific header table into a single
  platform-neutral caller-metadata allowlist. The OpenClaw family, its
  `openclaw.*` audit keys, the 256-byte cap, and the sanitization rules are
  unchanged.
- The allowlist stays compiled in rather than operator-configurable, so no
  configuration change can route a credential header into the audit log.
- `X-Phoenix-Tool` remains an attestation policy input and is never recorded
  as caller metadata; the audit-only `X-Hermes-Tool` hint cannot satisfy
  `allowed_tools`.
- Added unit coverage for Hermes capture, absent headers, oversize/control
  sanitization, ACL and attestation spoof resistance, both families on one
  request, and an allowlist self-check that rejects credential-bearing or
  `X-Phoenix-*` entries. Added e2e scenario 20.
- `GET /v1/secrets` list responses now return `"paths": []` instead of
  `"paths": null` when no paths are visible.

> `v0.16.0` is the minimum Phoenix version for `hermes-phoenix` first-class
> audit metadata. Older servers ignore the `X-Hermes-*` family entirely.

## v0.15.2 (2026-07-12)

### OpenClaw Exec Provider Merge-Review Fixes

- Session mint with `PHOENIX_ROLE` no longer fails when the home directory
  cannot be determined and no `PHOENIX_SEAL_KEY` is set; the CLI now mints an
  unsealed session, matching the missing-key-file behavior.
- The exec provider short-circuits an empty `ids` list to an empty response
  without calling the resolve API.
- The exec provider rejects trailing non-whitespace data after the stdin JSON
  request object.
- Audit metadata sanitization now strips Unicode format/bidi control
  characters (category Cf, e.g. U+202E) from `X-OpenClaw-*` header values.
- Added tests for the sealed-envelope decrypt branch, non-200 server
  responses in the exec-provider path, missing-HOME session mint, and
  format-control sanitization.
- Documented the three exec-provider auth modes (bootstrap token + role,
  mTLS + role, pre-minted session token) and the invalid combinations,
  added `HOME` to the recommended `passEnv` example, documented the
  audit-only `X-OpenClaw-*` metadata headers, and noted that signed resolve
  is not supported in the exec-provider path. `phoenix openclaw-exec-provider`
  is now documented as the canonical command form.

## v0.15.1 (2026-06-17)

### OpenClaw Audit Metadata

- Captures sanitized allowlisted `X-OpenClaw-*` metadata headers on server audit entries as audit hints only.
- Omits raw `X-OpenClaw-Session-Key` from audit records.
- Added tests proving spoofed OpenClaw headers do not affect Phoenix authorization, attestation policy identity, or sealed-response policy decisions.

## v0.15.0 (2026-04-27)

### OpenClaw SecretRef Exec Provider

- Added `phoenix openclaw-exec-provider` for OpenClaw's built-in exec SecretRef provider protocol.
- Added `phoenix secret-provider openclaw` and `phoenix resolve --stdin-json` aliases for compatibility with OpenClaw exec-provider configuration.
- The provider reads OpenClaw's stdin JSON request, resolves requested ids through Phoenix using the existing auth/session/mTLS/sealed-response paths, and writes OpenClaw-compatible `values`/`errors` JSON to stdout.
- Added tests for request parsing, stdout response shape, id normalization, and partial per-id failures.
- Updated OpenClaw integration docs to distinguish bootstrap/config SecretRefs from runtime `openclaw-phoenix` plugin tools, and to stop claiming plain `phoenix resolve <ref>` is the exec-provider protocol.

## v0.13.5 (2026-04-07)

### Step-Up Authorization Hygiene

- Fixed step-up authorization semantics so approved step-up sessions can
  temporarily grant access beyond the base agent ACL when the role is
  explicitly configured with `elevates_acl: true`.
- Fixed elevated step-up session renewal so temporary ACL elevation cannot be
  extended transparently; elevated sessions now require a fresh mint and human
  approval to continue.
- Preserved path policy, attestation, seal-key binding, expiry, and revocation
  enforcement for elevated step-up sessions.
- Added targeted API/session tests covering elevated access, revocation,
  expiry, non-step-up ACL behavior, policy/seal-key enforcement, and
  reapproval-required renewal behavior.
- Updated session/auth/API docs and SDK approval classification for the new
  `STEP_UP_REAPPROVAL_REQUIRED` denial path.

## v0.13.4 (2026-04-04)

### Stabilization Fixes

- Fixed CLI role-session cache reuse so repeated `PHOENIX_ROLE` invocations
  reuse valid cached sessions and only renew near expiry instead of minting
  fresh sessions unnecessarily.
- Fixed role-bound sealed sessions so requests consistently use the same seal
  key resolution path as session minting, including
  `~/.phoenix/session-seal-<role>.key`.
- Fixed `phoenix list` and adjacent sealed request paths to send
  `X-Phoenix-Seal-Key` when using sealed role sessions.
- Added sealed-success audit metadata so allowed sealed reads and resolves are
  distinguishable from plaintext success paths.
- `phoenix policy show` now displays `require_sealed`.
- Clarified `phoenix keypair generate -o` as a file path, with fast failure for
  directory-style output values.
- Fixed dashboard template rendering so page-specific `content` blocks do not
  collide across pages.

## v0.13.3 (2026-03-20)

### Session Identity

Role-based session tokens replace static bearer tokens for agent access.

- **Named roles** — define namespace scope, allowed actions, bootstrap trust,
  and optional step-up approval per role in server config
- **Session tokens** — short-lived (`phxs_` prefix), scoped credentials with
  auto-renewal and explicit revocation
- **Bootstrap trust** — roles declare which auth methods (bearer, mTLS, local,
  token) can mint sessions
- **Step-up approval** — roles with `step_up: true` require human confirmation
  via `phoenix approve` before the session is granted
- **CLI** — `phoenix sessions list|info|revoke` for session management
- **SDK** — `NewWithRole()`, `MintSession()`, `ListSessions()`, `RevokeSession()`,
  and error classification helpers (`IsSessionExpired`, `IsSessionRevoked`,
  `IsScopeExceeded`, `IsApprovalRequired`, `IsActionDenied`)
- **MCP** — auto-mint via `PHOENIX_ROLE`, background renewal,
  `phoenix_session_list` and `phoenix_session_revoke` tools, agent-friendly
  denial messages with remediation hints
- **Structured denials** — machine-readable denial codes on all session and
  access control failures (SESSION_EXPIRED, SCOPE_EXCEEDED, etc.)
- **Audit** — full session lifecycle audit trail: mint, renew, revoke, auth
  failures with session context, step-up approval workflow events
- **Access isolation** — session tokens can only inspect/revoke their own
  exact session; no ACL escalation from scoped credentials

### MCP Streamable HTTP Transport

The MCP server now supports Streamable HTTP in addition to stdio:

```bash
phoenix mcp-server --http 127.0.0.1:8080 --mcp-token <token>
```

Endpoint: `/mcp`. Auth via `Authorization: Bearer <mcp-token>`. Tool identity
headers carry through for policy evaluation.

### Operator Dashboard

Lightweight browser-based operator UI at `/dashboard/` — no external
dependencies, all assets embedded via `go:embed`.

- **Overview** — secret/agent/session counts, server uptime, recent audit
- **Approvals** — pending step-up approvals as cards with full context;
  approve/deny with shared safety checks (role, bootstrap, attestation, seal key)
- **Sessions** — active sessions table with filters and one-click revoke
- **Audit** — filterable audit log with auto-refresh
- **Roles** — read-only role inspection with namespace/action/trust pills
- **Auth** — cookie-based with HMAC-signed tokens, bcrypt password or PIN,
  CSRF protection on all mutations (including logout), `Secure` cookie
  flag auto-detected from TLS
- **Rate limiting** — exponential backoff per source IP on login
- **Audit** — full lifecycle: login success/failure, logout, expired session
  rejection, CSRF failures, approve/deny/revoke actions; post-login actions
  tagged `dashboard@<ip>` for per-operator distinction
- **Mobile** — responsive layout with bottom nav bar on small screens
- **Design** — dark industrial theme, phoenix red-orange accent gradient

### Infrastructure & Publishing
- Added GitHub Actions repository secrets required for Docker publishing:
  - `DOCKERHUB_USERNAME`
  - `DOCKERHUB_TOKEN`
  - `DOCKERHUB_NAMESPACE`
- Docker Hub org namespace is now `phoenixsecdev` with repository `phoenixsecdev/phoenix`.
- Updated release workflow Docker image target from `phoenixsec/phoenix` to `phoenixsecdev/phoenix`.
- Added `workflow_dispatch` trigger to `release.yml` so releases can be run manually for verification.

### Repository Security
- Enabled branch protection on `main`:
  - Pull request required before merge
  - 1 required approval
  - Dismiss stale reviews on new commits
  - Require conversation resolution
  - Force-push disabled
  - Branch deletion disabled
  - Admins are enforced

### Notes
- Deploy keys are disabled by org/repo policy, so push auth was set up using a personal GitHub SSH key instead.
