# Release Notes (Draft)

## Unreleased

### Session Identity (v1)

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
