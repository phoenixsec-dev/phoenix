# Phoenix — Operator Dashboard

The operator dashboard is a browser-based web UI for managing approvals,
sessions, audit, and roles. It is designed for human operators — not agents.

All HTML, CSS, JS, and SVG are embedded in the binary via `go:embed`. There
are no external dependencies, no CDN loads, and no build step.

## When to use it

- Approving or denying step-up requests from a phone or browser instead of CLI
- Reviewing active sessions and revoking compromised ones
- Tailing the audit log without SSH access to the server
- Inspecting role configuration at a glance

The dashboard is optional. Everything it does can also be done via the CLI
(`phoenix approve`, `phoenix sessions list`, etc.) or the API.

## Security model

The dashboard is a **separate auth surface** from the Phoenix API. It does
not use bearer tokens, mTLS, or session tokens. Instead:

- **Cookie auth**: HMAC-signed JSON payload with expiry, CSRF token, and
  session nonce. `HttpOnly`, `SameSite=Strict`, and `Secure` (when TLS detected).
- **Password or PIN**: Password stored as bcrypt hash in config. PIN uses
  constant-time comparison. Only one is needed.
- **Single active session**: By default, only one dashboard session exists
  at a time. A new login is rejected if a session is already active. A
  Force Login option re-authenticates and invalidates the prior session.
  Configurable via `allow_multi_login`.
- **Rate limiting**: Exponential backoff per source IP after 5 failed
  attempts (1s base, 60s cap). Rate-limited and failed attempts are
  logged to the audit trail.
- **CSRF**: Every mutation (approve, deny, revoke, logout) requires a
  token from the signed cookie. Validated with `hmac.Equal`.
- **No API proxy**: The dashboard reads stores directly via a `Deps`
  struct. It never calls the `/v1/` API endpoints, so API auth
  (bearer/mTLS) is not involved.

### What the dashboard can do

| Action | Risk level | Notes |
|--------|-----------|-------|
| View secrets count | Low | Count only, never values |
| View agent names | Low | Names only, no tokens |
| View active sessions | Medium | Exposes agent names, roles, IPs |
| Revoke sessions | Medium | Immediate effect, audited |
| View pending approvals | Medium | Exposes agent names, roles, IPs, namespaces |
| Approve step-up requests | **High** | Mints a session token for an agent |
| Deny step-up requests | Medium | Blocks an agent's session request |
| View audit log | Medium | Full access to audit trail |
| View role config | Low | Read-only |

Approval is the highest-risk action. It runs the same safety checks as
the API (`approval.ValidateForMint`): role existence, step-up still
enabled, bootstrap trust, attestation requirements, and seal key.

### What the dashboard cannot do

- Read or write secret values
- Create or modify agents
- Issue or revoke certificates
- Change server configuration
- Modify ACLs or policies

## Transport security

The dashboard session cookie carries admin-equivalent access to session
and approval management. Protecting it in transit is critical.

### Recommended: TLS reverse proxy

The safest general deployment is behind a TLS-terminating reverse proxy
(Nginx, Caddy, NPM, Traefik):

```
Browser --[HTTPS]--> Reverse Proxy --[HTTP]--> Phoenix (127.0.0.1:9090)
```

The proxy sets `X-Forwarded-Proto: https`, which Phoenix detects to
enable the `Secure` cookie flag. The server itself can bind to loopback.

### Alternative: mTLS mode

If Phoenix runs with `auth.mtls.enabled: true`, TLS is native and the
cookie gets `Secure` automatically via `r.TLS != nil`.

### Alternative: loopback only

If `server.listen` is `127.0.0.1:9090` (the default), the dashboard is
only reachable from the server host itself. This is safe for local-only
operator access. Use SSH port forwarding for remote browser access:

```bash
ssh -L 9090:127.0.0.1:9090 user@phoenix-host
# Then open http://127.0.0.1:9090/dashboard/ in your browser
```

### Not acceptable

Do not expose the dashboard over plain HTTP on a network you do not
fully control. The session cookie would be transmitted in cleartext,
making session hijacking trivial.

## Configuration

Generate a password hash:

```bash
phoenix-server --hash-password
# Enter dashboard password: ****
# Confirm dashboard password: ****
# $2a$10$...
```

Add the hash to your server config:

```json
{
  "dashboard": {
    "enabled": true,
    "password_hash": "$2a$10$...",
    "session_ttl": "4h"
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `bool` | Enable the dashboard at `/dashboard/` |
| `password_hash` | `string` | bcrypt hash of operator password |
| `pin` | `string` | Alternative: numeric or short PIN (constant-time compare) |
| `session_ttl` | `string` | Browser session lifetime (default `4h`) |
| `allow_multi_login` | `bool` | Allow concurrent dashboard sessions (default `false`) |

Either `password_hash` or `pin` is required. Use `password_hash` for
production deployments. `pin` is acceptable for local/loopback-only use
where convenience matters more than brute-force resistance.

By default, only one dashboard session is active at a time. A second
login attempt is rejected with a message to log out from the other
device first. If the other session is orphaned (browser closed without
logging out), a **Force Login** button appears that re-authenticates
and takes over, invalidating the old session. Set `allow_multi_login`
to `true` if concurrent operator sessions are needed.

The password is stored as a bcrypt hash — the plaintext never appears
in config. Config validation rejects non-bcrypt values in `password_hash`
to prevent accidental plaintext storage. An agent reading the config file
sees only the hash, which cannot be used to authenticate.

## Pages

### Overview (`/dashboard/`)

Status cards showing secrets count, agent count, active sessions, and
pending approvals. Server uptime and session-enabled status. Table of
the 10 most recent audit entries.

### Approvals (`/dashboard/approvals`)

Each pending approval is a card showing: role name, agent name, source
IP, bootstrap method, certificate fingerprint (truncated), namespaces,
requester TTY, created/expires timestamps with countdown.

Approve and Deny buttons with JavaScript confirmation dialogs. Both
submit POST forms with CSRF tokens.

Below: recently resolved approvals (collapsed by default) as a table
with status badges.

### Sessions (`/dashboard/sessions`)

Table of active sessions: ID (truncated), role, agent, source IP,
bootstrap method, created time, TTL remaining (color-coded), and a
Revoke button.

Filter bar: role dropdown and agent text search. Filters are query
params handled server-side.

### Audit (`/dashboard/audit`)

Table of audit entries: timestamp, agent, action, path, status (green/red
dot), IP, session ID, reason. Filters for agent, status (allowed/denied),
and result limit (50/100/500).

The audit page auto-refreshes every 30 seconds via client-side fetch.

### Roles (`/dashboard/roles`)

Read-only cards for each configured role: name, namespace pills, action
pills, bootstrap trust pills, and flags for step-up, seal key, max TTL,
and attestation requirements.

## Audit trail

All dashboard actions are logged to the same audit trail as API actions.

| Action | Status | Agent | When |
|--------|--------|-------|------|
| `dashboard.login` | allowed | `dashboard@<ip>` | Successful login |
| `dashboard.login` | denied | `dashboard` | Failed login (invalid credentials) |
| `dashboard.login` | denied | `dashboard` | Rate-limited login attempt |
| `dashboard.login` | denied | `dashboard` | Blocked by active session |
| `dashboard.force_login` | allowed | `dashboard@<ip>` | Force login (took over existing session) |
| `dashboard.force_login` | denied | `dashboard` | Force login with wrong credentials |
| `dashboard.logout` | allowed | `dashboard@<ip>` | Explicit logout |
| `dashboard.auth` | denied | `dashboard` | Expired, invalid, or superseded cookie |
| `dashboard.csrf` | denied | `dashboard` | CSRF token mismatch on a POST action |
| `approval.approved` | allowed | `dashboard@<ip>` | Step-up request approved |
| `approval.denied` | allowed | `dashboard@<ip>` | Step-up request denied |
| `session.revoke` | allowed | `dashboard@<ip>` | Session revoked |

Post-login actions use `dashboard@<client_ip>` for per-operator forensic
distinction. Pre-login events (failures, rate limiting, expired cookies)
use `dashboard` since there is no authenticated identity.

Missing-cookie redirects (e.g., a first visit to `/dashboard/`) are not
logged — they are normal navigation, not security events. Only present-
but-invalid cookies generate `dashboard.auth` denied entries.

## Deployment checklist

Use this checklist when enabling the dashboard on an existing Phoenix server.

1. Choose transport mode:
   - [ ] TLS reverse proxy (recommended), or
   - [ ] Native mTLS (`auth.mtls.enabled: true`), or
   - [ ] Loopback only (`server.listen: "127.0.0.1:..."`)

2. Choose credential mode:
   - [ ] Password (recommended for production)
   - [ ] PIN (acceptable for loopback-only)

3. Generate password hash: `phoenix-server --hash-password`

4. Add config:
   ```json
   { "dashboard": { "enabled": true, "password_hash": "$2a$10$..." } }
   ```

5. Protect config file: `chmod 600 /data/phoenix/config.json`

6. Restart server, verify log line: `Dashboard: enabled at /dashboard/`

7. Open browser, verify login page loads at `/dashboard/login`

8. Login, verify all pages render (overview, approvals, sessions, audit, roles)

9. Test approval flow end-to-end if step-up roles are configured:
   - Trigger a step-up mint (agent sends `POST /v1/session/mint` for a step-up role)
   - Approve from dashboard
   - Verify session appears in sessions list
   - Verify audit entries for the approval

10. Verify audit trail shows `dashboard@<your-ip>` entries

11. From a different machine, verify the dashboard is **not** reachable
    over plain HTTP (unless you explicitly chose loopback-only)

## Related docs

- [Configuration](configuration.md) — config field reference
- [Session Identity](session-identity.md) — step-up approval workflow
- [Authentication](authentication.md) — API auth model (separate from dashboard)
- [Threat Model](threat-model.md) — dashboard attack surface
- [LAN Deployment](lan-deployment.md) — multi-host setup
