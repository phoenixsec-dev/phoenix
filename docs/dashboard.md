# Phoenix — Operator Dashboard

The operator dashboard is a browser-based web UI for managing approvals,
sessions, audit, and roles. It is designed for human operators — not agents.

All HTML, CSS, JS, and SVG are embedded in the binary via `go:embed`. There
are no external dependencies, no CDN loads, and no build step.

## When to use it

- Approving or denying access requests from a phone or browser instead of CLI
- Reviewing active sessions and revoking compromised ones
- Tailing the audit log without SSH access to the server
- Inspecting role configuration at a glance

The dashboard is optional. Everything it does can also be done via the CLI
(`phoenix approve`, `phoenix sessions list`, etc.) or the API.

## Security model

The dashboard is a **separate auth surface** from the Phoenix API. It does
not use bearer tokens or session tokens. Instead:

- **Cookie auth**: HMAC-signed JSON payload with expiry, CSRF token, and
  session nonce. `HttpOnly`, `SameSite=Strict`, and `Secure` (when HTTPS detected).
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
  (bearer tokens) is not involved.

### What the dashboard can do

| Action | Risk level | Notes |
|--------|-----------|-------|
| View secrets count | Low | Count only, never values |
| View agent names | Low | Names only, no tokens |
| View active sessions | Medium | Exposes agent names, roles, IPs |
| Revoke sessions | Medium | Immediate effect, audited |
| View pending access requests | Medium | Exposes agent names, paths, IPs, reasons |
| Approve access requests | **High** | Grants an agent temporary use of exact secret paths |
| Deny access requests | Medium | Starts a 10-minute cooldown on those paths |
| Revoke grants | Medium | Immediate effect; does not recall values already used |
| View audit log | Medium | Full access to audit trail |
| View role config | Low | Read-only |

Approval is the highest-risk action. Access-request approval goes through the API server's shared approval
function (`ApproveAccessRequestAs`), so it applies exactly the API's
re-checks against the current config. Deny and revoke call the grant store,
as the API does. This is the one place the dashboard reaches into the API
server rather than a store, and it is deliberate: one copy of the checks.

### What the dashboard cannot do

- Read or write secret values
- Create or modify agents
- Change server configuration
- Modify ACLs or policies

## Transport security

The dashboard session cookie carries admin-equivalent access to session
and access-request management. Protecting it in transit is critical.

### Default: loopback only

If `server.listen` is `127.0.0.1:9090` (the default), the dashboard is
only reachable from the server host itself. This is safe for local-only
operator access — plain HTTP on loopback never touches the network. Use
SSH port forwarding for remote browser access:

```bash
ssh -L 9090:127.0.0.1:9090 user@phoenix-host
# Then open http://127.0.0.1:9090/dashboard/ in your browser
```

### Network access: native HTTPS

If other machines need to reach the dashboard, turn on the server's HTTPS
endpoint (`--init` already wrote the rest of the block):

```json
{ "https_listener": { "enabled": true } }
```

It uses the `--init` server certificate (import `ca.crt` into the browser's
trust store or accept the certificate), and the cookie gets `Secure`
automatically via `r.TLS != nil`. Browse to `https://<host>:9443/dashboard/`.

### Network access: TLS reverse proxy

Alternatively, deploy behind a TLS-terminating reverse proxy
(Nginx, Caddy, NPM, Traefik):

```
Browser --[HTTPS]--> Reverse Proxy --[HTTP]--> Phoenix (127.0.0.1:9090)
```

The proxy sets `X-Forwarded-Proto: https`, which Phoenix detects to
enable the `Secure` cookie flag. The server itself binds to loopback.

### Not acceptable

Do not expose the dashboard over plain HTTP on a network you do not
fully control. The session cookie would be transmitted in cleartext,
making session hijacking trivial. If the dashboard is enabled on a
non-loopback plain HTTP bind, the server logs a prominent
`INSECURE TRANSPORT` startup warning that names the dashboard cookie
exposure — it warns and continues; fixing the config is on you.

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

Status cards showing secrets count, agent count and active sessions. Server uptime and session-enabled status. Table of
the 10 most recent audit entries.

Also an **Access Requests** card with the pending count, and a red banner
when the grants file or grant audit events are degraded.

### Approvals (`/dashboard/approvals`)

**Secret access requests** come first: one card per pending request with
every fact an approver needs (paths in full with badges, source IP and auth
method, TTL picker limited to legal values, delivery mode, attestation
requirements, the agent's reason labelled "not verified", the agent's last
24 hours). Details in [Access requests](access-requests.md#in-the-dashboard).

When `access_requests` is not configured, the page says access requests
are turned off. (Step-up session approvals were removed; their cards are
gone.)

A new access request can also ping your phone (for example through ntfy).
The notification links to this page with the request's `#req_...` anchor;
you still log in here to decide. Set `access_requests.notify_url` and
`notify_dashboard_url` (see [Access requests](access-requests.md#notifications)).

Approve and Deny buttons with JavaScript confirmation dialogs. Both
submit POST forms with CSRF tokens.

### Grants (`/dashboard/grants`)

Active request-use grants (agent, paths, action, expires in, uses, last
used, approved by) with a Revoke button, and a Recent view of expired and
revoked grants. A revoke that could not be saved shows `REVOKE_NOT_DURABLE`
in red and stays on screen.

### Sessions (`/dashboard/sessions`)

Table of active sessions: ID (truncated), role, agent, source IP,
bootstrap method, created time, TTL remaining (color-coded), and a
Revoke button.

Filter bar: role dropdown and agent text search. Filters are query
params handled server-side.

### Audit (`/dashboard/audit`)

Table of audit entries: timestamp, agent, action, path, status (green/red
dot), IP, session ID, reason. Filters for agent, status (allowed/denied),
and result limit (50/100/500). Secret paths are always shown in full and
wrap on narrow screens. Filters run on the server while it reads the
log backwards from the newest entry, so "denied, 50" shows the newest 50
denied entries. The search covers the current file and the newest archive,
up to 64 MB; when that cut it short a note above the table says older
entries were not searched (see
[Audit log rotation](configuration.md#audit-log-rotation)).

The audit page auto-refreshes every 30 seconds via client-side fetch.

### Roles (`/dashboard/roles`)

Read-only cards for each configured role: name, namespace pills, action
pills, bootstrap trust pills, and flags for seal key, max TTL, and
attestation requirements.

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
| `session.revoke` | allowed | `dashboard@<ip>` | Session revoked |
| `access_request.approved` / `.denied` | allowed | `dashboard@<ip>` | Access request decided (plus an `.attempt` line before it) |
| `access_request.approve` | denied | `dashboard@<ip>` | Approval refused by a re-check (reason = code) |
| `grant.revoked` | allowed | `dashboard@<ip>` | Grant revoked |

Post-login actions use `dashboard@<client_ip>` for per-operator forensic
distinction. Pre-login events (failures, rate limiting, expired cookies)
use `dashboard` since there is no authenticated identity.

Missing-cookie redirects (e.g., a first visit to `/dashboard/`) are not
logged — they are normal navigation, not security events. Only present-
but-invalid cookies generate `dashboard.auth` denied entries.

## Deployment checklist

Use this checklist when enabling the dashboard on an existing Phoenix server.

1. Choose transport mode:
   - [ ] Loopback only (`server.listen: "127.0.0.1:..."`, the default), or
   - [ ] Native HTTPS (`"https_listener": {"enabled": true}`), or
   - [ ] TLS reverse proxy in front of a loopback bind

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

9. Test approval flow end-to-end if access requests are on:
   - Have an agent ask (`phoenix request <path> --reason "test"`)
   - Approve from the dashboard
   - Verify the grant appears on the Grants page
   - Verify audit entries for the approval

10. Verify audit trail shows `dashboard@<your-ip>` entries

11. From a different machine, verify the dashboard is **not** reachable
    over plain HTTP (unless you explicitly chose loopback-only)

## Related docs

- [Configuration](configuration.md) — config field reference
- [Access Requests](access-requests.md) — the approval workflow
- [Authentication](authentication.md) — API auth model (separate from dashboard)
- [Threat Model](threat-model.md) — dashboard attack surface
- [LAN Deployment](lan-deployment.md) — multi-host setup
