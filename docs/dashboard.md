# Phoenix — Operator Dashboard

The operator dashboard is a browser-based web UI for finding and using
secrets, and for managing approvals, sessions, audit, and roles. It is designed
for human operators — not agents — and for a phone first.

All HTML, CSS, JS, and SVG are embedded in the binary via `go:embed`. There
are no external dependencies, no CDN loads, and no build step.

## When to use it

- Finding a login by what it is for, and copying its password, from a phone
- Approving or denying access requests from a phone or browser instead of CLI
- Reviewing active sessions and revoking compromised ones
- Tailing the audit log without SSH access to the server
- Inspecting role configuration at a glance

The dashboard is optional. New installs have it on; an existing install has it off until it
has a password. Everything it does can also be done via the CLI
(`phoenix approve`, `phoenix sessions list`, etc.) or the API.

## Install it as an app

Open the dashboard over HTTPS with a certificate the device trusts, then use
the browser's *Install app* or *Add to Home Screen*. It opens on the secrets
list. The app keeps only its own files (styles, scripts, icons, a "can't reach
Phoenix" page) on the device. No page, answer or secret is ever stored offline.

## Security model

The dashboard is a **separate auth surface** from the Phoenix API. It does
not use bearer tokens or session tokens. Instead:

- **Cookie auth**: HMAC-signed JSON payload with expiry, CSRF token, and
  session nonce. `HttpOnly`, `SameSite=Strict`, and `Secure` (when HTTPS detected).
- **Password**: stored as a bcrypt hash in config; the plaintext never
  appears there.
- **Several logins, each listed**: up to 5 browsers can be signed in at
  once (a desktop and a phone, say). The Sessions page lists each one and
  can sign it out. A 6th login signs out the one used least recently, so
  the password holder is never locked out. Logins live in server memory:
  logout and sign-out end them on the server, and a restart ends them all.
- **Rate limiting**: Exponential backoff per source IP after 5 failed
  attempts (1s base, 60s cap). Rate-limited and failed attempts are
  logged to the audit trail.
- **CSRF**: Every mutation (approve, deny, revoke, logout) requires a
  token from the signed cookie. Validated with `hmac.Equal`. A POST a browser
  marks as coming from another site (`Sec-Fetch-Site`, or `Origin` in older
  browsers) is refused before that.
- **Recent password**: showing, copying, adding or changing a secret needs the
  password to have been typed in this browser in the last 5 minutes. A login
  counts; after that the page asks again. The window does not grow with use.
  Typing it again moves the login to a new cookie, so a copied old cookie stops
  working. Wrong passwords count in the same rate limit as logins, per address
  and per login, and parallel guesses count one by one.
- **Values**: a value leaves the server only as the answer to a POST that passed
  the cookie, CSRF token, same-origin and recent-password checks and the path's
  policy rule, and only after its audit line was written. It is never in a page's
  HTML and never cached. On screen it hides after 20 seconds and when you leave
  the page or switch apps.
- **Headers**: every response forbids framing, runs only the dashboard's own
  script files (Content-Security-Policy) and, except for static files, is
  `no-store`.
- **No API proxy**: The dashboard reads stores directly via a `Deps`
  struct. It never calls the `/v1/` API endpoints, so API auth
  (bearer tokens) is not involved.

### What the dashboard can do

| Action | Risk level | Notes |
|--------|-----------|-------|
| Find secrets | Medium | Every name, description, tag, username and link |
| Show or copy a secret value | **High** | Recent password, policy rule and audit line needed; `dashboard.reveal: false` turns it off |
| Add a secret, set a new value | **High** | Recent password; a new value needs a confirm, the old one is gone |
| Edit description, tags, username, link | Medium | Recent password; the value is not touched |
| View agent names | Low | Names only, no tokens |
| View active sessions | Medium | Exposes agent names, roles, IPs |
| Revoke sessions | Medium | Immediate effect, audited |
| View pending access requests | Medium | Exposes agent names, paths, IPs, reasons |
| Approve access requests | **High** | Grants an agent temporary use of exact secret paths |
| Deny access requests | Medium | Starts a 10-minute cooldown on those paths |
| Revoke grants | Medium | Immediate effect; does not recall values already used |
| View audit log | Medium | Full access to audit trail |
| View role config | Low | Read-only |

Values and approvals are the highest-risk actions. Access-request approval goes through the API server's shared approval
function (`ApproveAccessRequestAs`), so it applies exactly the API's
re-checks against the current config. Deny and revoke call the grant store,
as the API does. This is the one place the dashboard reaches into the API
server rather than a store, and it is deliberate: one copy of the checks.

### What the dashboard cannot do

- Delete secrets
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

New installs have the dashboard on: `phoenix-server --init` asks for its
password (or generates one and shows it once) and writes only the bcrypt hash.
To turn it on for an older install, or to change the password, generate a hash
(yourself, not through an agent):

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
    "session_ttl": "4h",
    "reveal": true
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `bool` | Enable the dashboard at `/dashboard/` |
| `password_hash` | `string` | bcrypt hash of operator password |
| `session_ttl` | `string` | Browser session lifetime (default `4h`) |
| `reveal` | `bool` | Show and copy secret values (default `true`) |

`password_hash` is required (generate it with `phoenix-server
--hash-password`). The old `pin` field was removed: it stored a short
plaintext secret in config, and a config that still sets it will not start.

Up to 5 dashboard logins can be active at once; see
[Sessions](#sessions-dashboardsessions). `session_ttl` is how long each
login lasts from when it signed in. The old `allow_multi_login` setting
and the Force Login button are gone (several logins are always allowed);
a config that still has `allow_multi_login` refuses to start until the
line is deleted.

The password is stored as a bcrypt hash — the plaintext never appears
in config. Config validation rejects non-bcrypt values in `password_hash`
to prevent accidental plaintext storage. An agent reading the config file
sees only the hash, which cannot be used to authenticate.

## Pages

On a desktop every page is in the sidebar. On a phone the bar at the bottom
has Home, Secrets, Approvals and **More** (`/dashboard/more`), which lists the
other pages and Sign out.

### Overview (`/dashboard/`)

A search box for secrets, then status cards showing secrets count, agent count and active sessions. Server uptime and session-enabled status. Table of
the 10 most recent audit entries.

Also an **Access Requests** card with the pending count, and a red banner
when the grants file or grant audit events are degraded.

### Secrets (`/dashboard/secrets`)

The list filters as you type, over name, description, tags and username; every
word must match. Open a secret to see its description, tags, username, link,
who set the value and when, and who may read it (agents by permission, agents
with temporary access, and the path's policy rule).

- **Show** puts the value on screen for 20 seconds. **Copy** copies it without
  showing it. **Copy password and open the page** does both steps of a login;
  the site it opens is named under the button. Nothing ties the password to that
  site: look at the name before you paste. What you copied stays on the
  device's clipboard.
- If the page says a rule stops it, the path's policy needs sealed delivery or
  another machine. Rules hold here for showing, copying and setting a value,
  not for finding a secret or editing its details. `source_ip` is checked
  against the network connection, so behind a reverse proxy that is the
  proxy's address.
- **Add secret**: paste, type or generate a value. Names are a folder, a slash
  and a name. Adding never overwrites.
- **Edit details** changes description, tags, username and link only.
- **New value** replaces the value after a confirm. The old one is gone.

With the 1Password backend, secrets can be found and shown but not changed.
Finding them reads the vault's items into the server's memory, as listing does.

### Requests (`/dashboard/requests`)

Everything about access requests on one live page: what is waiting (answer
with **No**, **Once**, **15 minutes** or **Always**), what is open now with
**Revoke**, what is on Always with **Remove**, what expired unanswered, and
history. Details in [Access requests](access-requests.md#in-the-dashboard).

New requests show up within about two seconds on every open dashboard page: in
the list here, as a popup elsewhere. The script polls
`/dashboard/requests/feed`; nothing needs changing in a reverse proxy. Polling
does not count as using the dashboard, so an open tab does not keep its login
from being the least recently used one.

A notification (for example through ntfy) links to
`/dashboard/requests/<req_id>`. If you are not logged in, the login page brings
you back to that request. Set `access_requests.notify_url` and
`notify_dashboard_url` (see [Access requests](access-requests.md#notifications)).

`/dashboard/approvals` and `/dashboard/grants`, the two pages this replaced,
redirect here.

### Sessions (`/dashboard/sessions`)

**Dashboard logins** at the top: one row per signed-in browser with its
device (for example "Chrome on Android", from the User-Agent; hover for
the full string), the IP of its last request, when it signed in, when it
was last used and how long until it expires. Your own browser is marked
"this device". **Sign out** ends that login at once; signing out your
own works like Logout. At most 5 logins exist; a new one past that signs
out the least recently used.

**Agent sessions** below: table of active role sessions: ID (truncated), role, agent, source IP,
bootstrap method, created time, TTL remaining (color-coded), and a
Revoke button.

Filter bar: role dropdown and agent text search. Filters are query
params handled server-side.

### Audit (`/dashboard/audit`)

Table of audit entries: timestamp, agent, who, host, authority, attested,
action, path, status (green/red dot), IP, session ID, reason. Filters for
agent, who, host, authority, status (allowed/denied), and result limit
(50/100/500). Filters match whole values. The agent filter also finds lines
under the identity's former names and says so.

`no (declared)` under Attested means an admin gave the identity that who or
authority and nothing checked it; a `-` means the line has no such field, as
in lines from before v0.25.0. See
[Who, authority and kind](authentication.md#who-authority-and-kind).
 Secret paths are always shown in full and
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
| `dashboard.login_evicted` | allowed | `dashboard@<ip>` | A new login pushed out the least recently used one (path = its ID, IP = its last IP) |
| `dashboard.login_revoke` | allowed | `dashboard@<ip>` | A login signed out from the Sessions page (path = its ID) |
| `dashboard.reauth` | allowed / denied | `dashboard@<ip>` | Password typed again for secrets: right, wrong, or rate limited |
| `read_value` | allowed / denied | `dashboard@<ip>` | A secret shown or copied, or refused (`attestation`, `reveal_off`, or `signed_out` when the login ended, or its cookie was replaced by typing the password again, during the read). Metadata `dashboard.use`: `show` or `copy` |
| `write` | allowed / denied | `dashboard@<ip>` | A secret added or given a new value, or refused by a policy rule |
| `describe` | allowed | `dashboard@<ip>` | Description, tags, username or link changed (metadata `changed`) |
| `dashboard.logout` | allowed | `dashboard@<ip>` | Explicit logout |
| `dashboard.auth` | denied | `dashboard` | Expired, invalid, or signed-out cookie |
| `dashboard.csrf` | denied | `dashboard` | CSRF token mismatch on a POST action, or a POST from another site (`cross_site_request`) |
| `session.revoke` | allowed | `dashboard@<ip>` | Session revoked |
| `access_request.approved` / `.denied` | allowed | `dashboard@<ip>` | Access request decided (plus an `.attempt` line before it) |
| `access_request.approve` | denied | `dashboard@<ip>` | Approval refused by a re-check (reason = code) |
| `grant.revoked` | allowed | `dashboard@<ip>` | Grant revoked |

The secrets actions, `dashboard.login` and `dashboard.reauth` carry metadata
`dashboard.login`: the ID of the login that did it, the same on every line.

Post-login actions use `dashboard@<client_ip>` for per-operator forensic
distinction. Pre-login events (failures, rate limiting, expired cookies)
use `dashboard` since there is no authenticated identity.

Missing-cookie redirects (e.g., a first visit to `/dashboard/`) are not
logged — they are normal navigation, not security events. Only present-
but-invalid cookies generate `dashboard.auth` denied entries.

## Deployment checklist

Use this checklist when enabling the dashboard on an existing Phoenix server.
(`--init` did steps 2 to 4 on a new one.)

1. Choose transport mode:
   - [ ] Loopback only (`server.listen: "127.0.0.1:..."`, the default), or
   - [ ] Native HTTPS (`"https_listener": {"enabled": true}`), or
   - [ ] TLS reverse proxy in front of a loopback bind

2. Generate password hash: `phoenix-server --hash-password`

3. Add config:
   ```json
   { "dashboard": { "enabled": true, "password_hash": "$2a$10$..." } }
   ```

4. Protect config file: `chmod 600 /data/phoenix/config.json`

5. Restart server, verify log line: `Dashboard: enabled at /dashboard/`

6. Open browser, verify login page loads at `/dashboard/login`

7. Login, verify all pages render (overview, secrets, approvals, grants, sessions, audit, roles), and
   open a secret and press Show

8. Test approval flow end-to-end if access requests are on:
   - Have an agent ask (`phoenix request <path> --reason "test"`)
   - Approve from the dashboard
   - Verify the grant appears on the Grants page
   - Verify audit entries for the approval

9. Verify audit trail shows `dashboard@<your-ip>` entries

10. From a different machine, verify the dashboard is **not** reachable
    over plain HTTP (unless you explicitly chose loopback-only)

## Related docs

- [Configuration](configuration.md) — config field reference
- [Access Requests](access-requests.md) — the approval workflow
- [Authentication](authentication.md) — API auth model (separate from dashboard)
- [Threat Model](threat-model.md) — dashboard attack surface
- [LAN Deployment](lan-deployment.md) — multi-host setup
