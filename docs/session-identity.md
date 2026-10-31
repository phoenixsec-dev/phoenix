# Phoenix — Session Identity

Session identity replaces static bearer tokens with short-lived, scoped session
tokens for agent access. Agents authenticate once (bootstrap), receive a session
token bound to a named role, and use that token for all subsequent requests.

## Concepts

**Roles** define what an agent session can do. Each role specifies:
- Which namespaces the session can access
- Which actions are allowed (list, read, write, delete, admin)
- How the agent must authenticate to mint a session (bootstrap trust)
- Whether human approval is required before the session is granted

**Sessions** are server-issued credentials with a fixed lifetime (default 1h).
They carry the role's scope and are bound to the minting agent's identity.
Sessions can be explicitly revoked. Non-elevated sessions auto-renew if
attestation still holds. Elevated step-up sessions require fresh approval
instead of transparent renewal.

**Bootstrap trust** determines which authentication methods can mint sessions
for a given role. Options: `bearer`, `mtls`, `local` (loopback), `token`
(short-lived attestation token).

## Configuration

Enable sessions in your server config:

```json
{
  "session": {
    "enabled": true,
    "ttl": "1h",
    "roles": {
      "dev": {
        "namespaces": ["dev/**", "staging/**"],
        "actions": ["list", "read_value"],
        "bootstrap_trust": ["bearer"]
      },
      "deploy": {
        "namespaces": ["prod/**"],
        "actions": ["list", "read_value"],
        "bootstrap_trust": ["mtls", "bearer"],
        "require_seal_key": true,
        "step_up": true,
        "step_up_ttl": "15m",
        "elevates_acl": true,
        "allowed_agents": ["deployer"]
      }
    }
  }
}
```

### Role fields

| Field | Type | Description |
|-------|------|-------------|
| `namespaces` | `[]string` | Required. Glob patterns for accessible paths (`dev/*`, `prod/**`) |
| `actions` | `[]string` | Allowed actions. Default: `["list", "read_value"]`. Options: `list`, `read_value`, `write`, `delete`, `admin` |
| `bootstrap_trust` | `[]string` | Required. Auth methods that can mint this role: `bearer`, `mtls`, `local`, `token` |
| `require_seal_key` | `bool` | Require seal public key at mint time |
| `max_ttl` | `string` | Per-role TTL override (e.g. `"30m"`) |
| `attestation` | `[]string` | Attestation requirements (e.g. `["source_ip", "cert_fingerprint"]`) |
| `step_up` | `bool` | Require human approval before minting |
| `step_up_ttl` | `string` | How long a step-up request waits for a human before it expires (e.g. `"15m"`) |
| `elevates_acl` | `bool` | For approved `step_up` sessions, allow temporary access within role scope even when the base agent ACL would normally deny it |
| `allowed_agents` | `[]string` | ACL agent names that may use this role. Empty = any agent whose auth method is in `bootstrap_trust` (see below) |

### Binding a role to agents (`allowed_agents`)

Without `allowed_agents`, a role only checks *how* the caller logged in
(`bootstrap_trust`), not *who* it is. Any agent with a bearer token could ask
for a `bearer` role. For an `elevates_acl` role that matters: once a human
approves, that agent reads beyond its own ACL.

`allowed_agents` closes that gap. It is checked three times:

1. **Mint.** An agent not on the list gets `403 ROLE_NOT_ALLOWED` at once. For
   a step-up role no approval is created, so nothing reaches a human.
2. **Approval.** `phoenix approve apr_...`, `POST /v1/approval/{id}/approve`
   and the dashboard Approve button all re-check the list. An agent removed
   while its request was pending cannot be approved.
3. **Renewal.** An existing session whose agent is no longer on the list
   cannot renew.

It is not checked on each read. A session minted before you changed the list
keeps working until it expires; revoke it (`phoenix sessions revoke`) if it
must stop now.

The denial names the role, never the list. `next_step` is `ask_user`.

An empty list keeps the old behaviour. At startup the server logs a
`WARNING` for every `step_up` role with no `allowed_agents` (stronger wording
for `elevates_acl` roles), and for any listed name that is not an agent in
the ACL. The dashboard approval card shows a **role has no agent binding**
badge for such roles.

**Next release:** `allowed_agents` becomes required for `elevates_acl` roles.
A config without it will fail to load with a message that says how to fix it.
This release only warns. Bind those roles now (for example
`openclaw-elevated`). A warning alone does not close the gap.

## Agent bootstrap

Set `PHOENIX_ROLE` to automatically mint a session on first request:

```bash
export PHOENIX_TOKEN="bootstrap-token"
export PHOENIX_ROLE="dev"
phoenix get dev/api-key  # auto-mints session, then reads secret
```

The bootstrap token is used once for minting. All subsequent requests use
the scoped session token. The CLI caches the session token locally and
auto-renews before expiry for non-elevated sessions. Elevated step-up
sessions must be re-minted and re-approved when they expire.

## Session lifecycle

### Minting

```
POST /v1/session/mint  {"role": "dev"}
```

The server checks role existence, `allowed_agents`, bootstrap trust,
attestation and the seal key.
Returns a session token (`phxs_...` prefix) with role scope and expiry.

### Renewal

Non-elevated sessions auto-renew when nearing expiry. On renewal, the
server rechecks `allowed_agents`, bootstrap trust and attestation. If anything changed
(cert expired, role config updated), renewal fails and the agent must
re-mint. Elevated step-up sessions do **not** auto-renew; they require a
fresh step-up request and approval to extend access.

### Revocation

```bash
phoenix sessions revoke ses_abc123def456
```

Takes effect immediately. The revoked token is rejected on the next request.

### Expiry

Sessions expire after their TTL. Expired tokens receive a structured
`SESSION_EXPIRED` denial with a hint to re-mint.

## Step-up approval

Roles with `step_up: true` require human approval before the session is granted.

```bash
# Agent's request returns approval_required:
#   "Run: phoenix approve apr_xyz789"

# Human approves from another terminal:
phoenix approve apr_xyz789
```

The approval request includes role, agent identity, and expiry. The human
sees full context before approving. Approvals expire if not acted on.
When `elevates_acl: true` is set on that step-up role, the approved session
temporarily uses the role's namespaces/actions as the access grant for the
session lifetime instead of treating the base agent ACL as a hard ceiling.
Path policy, attestation, and seal-key checks still apply after approval.

### Dashboard approval

When the dashboard is enabled, approvals can also be managed from the browser
at `/dashboard/approvals`. Each pending approval is shown as a card with full
context (role, agent, source IP, bootstrap method, namespaces, TTY, expiry
countdown). Approve or deny with one click. The same safety checks apply —
role config, `allowed_agents`, bootstrap trust, attestation, and seal key are
all re-verified at approve time. A role with no `allowed_agents` shows a
**role has no agent binding** badge on its card.

## CLI commands

```bash
# List active sessions (admin sees all, agents see own)
phoenix sessions list
phoenix sessions list --role dev --agent deployer

# Show session details
phoenix sessions info ses_abc123def456

# Revoke a session
phoenix sessions revoke ses_abc123def456

# Approve a step-up request
phoenix approve apr_xyz789
```

## SDK usage

```go
// Create a client with automatic session minting
client, err := phoenix.NewWithRole(server, token, "dev")

// Or mint manually
client := phoenix.New(server, token)
err := client.MintSession("dev")

// Session operations
sessions, _ := client.ListSessions()
client.RevokeSession("ses_abc123")

// Error classification
var perr *phoenix.Error
if errors.As(err, &perr) {
    if perr.IsSessionExpired()    { /* re-mint */ }
    if perr.IsSessionRevoked()    { /* session was killed */ }
    if perr.IsScopeExceeded()     { /* wrong role for this path */ }
    if perr.IsApprovalRequired()  { /* needs human approval */ }
}
```

Auto-renewal happens transparently when the session is within 5 minutes of
expiry for non-elevated sessions. Elevated step-up sessions return
`STEP_UP_REAPPROVAL_REQUIRED` and must be re-approved.

## MCP integration

Set `PHOENIX_ROLE` in your MCP server config:

```json
{
  "mcpServers": {
    "phoenix": {
      "command": "phoenix",
      "args": ["mcp-server"],
      "env": {
        "PHOENIX_SERVER": "https://phoenix:9090",
        "PHOENIX_CA_CERT": "/etc/phoenix/certs/ca.crt",
        "PHOENIX_TOKEN": "bootstrap-token",
        "PHOENIX_ROLE": "dev"
      }
    }
  }
}
```

The MCP server auto-mints a session on startup and renews in the
background for non-elevated sessions. Elevated step-up sessions require a
fresh approval flow when they expire.

Available MCP tools:
- `phoenix_session_list` — list active sessions
- `phoenix_session_revoke` — revoke a session by ID

Step-up approval happens while the MCP server mints its session: the
`phoenix approve apr_...` command (built locally from the approval ID) is
printed to stderr while it waits. Data tools (`phoenix_get`, `phoenix_resolve`,
`phoenix_list`) never get a 202; their denials show the code and next step.

The request-use tools (`phoenix_request_use`, `phoenix_request_status`,
`phoenix_whoami`) are listed too, but requests are refused for session tokens
(`SESSION_CANNOT_REQUEST`): run an MCP server on the agent's own bootstrap
identity for them. See [Access requests](access-requests.md).

## Denial codes

When a session request or scoped access is denied, the response includes a
machine-readable code and a `next_step` (see [denial-codes.md](denial-codes.md)
for the full list and client rules):

| Code | Meaning |
|------|---------|
| `SESSION_EXPIRED` | Session TTL elapsed, re-mint needed |
| `SESSION_REVOKED` | Session was explicitly revoked |
| `SESSION_INVALID` | Token is malformed or signature invalid |
| `SCOPE_EXCEEDED` | Path is outside the role's namespace scope |
| `ACTION_DENIED` | Action not permitted by the role |
| `APPROVAL_REQUIRED` | Step-up approval needed |
| `STEP_UP_REAPPROVAL_REQUIRED` | Elevated step-up session cannot renew without fresh approval |
| `BOOTSTRAP_FAILED` | Auth method not in role's bootstrap_trust |
| `ROLE_NOT_FOUND` | Requested role does not exist |
| `ROLE_NOT_ALLOWED` | The role's `allowed_agents` does not list this agent |
| `ATTESTATION_FAILED` | Missing or insufficient attestation |
| `SEAL_KEY_REQUIRED` | Role requires a seal key but none was provided |
| `SEAL_KEY_MISMATCH` | Seal key doesn't match session binding |

## Audit events

All session lifecycle events are logged to the audit trail:

| Action | Status | When |
|--------|--------|------|
| `session.mint.approved` | allowed | Session minted successfully |
| `session.mint` | denied | Mint failed (role_not_found, role_not_allowed, bootstrap_failed, attestation_failed) |
| `session.renewed` | allowed | Session renewed |
| `session.renew` | denied | Renewal failed (for example role_not_allowed) |
| `session.revoke` | allowed | Session revoked |
| `session.auth` | denied | Expired or revoked token used for a request |
| `session.list` | allowed | Sessions listed |
| `session.info` | allowed | Session details viewed |
| `approval.created` | allowed | Step-up approval request created |
| `approval.approved` | allowed | Approval granted, session minted |
| `approval.denied` | allowed | Approval explicitly denied |
| `approval.approve` | denied | Approval re-check failed at approve time |

## Access control

- **Session tokens** can only inspect/revoke their own exact session
- **Bearer/mTLS callers** can see/revoke sessions belonging to their agent
- **Admins** (ACL `admin` on `sessions`) can see/revoke all sessions

Session tokens never escalate to admin-level session management, even if
the underlying agent has admin ACL permissions.

### Role scope vs ACL

Session scope is always enforced on every request. By default, the base
agent ACL is also enforced. For approved step-up roles with
`elevates_acl: true`, the session can temporarily access paths/actions
inside the approved role scope even if the base agent ACL would normally
deny them. Policy, attestation, and seal-key requirements still apply.

## Operational notes

### In-memory state

Active sessions and pending approvals are held in server memory. A server
restart clears all sessions and pending approvals. Agents with `PHOENIX_ROLE`
set will auto-mint a new session on their next request, so this is
transparent for most workflows. Step-up approvals that were pending at
restart time must be re-initiated.

This is a deliberate design choice — it avoids persisting bearer-equivalent
tokens to disk and keeps the server stateless for simple deployments.
Persistent session storage may be added in a future release if demand
warrants it.

## Related docs

- [Authentication](authentication.md)
- [Configuration](configuration.md)
- [Dashboard](dashboard.md) — browser-based approval and session management
- [CLI Usage](cli-usage.md)
- [API Reference](api-reference-index.md)
