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
Sessions auto-renew if attestation still holds and can be explicitly revoked.

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
        "namespaces": ["dev/*", "staging/*"],
        "actions": ["list", "read_value"],
        "bootstrap_trust": ["bearer"]
      },
      "deploy": {
        "namespaces": ["prod/*"],
        "actions": ["list", "read_value"],
        "bootstrap_trust": ["mtls", "bearer"],
        "require_seal_key": true,
        "step_up": true,
        "step_up_ttl": "15m"
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
| `step_up_ttl` | `string` | TTL for step-up sessions (e.g. `"15m"`) |

## Agent bootstrap

Set `PHOENIX_ROLE` to automatically mint a session on first request:

```bash
export PHOENIX_TOKEN="bootstrap-token"
export PHOENIX_ROLE="dev"
phoenix get dev/api-key  # auto-mints session, then reads secret
```

The bootstrap token is used once for minting. All subsequent requests use
the scoped session token. The CLI caches the session token locally and
auto-renews before expiry.

## Session lifecycle

### Minting

```
POST /v1/session/mint  {"role": "dev"}
```

The server checks bootstrap trust, attestation, and role existence.
Returns a session token (`phxs_...` prefix) with role scope and expiry.

### Renewal

Sessions auto-renew when nearing expiry. On renewal, the server rechecks
bootstrap trust and attestation. If anything changed (cert expired, role
config updated), renewal fails and the agent must re-mint.

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

### Dashboard approval

When the dashboard is enabled, approvals can also be managed from the browser
at `/dashboard/approvals`. Each pending approval is shown as a card with full
context (role, agent, source IP, bootstrap method, namespaces, TTY, expiry
countdown). Approve or deny with one click. The same safety checks apply —
role config, bootstrap trust, attestation, and seal key are all re-verified
at approve time.

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

Auto-renewal happens transparently when the session is within 5 minutes of expiry.

## MCP integration

Set `PHOENIX_ROLE` in your MCP server config:

```json
{
  "mcpServers": {
    "phoenix": {
      "command": "phoenix",
      "args": ["mcp-server"],
      "env": {
        "PHOENIX_SERVER": "https://phoenix.home:9090",
        "PHOENIX_TOKEN": "bootstrap-token",
        "PHOENIX_ROLE": "dev"
      }
    }
  }
}
```

The MCP server auto-mints a session on startup and renews in the background.

Available MCP tools:
- `phoenix_session_list` — list active sessions
- `phoenix_session_revoke` — revoke a session by ID

When an MCP tool hits `APPROVAL_REQUIRED`, it returns a message the agent
can present to the human with the approve command.

## Denial codes

When a session request or scoped access is denied, the response includes a
machine-readable code:

| Code | Meaning |
|------|---------|
| `SESSION_EXPIRED` | Session TTL elapsed, re-mint needed |
| `SESSION_REVOKED` | Session was explicitly revoked |
| `SESSION_INVALID` | Token is malformed or signature invalid |
| `SCOPE_EXCEEDED` | Path is outside the role's namespace scope |
| `ACTION_DENIED` | Action not permitted by the role |
| `APPROVAL_REQUIRED` | Step-up approval needed |
| `BOOTSTRAP_FAILED` | Auth method not in role's bootstrap_trust |
| `ROLE_NOT_FOUND` | Requested role does not exist |
| `ATTESTATION_FAILED` | Missing or insufficient attestation |
| `SEAL_KEY_REQUIRED` | Role requires a seal key but none was provided |
| `SEAL_KEY_MISMATCH` | Seal key doesn't match session binding |

## Audit events

All session lifecycle events are logged to the audit trail:

| Action | Status | When |
|--------|--------|------|
| `session.mint.approved` | allowed | Session minted successfully |
| `session.mint` | denied | Mint failed (role_not_found, bootstrap_failed, attestation_failed) |
| `session.renewed` | allowed | Session renewed |
| `session.renew` | denied | Renewal failed |
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

## Related docs

- [Authentication](authentication.md)
- [Configuration](configuration.md)
- [Dashboard](dashboard.md) — browser-based approval and session management
- [CLI Usage](cli-usage.md)
- [API Reference](api-reference-index.md)
