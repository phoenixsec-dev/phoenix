# Phoenix — Session Identity

Session identity replaces static bearer tokens with short-lived, scoped session
tokens for agent access. Agents authenticate once (bootstrap), receive a session
token bound to a named role, and use that token for all subsequent requests.

## Concepts

**Roles** define what an agent session can do. Each role specifies:
- Which namespaces the session can access
- Which actions are allowed (list, read, write, delete, admin)
- How the agent must authenticate to mint a session (bootstrap trust)

**Sessions** are server-issued credentials with a fixed lifetime (default 1h).
They carry the role's scope and are bound to the minting agent's identity.
Sessions can be explicitly revoked, and auto-renew if the role's checks
still hold. A session never reads past the minting agent's own ACL; for
temporary extra access, use [access requests](access-requests.md).

**Bootstrap trust** determines which authentication methods can mint sessions
for a given role. Options: `bearer` and `local` (loopback callers).

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
        "bootstrap_trust": ["bearer"],
        "require_seal_key": true,
        "max_ttl": "15m"
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
| `bootstrap_trust` | `[]string` | Required. Auth methods that can mint this role: `bearer`, `local`. `["local"]` alone means loopback callers only (checked at mint and renewal) |
| `require_seal_key` | `bool` | Require seal public key at mint time, so every response is sealed |
| `max_ttl` | `string` | Per-role TTL override (e.g. `"30m"`) |

The role fields `step_up`, `step_up_ttl`, `elevates_acl` and `allowed_agents`
were removed along with step-up approval; a config that still has one stops
at startup with a line naming it. Temporary human-approved access is now
done with [access requests](access-requests.md). Bootstrap methods `mtls` and
`token` were removed too, and so was the role `attestation` list (use
`bootstrap_trust: ["local"]` or `require_seal_key: true`).

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

The server checks role existence, bootstrap trust and the seal key.
Returns a session token (`phxs_...` prefix) with role scope and expiry.

### Renewal

Sessions auto-renew when nearing expiry. On renewal, the server rechecks
bootstrap trust. If anything changed (role config updated),
renewal fails and the agent must re-mint.

### Revocation

```bash
phoenix sessions revoke ses_abc123def456
```

Takes effect immediately. The revoked token is rejected on the next request.

### Expiry

Sessions expire after their TTL. Expired tokens receive a structured
`SESSION_EXPIRED` denial with a hint to re-mint.

## CLI commands

```bash
# List active sessions (admin sees all, agents see own)
phoenix sessions list
phoenix sessions list --role dev --agent deployer

# Show session details
phoenix sessions info ses_abc123def456

# Revoke a session
phoenix sessions revoke ses_abc123def456
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
}
```

Auto-renewal happens transparently when the session is within 5 minutes of
expiry.

## MCP integration

Set `PHOENIX_ROLE` in your MCP server config:

```json
{
  "mcpServers": {
    "phoenix": {
      "command": "phoenix",
      "args": ["mcp-server"],
      "env": {
        "PHOENIX_SERVER": "https://phoenix:9443",
        "PHOENIX_CA_CERT": "/etc/phoenix/certs/ca.crt",
        "PHOENIX_TOKEN": "bootstrap-token",
        "PHOENIX_ROLE": "dev"
      }
    }
  }
}
```

The MCP server auto-mints a session on startup and renews it in the
background.

Available MCP tools:
- `phoenix_session_list` — list active sessions
- `phoenix_session_revoke` — revoke a session by ID

Data tool denials (`phoenix_get`, `phoenix_resolve`, `phoenix_list`) show the
code and next step.

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
| `BOOTSTRAP_FAILED` | Auth method not in role's bootstrap_trust |
| `ROLE_NOT_FOUND` | Requested role does not exist |
| `SEAL_KEY_REQUIRED` | Role requires a seal key but none was provided |
| `SEAL_KEY_MISMATCH` | Seal key doesn't match session binding |

## Audit events

All session lifecycle events are logged to the audit trail:

| Action | Status | When |
|--------|--------|------|
| `session.mint.approved` | allowed | Session minted successfully |
| `session.mint` | denied | Mint failed (role_not_found, bootstrap_failed) |
| `session.renewed` | allowed | Session renewed |
| `session.renew` | denied | Renewal failed (for example bootstrap_failed) |
| `session.revoke` | allowed | Session revoked |
| `session.auth` | denied | Expired or revoked token used for a request |
| `session.list` | allowed | Sessions listed |
| `session.info` | allowed | Session details viewed |

## Access control

- **Session tokens** can only inspect/revoke their own exact session
- **Bearer callers** can see/revoke sessions belonging to their agent
- **Admins** (ACL `admin` on `sessions`) can see/revoke all sessions

Session tokens never escalate to admin-level session management, even if
the underlying agent has admin ACL permissions.

### Role scope vs ACL

Session scope and the base agent ACL are both enforced on every request: a
role narrows what an agent can do, it never widens it. Policy, attestation,
and seal-key requirements also apply.

## Operational notes

### In-memory state

Active sessions are held in server memory. A server restart clears all
sessions. Agents with `PHOENIX_ROLE` set will auto-mint a new session on
their next request, so this is transparent for most workflows.

This is a deliberate design choice — it avoids persisting bearer-equivalent
tokens to disk and keeps the server stateless for simple deployments.
Persistent session storage may be added in a future release if demand
warrants it.

## Related docs

- [Authentication](authentication.md)
- [Configuration](configuration.md)
- [Dashboard](dashboard.md) — browser-based session management
- [CLI Usage](cli-usage.md)
- [API Reference](api-reference-index.md)
