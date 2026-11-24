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
They carry the role's scope and are bound to the agent and to the bearer token
it minted them with (see [Ended with the agent's token](#ended-with-the-agents-token)).
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

Only the agent's bearer token can mint, also from loopback: a session token gets
`403 BOOTSTRAP_FAILED`.
The server checks role existence, bootstrap trust and the seal key.
Returns a session token (`phxs_...` prefix) with role scope and expiry.

### Renewal

Sessions auto-renew when nearing expiry. On renewal, the server rechecks
bootstrap trust and the agent's token. If anything changed (role config
updated, agent deleted, token replaced), renewal fails and the agent must
re-mint.

### Revocation

```bash
phoenix sessions revoke ses_abc123def456
```

Takes effect immediately. The revoked token is rejected on the next request.

### Ended with the agent's token

A session works only while the bearer token it was minted with is still its
agent's token. Every use, renewal included, checks this.

- **Deleting an agent or replacing its token** (`phoenix agent delete`,
  `phoenix agent create --force` with a different token) ends the old token's
  sessions at once. They stay ended after a restart, and also if the agent is
  later created again, even with the same token. Each one is audited as
  `session.ended`.
- `--force` with the **same** token only changes permissions, so sessions carry
  on (permissions are checked on every request anyway).
- A token changed by editing the ACL file takes effect at the next start; the
  old token's sessions end then (the log says how many).
- A start with `session.enabled` false ends the saved sessions, since nothing
  would end them when a token changes meanwhile.

An ended session gets `401 SESSION_INVALID`. The CLI and `phoenix mcp-server`
mint a new one by themselves once `PHOENIX_TOKEN` holds the new token; a
running MCP server has to be restarted to see it, like any environment change.
A `phxs_` token used directly in `PHOENIX_TOKEN` cannot recover on its own:
mint a new one.

If the server answers 500 "could not be saved" to the delete or replace, the
change is done and the sessions are dead, but the disk needs looking at. The
server tries to save again every minute. Until that works, going back to the
token whose sessions were ended is refused (500 "agent not changed"), because a
restart could revive them; any other token is accepted.

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
| `SESSION_INVALID` | Token is malformed, its signature is invalid, or the session ended because its agent was deleted or the agent's token was replaced |
| `SCOPE_EXCEEDED` | Path is outside the role's namespace scope |
| `ACTION_DENIED` | Action not permitted by the role |
| `BOOTSTRAP_FAILED` | Auth method not in role's bootstrap_trust, or minting with a session token |
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
| `session.ended` | allowed | Phoenix ended a session because of its agent's token. The agent field is who caused it (`system` at start or on use); metadata has `session.agent` and `cause`: `agent_deleted`, `token_replaced`, `credential_not_current` or `sessions_disabled` |
| `session.auth` | denied | Expired, revoked or ended session used for a request |
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

### Restarts

Sessions survive a server restart:

- The signing key is derived from the master key (HKDF-SHA256 with a fixed
  label), so it is the same after a restart. There is no extra key file.
- Session records are saved to `role-sessions.json` in the same directory as
  the ACL file, on every mint, renew, revoke and cleanup (mode 0600). The file
  holds who, which role, scope, expiry and a fingerprint of the agent's token
  (a hash of its stored hash, as in `grants.json`), never a token or key, so a
  copy of it cannot be used to log in. Deleting it ends every session; clients mint
  new ones.
- Revoked sessions stay in the file until they expire, so a revoked token keeps
  getting `SESSION_REVOKED` after a restart.
- A role change still takes effect at restart. The file keeps a hash of each
  role's settings; sessions of a role that was removed or changed in any way
  are dropped at start (the log says how many), and clients mint new ones under
  the new settings. Sessions of unchanged roles carry on.
- Sessions saved by v0.23.0 carry no token fingerprint. They end at the first
  start on a newer version (the log says how many); clients mint new ones.
- The path is reserved. The server refuses to start if another Phoenix file
  (secrets, master key, audit log, grants file) is configured there, or if a
  file at that path is not a sessions file; it never moves or overwrites it.
  A damaged sessions file can simply be deleted.

Sessions still end when the signing key changes: after `phoenix rotate-master`
(at the next restart) and at every restart with the 1Password backend, which
has no master key (the server logs a warning at start).

The CLI and `phoenix mcp-server` recover from that on their own. When a role
session gets `SESSION_INVALID` or `SESSION_EXPIRED`, they drop it from
`~/.phoenix/token-cache.json`, mint a new one with `PHOENIX_TOKEN` and retry
the request once. A second failure is reported, never retried. A
`SESSION_REVOKED` session is not replaced in the same run, but it is dropped
from the cache so the next run mints a new one.

## Related docs

- [Authentication](authentication.md)
- [Configuration](configuration.md)
- [Dashboard](dashboard.md) — browser-based session management
- [CLI Usage](cli-usage.md)
- [API Reference](api-reference-index.md)
