# Access Requests (request-use grants)

An agent gets told "no" for a secret. Instead of a human editing the ACL, the
agent asks Phoenix for temporary use of **that exact secret**. A human approves
or denies. An approval becomes a **grant**: this agent, with this credential,
from this IP, may read this path until a clock runs out. A human can revoke it
at any time. Every step is in the audit log.

A grant holds no secret and no token. The agent keeps using its own identity
(bearer token, mTLS certificate or short-lived token). **Session tokens
(`phxs_`) can never request or use a grant.** No session roles are needed.

Humans decide on the dashboard (`/dashboard/approvals`) or, for identities
listed in `approvers`, with `phoenix approve req_...`. Agents ask with
`phoenix request` (or the MCP tool `phoenix_request_use`) and use a grant with
`phoenix exec --redact-output`.

## The flow in one screen

```bash
# Agent: told ACL_DENIED with "next: ... phoenix request infra/b2/app-key ..."
phoenix request infra/b2/app-key --reason "nightly backup fails auth" --ttl 30m --wait

# Human: dashboard -> Approvals -> "Secret access requests" card -> Approve
#   (or, as an approver identity:  phoenix approve req_... --ttl 15m)

# Agent: use it. The value goes into the child's env, never into the output.
phoenix exec --redact-output --env B2_KEY=phoenix://infra/b2/app-key -- ./backup.sh

# Human: take it back early (dashboard -> Grants -> Revoke, or)
phoenix grants revoke gnt_...
```

## Turning it on

New installs (`phoenix-server --init`, `config.example.json`) have it on.
Upgraded installs have no `access_requests` block, which means **off**.

1. Add the block below to the server config (all defaults shown).
2. Make sure someone can approve: enable the dashboard, or list an agent in
   `approvers`. The server warns at startup if nobody can.
3. Give each agent that will ask a registered seal key (an admin runs
   `phoenix keypair generate <agent>`; the agent sets `PHOENIX_SEAL_KEY` to
   the private key file). With `require_sealed` on, agents without one are
   refused with `SEAL_KEY_NOT_REGISTERED`.
4. Restart the server. Settings are read at startup.

Check it with `phoenix whoami` as the agent: the `Requests:` line shows
`enabled=true` and whether the seal key is registered.

## Configuration

```json
"access_requests": {
  "enabled": true,
  "request_ttl": "15m",
  "default_grant_ttl": "1h",
  "max_grant_ttl": "8h",
  "grantable_actions": ["read_value"],
  "require_sealed": true,
  "bind_source_ip": true,
  "approvers": [],
  "deny_paths": [],
  "notify_url": "",
  "notify_token_ref": "",
  "notify_include_paths": false,
  "notify_dashboard_url": "",
  "store_path": ""
}
```

| Key | Meaning |
|---|---|
| `enabled` | Off when the whole block is missing (every upgraded install). `phoenix-server --init` and `config.example.json` turn it on. |
| `request_ttl` | How long a request waits for a decision (min `1m`). |
| `default_grant_ttl` / `max_grant_ttl` | Grant length when the agent does not ask / the ceiling. `1m <= default <= max <= 24h`. |
| `grantable_actions` | Must be `["read_value"]`. `write` is a startup error ("write grants are not supported yet"); `list`, `delete`, `admin` are never grantable. |
| `require_sealed` | Granted values are served only sealed to the agent's **registered** seal key. Agents without one get `SEAL_KEY_NOT_REGISTERED` when they ask. |
| `bind_source_ip` | The grant only works from the IP that made the request. |
| `approvers` | ACL agent names allowed to approve over the API. Empty = dashboard only. ACL `admin` alone is **not** enough, and nobody can approve their own request. The name must also still be in the ACL: a deleted approver's leftover short-lived token or certificate approves nothing. Unknown names only warn at startup. |
| `deny_paths` | Globs (`phoenix/**`, `infra/*`, exact paths) that can never be requested. |
| `notify_url` | Where to POST a short message for each new request, e.g. an ntfy topic URL. Empty = no notifications. Must be `http://` or `https://`, with no `user:password@`, query or fragment. See [Notifications](#notifications). |
| `notify_token_ref` | A `phoenix://` reference to a token in this Phoenix store. Read at send time and sent as `Authorization: Bearer <token>`. Never write the token itself into the config. |
| `notify_include_paths` | `true` adds the requested paths to the message. Off by default. |
| `notify_dashboard_url` | The address you use to open the dashboard, e.g. `https://phoenix.example.net`. Used only to build the link in the message. Empty = no link. |
| `store_path` | Where grants live. Empty = `grants.json` next to the ACL file (mode `0600`). This path is checked at every start, even without an `access_requests` block: if it (or its temp files) is the same file as the ACL, audit log, secrets data file, master key, policy or CRL file, resolved through relative paths and symlinks, the server refuses to start and touches nothing. The grants file itself must not be a symlink. Set `store_path` to a separate regular file to fix either problem. |

Turning it off (`enabled: false`) stops new requests (`501 REQUESTS_DISABLED`)
**and** all grant-backed access. Records stay on disk; listing and revoking
still work. Turning it back on resumes only grants that have not expired or
been revoked.

## Agent flow

1. The agent reads a secret and is denied: `403 ACL_DENIED` with
   `next_step: request_use`. `request_use` is only offered when the feature is
   on, the action is `read_value` and the path is not in `deny_paths`.
   Otherwise the next step is `ask_user`.
2. It asks, with its own identity (not `PHOENIX_ROLE`):
   `phoenix request <path>... --reason "..." [--ttl 30m] [--wait]`.
   Up to 10 exact paths: no wildcards (`* ? [ ] { }`), no control characters,
   and no invisible formatting characters (bidi marks, zero-width spaces, soft
   hyphens), so every path looks exactly like what it is when a human approves
   it. The answer is a `req_...` id.
3. It tells the user in chat what it asked for and why.
4. It waits. `--wait` polls every 5 seconds;
   `phoenix request status req_...` checks once. Each status has a
   `next_step`: `wait` (pending), `use_exec` (approved), `ask_user`
   (denied, expired or revoked) or `request_use` (grant ended by time).
5. Approved: it uses the secret through `phoenix exec --redact-output`
   (see [Using a grant](#using-a-grant)).

The agent's CLI commands:

| Command | Does |
|---|---|
| `phoenix request <path>... --reason "..." [--ttl 30m] [--wait]` | File a request. `--wait` polls every 5s and exits non-zero on deny/expiry |
| `phoenix request status <req_id>` | State plus the exact next command |
| `phoenix whoami` | Identity, ACL rules, active grants, pending requests |
| `phoenix grants` | Your grants |
| `phoenix grants revoke <gnt_id>` | Give up your own grant early |

All of these use the agent's **own** identity (`PHOENIX_TOKEN` bootstrap
token or mTLS cert). `PHOENIX_ROLE` is ignored and a `phxs_` session token is
refused before anything is sent. The exception is `phoenix whoami`, which uses
whatever credential you have (session included) so it can show what that
credential can do.

When a read is denied with `next_step: request_use`, the CLI and MCP print
the concrete command, e.g.
`next: request temporary use from a human: phoenix request infra/b2/app-key --reason "why you need it"`.
The path is only pasted in when it is plain path characters
(`A-Z a-z 0-9 . _ / -`); otherwise the hint says `<path>`.

MCP (`phoenix mcp-server`) has `phoenix_request_use`, `phoenix_request_status`
and `phoenix_whoami`. None of them returns a secret value.

## Approving

### In the dashboard

`/dashboard/approvals` shows a **Secret access requests** section above the
step-up table. Each pending request is one card (anchor `#req_...`, so a
notification link can jump straight to it) showing:

- agent, source IP and auth method (bearer / mtls / token)
- every path in full, monospace, each with badges: **does not exist**,
  **hidden from this agent** (its ACL has no `list` there), **already allowed**
- action, requested TTL, delivery mode (sealed only, or plaintext allowed),
  and a red line if sealing is required but the agent has no seal key
- the path's hard attestation requirements and whether the requesting
  credential met them (`met`, `not met`, or `checked at each use`). Approval
  never waives them.
- the reason, in a box labelled **Agent says (not verified)**: escaped,
  control/bidi/zero-width characters stripped, capped at 300 characters,
  never turned into a link
- this agent's other requests in the last 24 hours and how many were denied
- "Revoking later does not recall a value already used."

To approve, untick any paths you do not want (all start ticked) and pick a
TTL. The dropdown only offers legal choices: 5m, 15m, 1h and the requested
TTL, keeping those >= 1m and <= the request (capped at the current
`max_grant_ttl`). Anything else posted is refused. There is no bulk approve.
Deny takes an optional note that the agent sees.

Dashboard approvals run the **same re-checks as the API** (current config,
`deny_paths`, `require_sealed`, agent still exists, active-grant cap) and are
recorded as `dashboard@<ip>`. The dashboard login is the approver here: the
`approvers` list only controls API/CLI identities.

The Overview page shows the pending request count (also in the nav badge)
and a red banner when the grants file or grant audit events are degraded.

Error banners on these pages come from a fixed list keyed by code; text in
the URL is never shown in red, so a crafted link cannot fake a warning.

### From the CLI

Only identities listed in `approvers` (not sessions):

| Command | Does |
|---|---|
| `phoenix pending` | Step-up approvals and access requests, with every path |
| `phoenix approve <req_id> [--ttl 15m] [--path p ...] [--yes]` | Shows every path (`+` kept, `-` removed by `--path`), action, TTL and the unverified reason, then asks y/N |
| `phoenix deny <req_id> [--note "..."]` | Deny; starts the 10-minute cooldown |
| `phoenix grants [--all] [--agent name]` | List grants |
| `phoenix grants revoke <gnt_id>` | Revoke now |

`phoenix approve` and `phoenix deny` look at the ID: `apr_...` is the
existing step-up flow (unchanged), `req_...` is an access request. The y/N
answer is read from `/dev/tty`, or stdin when there is no terminal (same as
the step-up approve); `--yes` skips the prompt for scripts.

Approval re-checks the **current** config: feature on, action grantable, no
path in `deny_paths`, TTL clamped to `max_grant_ttl`, `require_sealed` and
`bind_source_ip`, the agent still exists, at most 10 active grants.

## Using a grant

`phoenix exec --redact-output --env NAME=phoenix://<path> -- <command>` with
the agent's own `PHOENIX_TOKEN` (or cert) and `PHOENIX_SEAL_KEY`, from the
same IP that asked. Exec resolves sealed, decrypts in its own process, and
gives the child the value but no Phoenix credentials. A plain `GET` or
`resolve` without the registered seal key gets `SEALED_REQUIRED` while
`require_sealed` is on. Do not set `PHOENIX_ROLE` for this: sessions never
use grants.

### `--redact-output`

Without it, exec replaces itself with the command. With it, exec stays as the
parent, pipes the command's stdout and stderr, and replaces every resolved
value with `[REDACTED:<NAME>]` before passing the output on. The exit code is
passed through (128 + signal number if the command was killed). SIGTERM and
SIGHUP sent to exec go to the command; Ctrl-C reaches it from the terminal.

- It catches **accidents**: a script echoing its token, `curl -v` printing the
  `Authorization` header into an agent's transcript.
- It does **not** stop a hostile command: base64, splitting the value, writing
  it to a file or the network all get past it.
- A value split across two output chunks is still caught (the possible start
  of a value is held back until the next chunk). A value split between stdout
  and stderr is not.
- Values shorter than 4 bytes are not redacted (they would garble normal
  output); exec prints a warning naming the variable.
- Output that ends in the first few bytes of a secret is held until more
  output arrives or the command exits.
- It cannot be combined with `--output-env`.

What a grant never does:

- It is never consulted for session tokens, for `list`, `write` or `delete`.
- It never waives the path's attestation policy (mTLS, IP, nonce, ...).
- It never makes `GET /v1/policy/check?check=allow_unseal` true, so an
  envelope cached while the grant was active cannot be unsealed by plugin
  unseal tools later.

## Revoking

Dashboard -> **Grants** -> **Revoke**, or `phoenix grants revoke gnt_...`
(the owning agent, or an approver). Revoke is idempotent. The very next use
gets `403 GRANT_REVOKED` with next step `ask_user`.

`/dashboard/grants` lists active grants (agent, paths, action, expires in,
uses, last used, approved by); "Recent" shows expired and revoked ones. If a
revoke cannot be saved, the page says `REVOKE_NOT_DURABLE` in red: the grant
is denied until the next restart but not saved, so fix the disk and revoke
again, or rotate the secret.

Expiry and revoke are checked on every request (no cache). Rotating an agent's
bearer token or certificate ends its grants. Deleting an agent revokes its
grants and records a tombstone first, so a recreated agent with the same name
cannot use the old grants with old credentials.

### What revoke cannot do

- **It cannot take back a value already delivered.** The agent (or the
  child process) may have kept it. Rotate the secret if that matters.
- It does not stop a process that is already running with the value in its
  environment.
- If a revoke cannot be saved (`REVOKE_NOT_DURABLE`), it holds only until the
  server restarts.

## Notifications

Set `notify_url` and Phoenix sends one POST for each **new** request (`201`).
A repeat of a request that is already pending sends nothing. The POST runs in
the background with a 5 second timeout, no retries and no redirects. If it
fails, the server logs one line and the request goes on as normal.

What is sent:

- agent name, action, how many paths, the request id
- a link to `<notify_dashboard_url>/dashboard/approvals#<req_id>` when
  `notify_dashboard_url` is set. The link is never built from the address the
  agent used to reach Phoenix.
- the paths, only when `notify_include_paths` is `true`

What is never sent: the agent's reason, approve links, tokens of any kind.
You still log in to the dashboard to approve.

The message is plain text with ntfy headers:

```
POST <notify_url>
Content-Type: text/plain; charset=utf-8
Title: Phoenix: access request
Tags: key
Click: https://phoenix.example.net/dashboard/approvals#req_...   (only with notify_dashboard_url)
Authorization: Bearer <token>                                     (only with notify_token_ref)

vector asks for read_value on 1 secret.
Request req_...: approve or deny it in the Phoenix dashboard.
https://phoenix.example.net/dashboard/approvals#req_...
```

Any webhook that accepts a plain-text POST works too; it can ignore the
headers.

At startup the server logs that notifications are on and the notify host
(not the full URL: an ntfy topic name works like a password). It warns when
`notify_url` is plain `http://` to a non-loopback host and
`notify_token_ref` is set, because the token would cross the network
unencrypted.

### ntfy example

Store the ntfy access token in Phoenix (not in the config), then point the
config at it:

```bash
phoenix set phoenix/ntfy-token -d "ntfy token for approval pings"   # paste tk_... when asked
```

```json
"access_requests": {
  "enabled": true,
  "notify_url": "https://ntfy.example.net/phoenix-approvals",
  "notify_token_ref": "phoenix://phoenix/ntfy-token",
  "notify_dashboard_url": "https://phoenix.example.net"
}
```

Restart the server. Subscribe to `phoenix-approvals` in the ntfy app; tapping
a notification opens the request card. The token is read from the store each
time a message is sent, so rotating it needs no restart. If the reference
cannot be read, nothing is sent (an unauthenticated post could land on a
public topic) and the server logs why, without the token. Consider adding
`phoenix/**` to `deny_paths` so no agent can request the token itself.

## Limits

- Exact paths only, at most 10 per request, `read_value` only.
- 3 pending requests per agent, 50 pending in total.
- 10 new requests per agent per hour.
- 10-minute cooldown on a path after a human denies it.
- 10 active grants per agent (a further approval returns `GRANT_LIMIT`; the
  request stays pending).
- Reason capped at 300 characters.
- Grants last at most `max_grant_ttl` (24h ceiling).

Each `429` carries `Retry-After`. Limits are worked out from the saved
requests, so a restart does not reset them.

## Troubleshooting

Each denial has a `code` and a `next_step`. Full table:
[denial-codes.md](denial-codes.md#access-requests-and-grants).

| Code | What it means | What to do |
|---|---|---|
| `ACL_DENIED` with `ask_user` | The feature is off, the action is not `read_value`, or the path is in `deny_paths` | Turn the feature on, or change the ACL |
| `SESSION_CANNOT_REQUEST` | Sent with a `phxs_` session token | Unset `PHOENIX_ROLE`; use the agent's own token or cert |
| `REQUESTS_DISABLED` (501) | `enabled` is false or the block is missing | See [Turning it on](#turning-it-on) |
| `REQUESTS_DEGRADED` (503) | The grants file could not be saved or was quarantined | Check disk space and permissions; see `GET /v1/status` |
| `SEAL_KEY_NOT_REGISTERED` | `require_sealed` is on and the agent has no seal key | `phoenix keypair generate <agent>`, then set `PHOENIX_SEAL_KEY` |
| `NOT_REQUESTABLE` | A path matches `deny_paths` | Ask the user; this path is never granted |
| `ALREADY_ALLOWED` | The ACL already allows every path | Just read it |
| `TOO_MANY_PENDING` / `RATE_LIMITED` / `REQUEST_COOLDOWN` (429) | A limit was hit | Wait for `Retry-After`; ask the user instead of re-asking |
| `APPROVER_REQUIRED` | Approve/deny from an identity not in `approvers` | Use the dashboard, or add the name to `approvers` |
| `SELF_APPROVAL` | An agent tried to approve its own request | Another approver or the dashboard must decide |
| `SEALED_REQUIRED` | A grant-backed read without the registered seal key | Use `phoenix exec --redact-output` with `PHOENIX_SEAL_KEY` set |
| `ATTESTATION_REQUIRED` | The path's policy (mTLS, IP, nonce, ...) was not met | A grant never waives this; meet the policy |
| `GRANT_EXPIRED` | The grant ran out of time | Request again if still needed |
| `GRANT_REVOKED` | A human revoked it | Ask the user before requesting again |
| `GRANT_LIMIT` | The agent has 10 active grants | Revoke some, then approve again |
| `REVOKE_NOT_DURABLE` | Revoked in memory but not saved | Fix the disk, revoke again, or rotate the secret |

Other things to check:

- **Grant approved but reads still fail:** same IP as the request
  (`bind_source_ip`)? Same credential (a rotated token or cert ends grants)?
  `PHOENIX_ROLE` unset?
- **No notification:** look for `access requests: notify for req_... failed`
  in the server log. Check `notify_url`, the token reference and that the
  request was new (a repeat of a pending one sends nothing).

## Endpoints

All responses are JSON with `Cache-Control: no-store`. Errors use the denial
shape and codes in [denial-codes.md](denial-codes.md#access-requests-and-grants).

Agent side (own bearer / mTLS / short-lived token; sessions get `403 SESSION_CANNOT_REQUEST`):

| Method + path | Does |
|---|---|
| `POST /v1/access-requests` | `{"paths":[...],"action":"read_value","reason":"...","ttl":"30m"}` -> `201` new, `200` identical one already pending |
| `GET /v1/access-requests[?status=pending]` | Your own requests |
| `GET /v1/access-requests/{id}` | One of yours (anything else is `404`), with `next_step` and `message` |
| `GET /v1/grants[?include=inactive]` | Your own grants |
| `POST /v1/grants/{id}/revoke` | Give up your own grant early |
| `GET /v1/whoami` | Identity, your ACL rules, active grants, pending requests, feature summary |

Approver side (an identity in `approvers`, not a session):

| Method + path | Does |
|---|---|
| `GET /v1/access-requests[?status=&agent=]` | Every agent's requests, with source IP, auth method and `already_allowed_paths` |
| `POST /v1/access-requests/{id}/approve` | Optional `{"paths":[subset],"ttl":"15m"}`: may narrow paths and shorten TTL, never widen |
| `POST /v1/access-requests/{id}/deny` | Optional `{"note":"..."}`; starts a 10-minute cooldown on those paths |
| `GET /v1/grants?agent=&include=inactive` | Every grant |
| `POST /v1/grants/{id}/revoke` | Revoke any grant (idempotent) |

## Status and audit

`GET /v1/status` (admin) shows `access_requests.state` (`ok` / `degraded`,
for example a quarantined or unwritable grants file) and `audit.state`
(`degraded` while committed grant events wait to reach the audit log; they
are retried every 30 seconds). Grant events are audit actions such as
`access_request.created`, `access_request.approved`, `grant.revoked`, each
preceded by an `....attempt` line. Reads through a grant are normal
`read_value` / `resolve` entries with metadata `grant_id`.

## Grants and step-up roles

Grants and step-up sessions are separate. A grant is for one agent and exact
paths and needs no role. A step-up role gives a whole session a role's
namespaces after a human approves. If you use step-up roles with
`elevates_acl`, bind them to named agents with `allowed_agents` (see
[session-identity.md](session-identity.md#binding-a-role-to-agents-allowed_agents)).
This release only warns about unbound step-up roles; the next release makes
`allowed_agents` required for `elevates_acl` roles.
