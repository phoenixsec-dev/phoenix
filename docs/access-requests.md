# Access Requests (request-use grants)

An agent gets told "no" for a secret. Instead of a human editing the ACL, the
agent asks Phoenix for temporary use of **that exact secret**. A human approves
or denies. An approval becomes a **grant**: this agent, with this credential,
from this IP, may read this path until a clock runs out or its uses are spent,
whichever comes first. A human can revoke it at any time. Every step is in the audit log.

A grant holds no secret and no token. The agent keeps using its own identity
(its bearer token). **Session tokens
(`phxs_`) can never request or use a grant.** No session roles are needed.

Humans decide on the dashboard (`/dashboard/requests`) or, for identities
listed in `approvers`, with `phoenix approve req_...`. Agents ask with
`phoenix request` (or the MCP tool `phoenix_request_use`) and use a grant with
`phoenix exec --redact-output`.

## The flow in one screen

```bash
# Agent: told ACL_DENIED with "next: ... phoenix request infra/b2/app-key ..."
phoenix request infra/b2/app-key --reason "nightly backup fails auth" --ttl 30m --wait

# Human: dashboard -> Requests -> No / Once / 15 minutes / Always
#   (or, as an approver identity:  phoenix approve req_... --ttl 15m --uses 1)

# Agent: use it. The value goes into the child's env, never into the output.
phoenix exec --redact-output --env B2_KEY=phoenix://infra/b2/app-key -- ./backup.sh

# Human: take it back early (dashboard -> Requests -> Revoke, or)
phoenix grants revoke gnt_...
```

## Turning it on

New installs (`phoenix-server --init`, `config.example.json`) have it on.
Upgraded installs have no `access_requests` block, which means **off**.

1. Add the block below to the server config (all defaults shown).
2. Make sure someone can approve: enable the dashboard (`--init` already did on
   a new install), or list an agent in `approvers`. The server warns at startup
   if nobody can.
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
| `approvers` | ACL agent names allowed to approve over the API. Empty = dashboard only. ACL `admin` alone is **not** enough, and nobody can approve their own request. The name must also still be in the ACL. Unknown names only warn at startup. |
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
   (denied, expired or revoked) or `request_use` (the grant's time or uses
   ran out). An approval says how far it goes: `one use left`, `until 14:32`
   or `always`. After a no, the agent must not ask again by itself.
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
token). `PHOENIX_ROLE` is ignored and a `phxs_` session token is
refused before anything is sent. The exception is `phoenix whoami`, which uses
whatever credential you have (session included) so it can show what that
credential can do.

When a read is denied with `next_step: request_use`, the CLI and MCP print
the concrete command, e.g.
`next: request temporary use from a human: phoenix request infra/b2/app-key --reason "why you need it"`.
The path is only pasted in when it is plain path characters
(`A-Z a-z 0-9 . _ / -`); otherwise the hint says `<path>`.

MCP (`phoenix mcp-server`) has `phoenix_request_use`, `phoenix_request_status`
and `phoenix_whoami`. None of them returns a secret value. The first two ask
as the agent itself even when the MCP server runs with `PHOENIX_ROLE`.

## Approving

### In the dashboard

**Requests** (`/dashboard/requests`) is the one page for this. A waiting
request is a card that asks one question, "May courier use infra/b2/app-key?",
with who asked and from which address, the agent's reason, the time left, and
four buttons:

| Button | What it gives |
|---|---|
| **No** | Nothing. The agent is told a human said no and not to ask again (10-minute cooldown). An optional note under **More** goes back to it. |
| **Once** | One read of each ticked secret, within the time the agent asked for. |
| **15 minutes** | Any number of reads for 15 minutes (less if the agent asked for less, or `max_grant_ttl` is lower). |
| **Always** | `read_value` on exactly the ticked paths, put on the agent's own access list. See [Always](#always). |

**More** has the rest: another of the listed times, "or N uses" (whichever
runs out first), the note, and what each button means for this request. With
several paths, untick the ones you do not want. Nothing here can widen what
was asked.

A card also shows each path in full with badges (**does not exist**, **hidden
from this agent**, **already allowed**), a red line for anything that would
make a yes fail (no seal key, token replaced since it asked, agent deleted),
and the path's attestation requirements. An answer never waives those. The
reason is in a box labelled **Agent says (not verified)**: escaped,
control/bidi/zero-width characters stripped, at most 300 characters, never a
link.

Below the waiting cards:

- **Active now**: open grants with the time and uses left, and **Revoke**.
- **Always**: every path an agent may read because of an Always, and
  **Remove**. Removing counts from the very next read.
- **Expired, nobody answered** and **History** (30 days).

The page is live: a new request appears within about two seconds on any open
dashboard page, as a card in the list here and as a popup anywhere else
(**Later** closes it). It polls with plain short requests, so it needs nothing
special from a reverse proxy and picks up by itself after a lost connection. A
card on screen is never redrawn while you are using it, and one that expires
stays, marked expired. **Notify me in this browser** turns on a browser
notification for when the tab is in the background; browsers offer that only
over HTTPS or on localhost. The page works without JavaScript too, just not
live.

Answers run the **same re-checks as the API** (current config, `deny_paths`,
`require_sealed`, the agent still exists with the token that asked,
active-grant cap) and are recorded as `dashboard@<ip>`. The dashboard login is
the approver here: the `approvers` list only controls API/CLI identities. Two
people, or a double tap: the first answer counts, the same answer again
returns the same result and adds nothing, and any other answer says the
request was already answered.

`/dashboard/requests/<req_id>` opens the page at one request, or shows how it
ended. Notifications link there, and the login page brings you back to it. The
old addresses (`/dashboard/approvals`, `/dashboard/grants`) redirect.

### Always

Always adds a rule to the agent's own access list (`acl.json`): `read_value`
on that exact path, never a wildcard, marked with the request it came from. It
is the same as writing the rule by hand, so it has no time limit, works from
any address, may be served plain (`require_sealed` and `bind_source_ip` are
for grants), also counts for the agent's role sessions when their scope covers
the path, and stays when access requests are turned off. Path attestation
policy still applies.

The audit log has `access_request.approved` with `always: true` and the
request id, and `always.removed` when it is taken back. Only the dashboard can
answer Always: an API approver need not be an admin, and this changes an
access list. Logins ([SSH](ssh-certificates.md)) have no Always.

Giving the agent a new token with a new permission list
(`phoenix agent create --force`) replaces all its rules, these included.

### From the CLI

Only identities listed in `approvers` (not sessions):

| Command | Does |
|---|---|
| `phoenix pending` | Pending access requests, with every path |
| `phoenix approve <req_id> [--ttl 15m] [--uses N] [--path p ...] [--yes]` | Shows every path (`+` kept, `-` removed by `--path`), action, TTL, use limit and the unverified reason, then asks y/N. `--uses 1` is the dashboard's Once |
| `phoenix deny <req_id> [--note "..."]` | Deny; starts the 10-minute cooldown |
| `phoenix grants [--all] [--agent name]` | List grants |
| `phoenix grants revoke <gnt_id>` | Revoke now |

`phoenix approve` and `phoenix deny` take a `req_...` ID. (`apr_...` IDs
belonged to step-up approvals, which were removed; those print why.) The y/N
answer is read from `/dev/tty`, or stdin when there is no terminal; `--yes`
skips the prompt for scripts.

Approval re-checks the **current** config: feature on, action grantable, no
path in `deny_paths`, TTL clamped to `max_grant_ttl`, `require_sealed` and
`bind_source_ip`, the agent still exists, at most 10 active grants.

## Using a grant

`phoenix exec --redact-output --env NAME=phoenix://<path> -- <command>` with
the agent's own `PHOENIX_TOKEN` and `PHOENIX_SEAL_KEY`, from the
same IP that asked. Exec resolves sealed, decrypts in its own process, and
gives the child the value but no Phoenix credentials. A plain `GET` or
`resolve` without the registered seal key gets `SEALED_REQUIRED` while
`require_sealed` is on.

With `PHOENIX_ROLE` set, exec first asks with the role's session. Sessions never
use grants, so for a path the role may not read, exec asks again with the agent's
own token at `POST /v1/resolve-approved`. There the server allows a read only
through a grant that matches right now or an exact Always; the agent's other
access does not count.

### Uses

A grant with a use limit counts each path separately: Once on two secrets lets
each be read one time.

- A use is spent only when the value is handed over. A refused read, a dry run,
  a missing secret or an unmet policy costs nothing.
- `phoenix exec` resolves all or nothing: if one reference is refused, none is
  delivered and no use is spent. It also looks for the command first, so a typo
  in it costs nothing. Once the value was handed over the use is gone, even if
  the command then fails.
- The same path twice in one `exec` or resolve is one use.
- The count is saved before the value leaves the server, so it is exact under
  any number of calls at once and after a restart. If it cannot be saved,
  nothing is delivered (`REQUESTS_DEGRADED`). If the connection drops right
  then, the use is still spent: the server cannot know whether the value
  arrived. The same goes for a disk that fails twice in a row (the save, then
  putting the old file back): nothing is delivered, and the use may count as
  spent after a restart. It is never given back twice.
- When several grants cover a path, one without a use limit is used first.
- After the last use, reads get `GRANT_EXPIRED` with `request_use`.
- For an SSH login a use is one certificate, not one connection. It can log in
  until the approval's time ends, and Revoke ends that earlier.

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

What a grant never does:

- It is never consulted for session tokens, for `list`, `write` or `delete`.
- It never waives the path's attestation policy (`source_ip`, `require_sealed`).
- It never makes `GET /v1/policy/check?check=allow_unseal` true, so an
  envelope cached while the grant was active cannot be unsealed by plugin
  unseal tools later.

## Revoking

Dashboard -> **Requests** -> **Revoke** (a grant) or **Remove** (an Always), or
`phoenix grants revoke gnt_...` (the owning agent, or an approver). Revoke is
idempotent. The very next use gets `403 GRANT_REVOKED` with next step
`ask_user`. If either cannot be saved, the page says `REVOKE_NOT_DURABLE` in
red: access is denied but that is not saved, and a restart may bring it back. Fix
the disk: the save is retried every 30 seconds, or do it again.

Expiry and revoke are checked on every request (no cache). Replacing an agent's
bearer token ends its grants: a grant is bound to the exact token that asked.
That includes an SSH login already signed under one: new logins stop at once
and an open session ends within about 30 seconds, as with a revoke.
Deleting an agent revokes its grants first.

### What revoke cannot do

- **It cannot take back a value already delivered.** The agent (or the
  child process) may have kept it. Rotate the secret if that matters.
- It does not stop a process that is already running with the value in its
  environment.
- A revoke that cannot be saved (`REVOKE_NOT_DURABLE`) denies at once, but a
  restart before a retry succeeds may bring the access back.

## Notifications

Set `notify_url` and Phoenix sends one POST for each **new** request (`201`).
A repeat of a request that is already pending sends nothing. The POST runs in
the background with a 5 second timeout, no retries and no redirects. If it
fails, the server logs one line and the request goes on as normal.

What is sent:

- agent name, action, how many paths, the request id
- a link to `<notify_dashboard_url>/dashboard/requests/<req_id>` when
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
Click: https://phoenix.example.net/dashboard/requests/req_...   (only with notify_dashboard_url)
Authorization: Bearer <token>                                     (only with notify_token_ref)

courier asks for read_value on 1 secret.
Request req_...: answer it in the Phoenix dashboard.
https://phoenix.example.net/dashboard/requests/req_...
```

Any webhook that accepts a plain-text POST works too; it can ignore the
headers.

At startup the server logs that notifications are on and the notify host
(not the full URL: an ntfy topic name works like a password). It warns when
`notify_url` is plain `http://` to a non-loopback host and
`notify_token_ref` is set, because the token would cross the network
unencrypted.

The same `notify_url`, token and link settings carry the dashboard's ping for a
secret shown or copied, which works with access requests off too and has its own
switch: see
[Showing and copying secrets](dashboard.md#showing-and-copying-secrets).

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
a notification opens that request. If you are not logged in you get the login
page first, and then the request. The token is read from the store each
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

## The grants file and older servers

Never run an older server and this one on the same files at once, also not for the
moment of an upgrade or rollback: see
[One server per set of files](configuration.md#one-server-per-set-of-files).

`grants.json` keeps grants with a use limit in their own `limited_grants` map.
A server older than use limits does not know that map: it opens the file, runs
normally, never honours one of those grants, and drops them when it next saves.
Grants without a limit, requests and cooldowns carry over both ways. Files from
older servers load unchanged.

An Always rule in `acl.json` carries an `always` mark (request, who, when). An
older server ignores the mark and keeps the rule as any other; if it then
changes an agent, the mark is lost. The access stays, but the Requests page can
no longer list or remove it; edit the agent's rules instead.

An Always is written in two steps: an inactive rule first (marked `staged`, with
no actions, so no server of any version reads through it), and the real one only
after the answer is saved. If the server dies in between, the next start
finishes it when the answer was saved and throws it away when it was not.

## Troubleshooting

Each denial has a `code` and a `next_step`. Full table:
[denial-codes.md](denial-codes.md#access-requests-and-grants).

| Code | What it means | What to do |
|---|---|---|
| `ACL_DENIED` with `ask_user` | The feature is off, the action is not `read_value`, or the path is in `deny_paths` | Turn the feature on, or change the ACL |
| `SESSION_CANNOT_REQUEST` | Sent with a `phxs_` session token | Unset `PHOENIX_ROLE`; use the agent's own token |
| `REQUESTS_DISABLED` (501) | `enabled` is false or the block is missing | See [Turning it on](#turning-it-on) |
| `REQUESTS_DEGRADED` (503) | The grants file could not be saved or was quarantined | Check disk space and permissions; see `GET /v1/status` |
| `SEAL_KEY_NOT_REGISTERED` | `require_sealed` is on and the agent has no seal key | `phoenix keypair generate <agent>`, then set `PHOENIX_SEAL_KEY` |
| `NOT_REQUESTABLE` | A path matches `deny_paths` | Ask the user; this path is never granted |
| `ALREADY_ALLOWED` | The ACL already allows every path | Just read it |
| `TOO_MANY_PENDING` / `RATE_LIMITED` / `REQUEST_COOLDOWN` (429) | A limit was hit | Wait for `Retry-After`; ask the user instead of re-asking |
| `APPROVER_REQUIRED` | Approve/deny from an identity not in `approvers` | Use the dashboard, or add the name to `approvers` |
| `SELF_APPROVAL` | An agent tried to approve its own request | Another approver or the dashboard must decide |
| `SEALED_REQUIRED` | A grant-backed read without the registered seal key | Use `phoenix exec --redact-output` with `PHOENIX_SEAL_KEY` set |
| `ATTESTATION_REQUIRED` | The path's policy (`source_ip`, ...) was not met | A grant never waives this; meet the policy |
| `GRANT_EXPIRED` | The grant ran out of time or uses | Request again if still needed |
| `CREDENTIAL_CHANGED` | The agent's token was replaced after it asked | The agent asks again with its new token |
| `ACL_WRITE_FAILED` | An Always could not be saved; nothing changed | Fix the disk, answer again |
| `GRANT_REVOKED` | A human revoked it | Ask the user before requesting again |
| `GRANT_LIMIT` | The agent has 10 active grants | Revoke some, then approve again |
| `REVOKE_NOT_DURABLE` | Revoked in memory but not saved | Fix the disk, revoke again, or rotate the secret |

Other things to check:

- **Grant approved but reads still fail:** same IP as the request
  (`bind_source_ip`)? Same credential (a rotated token ends grants)?
  `PHOENIX_SEAL_KEY` set? Any uses left (`phoenix whoami`)?
- **No notification:** look for `access requests: notify for req_... failed`
  in the server log. Check `notify_url`, the token reference and that the
  request was new (a repeat of a pending one sends nothing).

## Endpoints

All responses are JSON with `Cache-Control: no-store`. Errors use the denial
shape and codes in [denial-codes.md](denial-codes.md#access-requests-and-grants).

Agent side (own bearer token; sessions get `403 SESSION_CANNOT_REQUEST`,
except `GET /v1/whoami`, which answers for a session too, showing its scope and no grants):

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
| `POST /v1/access-requests/{id}/approve-limited` | The same plus `"uses":1` (1 to 1000, required). Its own address so a server too old to count uses answers `404` instead of allowing any number. `/approve` refuses `uses` |
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

## Logins as grants

A request with action `ssh_login` asks to log in to a machine, not to read a secret.
It follows this same flow with its own rules: see
[SSH certificates](ssh-certificates.md).

## Grants replace step-up roles

Step-up session approvals (role fields `step_up`, `step_up_ttl`,
`elevates_acl`, `allowed_agents`) were removed; access requests are the one
approval system. A config that still has those fields stops at startup with
a line naming each. To replace a step-up role, give the agent's own ACL what
it uses daily, and have it ask for the rest with `phoenix request`; a human
approves exact paths for a limited time.
