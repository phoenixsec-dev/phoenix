# Release Notes

## v0.25.0 (2026-11-24)

In short: find and use secrets from a phone, answer agents' requests on one live
page, see who, host and authority in the audit log, and a store that survives
crashes, full disks and mistakes. Also five security fixes.

**Before upgrading:** run the new `phoenix-server --check-config` on your config,
since it now refuses settings that name one file twice. If the dashboard is behind
a reverse proxy, set `dashboard.trusted_proxies`. The server needs to write small
`.lock` files next to its data files and the master key. **Stop the old server
before you start the new one on its files,** and the new one before you go back to
an older one: servers before v0.25.0 don't see these locks, so nothing stops both
from running and undoing each other's writes. Update the server first, then every
CLI. Scripts that run `phoenix export app` must say `phoenix export app/`: without
the slash it is now refused (it exported nothing and looked like a success). Showing secret values in the dashboard is off until you turn it on.

### Security: a request already running could use a replacement token's permissions

A request logs in with its bearer token, then looks up permissions by agent
name. If the token was replaced (or the agent deleted and made again) between
those two steps, the request used the new token's permissions. The window is
normally microseconds, but a `POST /v1/resolve` that sends its body slowly
could hold it open for up to 15 seconds. Now every permission check, admin
and approver checks included, also requires that the token the request logged
in with is still the agent's. So does everything looked up by agent name
("your" sessions, requests and grants). Requests that send a body are checked
again after it arrived, so one kept waiting with an old token can no longer
write a secret, make an agent or approve anything once that token is replaced.
Such a request is refused, normally with `401 unauthorized` and audit reason
`token_replaced`. Replaced at the very last moment it can also be a 403 (a few
admin endpoints, a grant with a use limit), a 409 (a new access request) or a
per-ref error in a batch resolve. Writing the same
token again with `--force` is not a replacement. Nothing to configure.

### Security: a revoked session could be quietly replaced after a role change

At start the server drops sessions whose role was removed or changed. It
dropped revoked ones too, so a revoked token then answered `SESSION_INVALID`
("mint a new one") instead of `SESSION_REVOKED` ("ask a human"), and the CLI
minted a fresh session on its own. Revoked sessions are now kept until they
expire, whatever happened to their role.

### Security: replacing an agent's token now ends its SSH logins

A grant is bound to the token that asked, so replacing the token stopped new
reads and new SSH certificates. An SSH login already signed carried on until
the grant ended. The machine's own check (`/v1/ssh/window`) now also says no
once the token was replaced or the agent deleted: a kept certificate stops
working at once and an open session ends within about 30 seconds. Nothing to
change on the machines.

### Security: the dashboard believed X-Forwarded-For from anyone

Any visitor could send their own `X-Forwarded-For`, use a new one for each
guess to dodge the login lockout, and choose the address shown beside a login
or an approval. The dashboard now uses the address the connection comes from.
The API always did. `X-Forwarded-Proto: https` is still believed from anyone,
on purpose: it gives the sender's own login cookie its `Secure` flag, can refuse
posts from an `http://` page and leaves out the plain-HTTP warning, all for the
sender alone, so a lie gains nothing, and no install behind a proxy loses that
flag.

**Action needed only if your dashboard is behind a reverse proxy:** add the
proxy's address to the new `dashboard.trusted_proxies` and restart, for example
`"trusted_proxies": ["127.0.0.1"]` for a proxy on the same host. Until you do,
the dashboard works (as after any restart, sign in again once), but logins and
approvals show the proxy's address, and everyone behind the proxy shares one
login lockout (a wait of up to 60 seconds after repeated wrong passwords). The
log names the address to add, for the first ten peers that send the header:
`Dashboard: ignored X-Forwarded-For from <address>`. A config with the
setting still loads on older versions, which ignore it. Details:
[Dashboard](docs/dashboard.md#network-access-tls-reverse-proxy).

### Security: an unusable PHOENIX_CA_CERT was only a warning

If `PHOENIX_CA_CERT` named a file that was missing or held no certificate, the
CLI and `phoenix mcp-server` warned and then trusted every public CA for that
request, the token included. HTTPS requests now fail and say why. Plain HTTP,
where the certificate is not used, works as before. **If your server's
certificate is from a public CA and you have a stale `PHOENIX_CA_CERT`, unset
it.**

### Store safety: ways a data file could be lost

Every place the server writes a file was checked for what a failed or cut-off
write, a full disk, a wrong path, a symlink, a second server or a key rotation
that dies halfway can do to it. Nothing to configure; what changed:
- **A key rotation cut off by a crash could end in losing every secret.** The
  server started on a store its key could not open, and trying `rotate-master`
  again overwrote `<store>.pre-rotate`, the one good copy. Now the rotation
  reads everything with the current key before it touches that backup, and the
  server refuses to start when the key opens nothing in the store, naming the
  backup if it works. If only some namespaces are unreadable it starts and logs
  them. If the new key is saved but the disk could not confirm it would survive
  a power cut, the backup is kept.
- **A data file that was a symlink was replaced by a plain file** on its first
  save (store, ACL, master key, audit rotation), so new content landed next to
  the link instead of on the disk the owner pointed it at, for example inside a
  container that is later thrown away. Writes now go to the file the link
  points at and the link stays.
- **Two servers on the same files silently undid each other's writes.** Each
  keeps the store, ACL, grants and sessions in memory and rewrites them whole,
  and even a second start that then failed on the port had already rewritten
  the sessions file. The server now holds a lock on each file it rewrites (an
  empty `<file>.lock` next to it, safe to leave there, gone with the process)
  and refuses to start while another one holds it. Two servers may share an
  audit log only if neither rotates it. Two servers with their own stores may
  share a master key, but then neither can rotate it (409) until the other has
  its own copy. Where locking does
  not work the server starts and logs a `WARNING`. This protects only servers
  that lock, v0.25.0 and newer: an older one neither makes nor checks a lock, so
  stop it before an upgrade, and stop the new one before a rollback.
- **`--protect-key` and `rotate-master` could overwrite each other's key
  file.** Adding a passphrase and then rotating without a restart saved the new
  key with no passphrase again; rotating while `--protect-key` waited for a
  passphrase put the old key back over the new one, leaving a store no key on
  disk opened. Both now check that the file is still the one they read:
  `rotate-master` answers 409 and asks for a restart, `--protect-key` stops.
- **A failed rotation no longer replaces `master.key.prev`**: the old key waits
  in `master.key.prev.new` and takes that name once the new key is saved.
  `rotate-master` on an empty store keeps the key and says so.
- **A damaged namespace key or protected master key crashed the server** (a
  wrong-length nonce). It is now an ordinary error for that namespace or file.
- **A grants file that was really another version 1 Phoenix file** was replaced
  by the next save. It is now set aside like a damaged one.
- **`store.path` pointing at another JSON file** (the ACL, the config, a
  passphrase-protected key, or a store of a newer format) loaded as an empty
  store, and the first secret written replaced that file. The server now
  refuses to start on anything that is not a version 1 store file.
- **A write or delete that failed (full disk) could still happen later.** The
  caller got an error, but the server kept the change in memory, served it and
  saved it with the next write that worked. It is now undone.
- **Two settings naming one file** (for example `audit.path` and
  `store.master_key`, or `store.path` and the SSH key) could destroy it. Only
  the grants and sessions files were checked, and not against the config file,
  TLS keys, the SSH key or the names of audit archives. The server now refuses
  to start, and `--check-config` fails, when a file it writes is also another of
  its files.
- **`--init` in a directory without `master.key`** (the key kept elsewhere, or
  lost) replaced `config.json` and the CA and server keys there. It now refuses
  if any file it would write, or `store.json`, is already there, or if another
  `--init` is running there.
- **`--reissue-cert` rewrote the CA certificate in place,** so a full disk or a
  crash could leave it empty, and it cannot be made again. It is now left alone
  and only ever replaced in one step, like the CA key. (The server certificate
  and key are still written in place, so that whoever you let read them still
  can; if that is cut off, run `--reissue-cert` again.) `--reissue-cert` also
  refuses a config that would make it write over the CA key or any other Phoenix
  file. The SSH signing key appears whole or not at all: one cut off half way
  used to stop the server from starting.
- **Replaced files keep their owner** when Phoenix runs as root, so
  `--protect-key` run with sudo no longer leaves a key the server cannot read.
- **An audit line cut off by a full disk or a power cut swallowed the next
  one:** that entry was written and reported as written, but no search could
  read it. It now starts on its own line.
- **An access change that failed to save could still give access.** A new agent,
  a seal key, or `agent create --force` with wider permissions or a new token was
  kept in memory, and the next save kept it for good, although the caller was told it
  failed. Now a change answered with an error may take access away but never gives
  any, at once or later. If replacing a token can't be saved, the old token stays
  dead and its sessions end, and the new one isn't in force: free the disk and run
  it again (a restart before that may bring the old token back). Replacing your own
  token is undone instead, or nobody could run it again. Access that was taken away
  but not saved, such as a removed Always, is saved by itself once the disk works.
- **The server did not start on a full disk** (since v0.23.0), because it rewrote
  `role-sessions.json` at every start. It now writes only what changed, and starts
  with a `WARNING` if that fails: ended sessions stay ended, and the save is
  retried. A missing audit log or SSH signing key that can't be made on a full disk
  is also only a warning. Reads, the dashboard login and role sessions work on a
  full disk: minting and renewing a session no longer fails, it goes on from memory
  until it can be saved (a restart before that only means minting another).

### One live Requests page: No, Once, 15 minutes or Always

Approvals and Grants were two pages for one thing, neither updated by itself,
and a request could expire while you looked at the page.

- **Requests** (`/dashboard/requests`) replaces both. A card asks "May courier
  use infra/b2/app-key?" with four buttons: **No**, **Once**, **15 minutes**,
  **Always**. Below: open access with Revoke, what is on Always with Remove,
  requests that expired unanswered, and history. The old addresses redirect.
- **Live.** A new request appears within about two seconds on any open
  dashboard page, as a popup when you are on another page, with a countdown.
  Optional browser notification. A choice you are making is never wiped, and
  an expired request stays, marked expired.
- **Once** and "N uses or M minutes": grants can have a use limit, counted per
  secret. Counting is exact and survives a restart; only a value that is handed
  over costs a use, with one exception: if saving the use fails and so does
  undoing that save, nothing is handed over but the use may count as spent after
  a restart. `phoenix approve --uses N` for CLI approvers.
- **Always** puts `read_value` on exactly that path on the agent's own access
  list, marked with the request, removable on the page at once. Never a
  wildcard, never for SSH logins, only from the dashboard.
- **Notifications link to the request** (`/dashboard/requests/<req_id>`), also
  through the login page.
- A request whose agent got a new token since asking can no longer be approved
  (`CREDENTIAL_CHANGED`). Before, the approval looked fine and did nothing.
- `phoenix request`, `phoenix request status`, `phoenix whoami` and the MCP
  request tools say what was granted: `one use left`, `until 14:32`, `always`.
  MCP requests run as the agent itself also under `PHOENIX_ROLE`.
- `phoenix exec` uses approvals also under `PHOENIX_ROLE`, resolves all or
  nothing, and checks that the command exists before it resolves.

**Upgrading:** nothing to change. On an install without an `access_requests`
block the feature is still off; see
[Turning it on](docs/access-requests.md#turning-it-on). **Going back:** an
older server opens the new files and works; it ignores grants with a use limit
and keeps Always rules as ordinary ones. Details in
[docs/access-requests.md](docs/access-requests.md#the-grants-file-and-older-servers).
Links in notifications sent before the upgrade still work.

### Who, host and authority as fields of their own

An identity's name often mashes together who uses it and what role it has.
Both can now be recorded next to the name, and the audit log shows them as
separate columns. The words are yours; Phoenix has no list of allowed values,
and they decide nothing about access.

- An identity can have `who`, `authority`, `kind` and `formerly` (older names).
  Set them with `phoenix agent set <name> --who ... --authority ... --kind ...
  --formerly old1,old2`: the token stays and no session ends. `phoenix agent
  show [name]` prints them, `phoenix agent create` takes the same options, and
  `phoenix whoami` and MCP `phoenix_whoami` show the caller's own. API:
  `PATCH /v1/agents/{name}/identity`, and `identities` in `GET /v1/agents`.
  A change is audited as `set-identity`, also when it is refused.
- Audit lines gain `who`, `host`, `authority` and `attested`. No field was
  renamed or removed. They come from the identity's record, never from a
  caller. A line about a refused credential, the dashboard or Phoenix itself
  has an empty `who` and `authority`. Grant events keep the actor's labels in
  `grants.json` until their line is written, so a delayed line stays right.
- `attested` is `false` on every line for now: a token doesn't prove who holds
  it. The dashboard calls such a `who` "declared". `host` is recorded only when
  Phoenix has established it, so it is empty until the per-machine service
  exists.
- The dashboard Audit page has the four columns and filters by who, host and
  authority. `phoenix audit` takes `--who`, `--host` and `--authority`, and adds
  the fields at the end of a line. Searching for an identity by name also finds
  its former names.
- Each identity gets a hidden `serial` in `acl.json`. Unlike `credential_id` (one
  per token), it stays when the token is replaced and is new when the identity
  is deleted and made again. Nothing uses it yet.

**Upgrading:** update the server first: the new CLI options say so when the
server is too old. Otherwise nothing to change. `acl.json` and old audit lines load as they
are; a missing field shows as `-`. Existing identities have no labels until you
run `phoenix agent set`, and get their serial at the next change to any agent.

**Going back:** an older server reads the new `acl.json` and works, but the
first agent change it saves drops the new fields. Old audit readers skip the
new keys.

### A fresh install can approve

`phoenix-server --init` used to turn on access requests with nobody able to
answer them: no dashboard, no approvers. Now it also turns on the dashboard. It
asks for the password (12 characters or more), or makes one up and shows it
once: press Enter, or run it without a terminal (Docker, scripts). Only the
bcrypt hash is stored.

- `--init --https` writes the config with HTTPS (`0.0.0.0:9443`) already on.
  The Docker quickstart and `docker-compose.yml` use it and publish 9443 to the
  host's loopback, so the dashboard works without editing a file. The image now
  also lists port 9443.
- `--hash-password` says so when a password is over bcrypt's 72 bytes.

**Upgrading:** existing installs do not change. To get the dashboard on one, run
`phoenix-server --hash-password`, put the result in the config as
`"dashboard": {"enabled": true, "password_hash": "..."}` and restart. Scripts that
run `--init` at a terminal now get a question; give it `</dev/null` to have the
password generated and printed. `docker-compose.yml` now publishes
`127.0.0.1:9443`; remove that line if the port is taken.

### Fixed: the CLI ignored proxies when it used Phoenix's own CA

With `PHOENIX_CA_CERT` set, `phoenix` (and `phoenix mcp-server`) ignored
`HTTPS_PROXY` and dialed the server directly, so HTTPS failed on machines that
only get out through a proxy, such as hosted agents on userspace Tailscale. It
now uses it for `https://` servers, like it already did without a CA. Plain
`http://` servers are still reached directly when the CA file loads. Connecting now times out after 30
seconds instead of the system's limit (requests themselves have no new limit).

**Upgrading:** if a machine sets `HTTPS_PROXY` but reaches Phoenix directly, add
the Phoenix host to `NO_PROXY`. If the proxy's own address is `https://`, add its
CA to the `PHOENIX_CA_CERT` file, but only if you trust that CA to vouch for the
Phoenix server itself: both connections are checked against the same file.

### Fixed: `phoenix export` wrote empty values when a seal key was set

With `PHOENIX_SEAL_KEY` (or `PHOENIX_ROLE`, which has its own seal key) the
server answers sealed. `export` sent the key but looked for a plain value, so it
printed `NAME=` for every secret and exited 0. It now opens sealed answers. If
one can't be opened, or an answer holds no value, it stops with an error that
names the secret and a non-zero exit. The same now goes for output that could not
be written (a full disk), an unknown format, and a single secret's name instead
of a folder (`export` takes `app/`, with the slash): each gave an empty or cut
file and exit 0. `-f json` is now always valid JSON, one object per line. **A
backup made with `export` while a seal key was set is empty: make it again.**

### Fixed: a name with `?`, `#` or `%` reached another secret

The CLI and MCP put names into web addresses as they were, so
`phoenix set 'app/key?v2'` wrote `app/key`, `phoenix delete 'app/key#old'`
deleted `app/key`, and `phoenix agent delete 'bob?x'` deleted the agent `bob`.
`get`, `list`, `export`, `import`, `keypair show`, `sessions info`, `sessions
revoke`, `phoenix_get`, `phoenix_list` and `phoenix_session_revoke` had the same
fault. Every command now acts on exactly the name it was given, and secrets whose
names already hold these characters can be read, listed, changed and deleted. To
list a folder with `?` or `[` in its name, end it with `/`.
`phoenix_unseal` now asks the server about the sealed secret's own name, and
refuses an answer about another one.

The server refuses a new secret name that is not valid UTF-8: after a restart it
could have become another name.

**Upgrading:** update the CLI wherever it is installed. Only `keypair show` for an
agent with `/` in its name needs the new server too. If something stored secrets under names with these characters, look at
the names without them too: they may have been overwritten. Names the server
redirected, such as `/app/key` or `app//key`, are now refused. `set` and
`delete` used to print ok for them and do nothing, and `get` read `app/key`.

### Smaller things

- `phoenix agent create` asks for the token at a terminal (hidden, twice), or
  reads it with `--token-stdin`. `-t <token>` still works, but is no longer taught:
  it puts the token in shell history and the process list.
- The end-to-end scenarios run in CI on every pull request (into any branch), with two new ones:
  upgrade from the previous release and back on the same files, and a fresh
  install that approves a request.
- Docs say which systems are supported (Linux and macOS; no Windows build).
- The agent skill no longer offers `phoenix keypair generate`, which needs admin.
- The runnable examples use the `go` on `PATH`.

### Find and use a secret from your phone

Getting one password used to take a terminal, the exact name, and a guess at
the username. The dashboard now has a **Secrets** page: search by name,
description, tag or username, open one and copy the username. With showing turned
on you can show or copy the password, or copy it and open the page in one tap. You can add a secret (paste,
type or generate), give one a new value, and edit its description, tags,
username and link. The dashboard is laid out for a phone first, with one
navigation, and can be installed as an app. Its offline cache (the
service worker's) holds only static files. The browser also remembers the IDs of
requests it has already shown, so it does not announce them twice.

**Showing and copying secrets is off until you turn it on**, after an upgrade and
on a new install. The dashboard password could only approve access until now; with
showing on, anyone who knows it can read every value that no policy rule
withholds. So it is set in the config file only, never from the dashboard:

1. If the password was shared, or an agent can read it, change it first: put the
   output of `phoenix-server --hash-password` in the config as
   `dashboard.password_hash`.
2. In the server's config file, change `"reveal": false` inside `"dashboard"` to
   `"reveal": true`. If there is no `"reveal"` line (an older config), put `"reveal": true,`
   right after `"dashboard": {`. Restart: the log says `showing secrets is ON`.

`phoenix-server --init` asks once at a terminal (default no). While it is off,
the page says so where Show and Copy would be, with that line and the name of the
file. Finding, adding and editing work without it. A secret whose rule blocks the
dashboard stays blocked when showing is on.

**Every secret shown or copied pings you**, if notifications are set up
(`access_requests.notify_url`, also with access requests off): which secret, and
the login, device and address that did it, never the value. One ping per secret
and login per 5 minutes. `"dashboard": {"notify_on_reveal": false}` turns it off
without touching request notifications; the audit line has no switch. A ping that
fails never stops anything and is logged. Without `notify_url` the page says once
that nobody is pinged. The ping names the secret whatever `notify_include_paths`
says, so check who can read that topic.

How it is protected ([threat model](docs/threat-model.md#threats-specific-to-the-dashboard)):
showing, copying or changing needs the password typed within the last 5
minutes; every show and copy is audited (`read_value`, with the address and the
login's ID) before the value is sent; policy rules (`source_ip`,
`require_sealed`) hold for values in the dashboard too; values are never in a page's HTML
and never cached; no page can be framed or run foreign script.

Dashboard responses now carry a Content-Security-Policy: scripts must be files
on the dashboard's own address, never inline. Every dashboard POST refuses
requests from other sites. Wrong passwords sent in parallel now count one by
one, at login too.

### A secret can carry its username and link

- `phoenix set` takes `--username` and `--url`. `phoenix info`, MCP
  `phoenix_list`, `GET /v1/metadata` and the dashboard show them to callers with
  `list` on the path. They are never in a value read.
- `phoenix describe <path> [-d ...] [--tags ...] [--username ...] [--url ...]`
  (`PATCH /v1/metadata/{path}`) changes them without reading or writing the
  value. Needs `write` on the path; audited as `describe`; who wrote the value
  and when stays as it was.
- A save that fails now leaves the old value in use. Before, the server kept
  serving the new value from memory although it reported an error.

**Upgrading:** nothing to do. Store files load unchanged and the new fields
appear only on secrets that have them. Going back: v0.24 opens a file with
usernames and links and keeps every value, but drops those two fields the next
time it writes. Update the server before the CLI: an older server cannot store
them, and the CLI says so.

## v0.24.0 (2026-11-24)

### Agents can find out they may log in to another machine

An agent can now ask Phoenix which machines it may log in to, and whether it
already has an approval.

- `GET /v1/ssh/machines` lists the machines this server can sign logins for,
  to any signed-in caller: names only, never addresses or users. Each shows
  `approved_until` where the caller's own approval is active. With `ssh_ca`
  off it answers 200 with an empty list, `enabled: false` and a note. Audited
  as `ssh.list`.
- `phoenix ssh --list` prints that list. Plain `phoenix ssh` prints the list
  and the usage line.
- `phoenix-skill/SKILL.md` now has frontmatter (`name: phoenix` and a
  trigger description that covers "root or an SSH login on another machine")
  and a short "Root on another machine" section. The MCP `phoenix_whoami`
  description points at `phoenix ssh --list` too.

### A clearer error when `phoenix ssh` has no approval

- An approval belongs to one agent, token and IP, so a login with another token
  or from another IP is refused even after a human approved it. The error now
  says to check `PHOENIX_TOKEN` and where the command runs from and, when the
  server is v0.24.0 or newer, names the agent the CLI ran as. Before, it only
  said to run again with `--reason`.
- It says so plainly when the approval has ended.
- When `PHOENIX_TOKEN` holds the agent's own token, `phoenix ssh --list` uses it
  even with `PHOENIX_ROLE` set, so it shows the approvals a login would use.
- The usage line shows `--reason` as optional. Inside an active approval it was
  never required.

**Upgrading:** update the server first. An older server has no
`/v1/ssh/machines` and answers 404; `phoenix ssh --list` then says the server
is too old. Logging in with `phoenix ssh <machine>` still works on servers that
have SSH logins (v0.20.0 and newer).

## v0.23.1 (2026-11-24)

### Security: replacing an agent's token did not end its role sessions

A role session (`phxs_`) named its agent but was not tied to the token that
minted it. So when an agent was deleted, or its token replaced because it had
leaked, sessions already made with the old token kept logging in and could be
renewed without limit. While the agent did not exist they could not read
secrets (but see below for v0.13.5 to v0.20.0). Once an agent with the same
name existed again, or if its token was replaced with `--force`, they could
read whatever that agent and the session's role allow. **Replacing a leaked
token did not cut off someone holding a session made with it.**

**Who is affected:** servers with `session.enabled`, on every release that has
role sessions: v0.13.3 (2026-03-20) to v0.23.0. Up to v0.22.0 a server restart
ended such sessions; on v0.23.0 sessions survive restarts (except with the
1Password backend), so they did not end on their own as long as they were
renewed. On v0.13.5 to v0.20.0, a session
approved for an `elevates_acl` role skipped the ACL, so it could still read
secrets after its agent was deleted, until it expired.

**What to do:** update. If you replaced an agent's token or deleted an agent on
one of these versions because the token may have leaked, updating ends every
session saved by the old version; check the audit log for that agent's reads
after the replacement. If you cannot update yet, after replacing a token or
deleting an agent, list that agent's sessions and revoke each one, as an admin:

```bash
phoenix sessions list --agent <name>
phoenix sessions revoke <session-id>
```

Do it after the replacement, not before: the old token could mint more until
then. If any role has `local` in `bootstrap_trust`, that is not enough, because
there a session could mint another one while you work. To be sure, end every
agent's sessions after the replacement: on v0.22.0 and older restart the server;
on v0.23.0 stop it, delete `role-sessions.json` (next to the ACL file) and start
it. Other agents' clients mint new sessions (CLIs older than v0.23.0 need
`~/.phoenix/token-cache.json` cleared).

**Now:**

- Each session is bound to a fingerprint of the bearer token that minted it
  (never the token), and works only while that is still its agent's token.
  Every use and renewal checks this, on every endpoint.
- Deleting an agent or replacing its token ends the old token's sessions at
  once and for good, and writes one `session.ended` audit line per session.
  `--force` with the same token keeps them.
- A session can no longer mint another session (a role trusting `local` let it,
  although the docs said not). The new one did not keep its scope or seal key.
- Each token the server issues gets a random `credential_id` in `acl.json`
  (written by the server; nothing to set). A token taken away and given out again
  does not bring its old sessions back.
- The ACL file is synced to disk before a change is reported done.
- An ended session gets `401 SESSION_INVALID`, which the CLI and
  `phoenix mcp-server` (v0.23.0 and newer) recover from by minting once with
  their current `PHOENIX_TOKEN`.

**Upgrading:** nothing to configure. The first start ends the sessions saved by
v0.23.0, which have no fingerprint, and logs how many. CLIs and MCP servers from
v0.23.0 or newer mint new ones by themselves; older CLIs need
`~/.phoenix/token-cache.json` cleared once. See
[Session identity](docs/session-identity.md#ended-with-the-agents-token).

## v0.23.0 (2026-11-24)

### Fixed: a server restart broke every role session

Every restart made a new random session signing key and forgot all session
records, so every cached role session failed with `401 SESSION_INVALID`
until someone cleared `~/.phoenix/token-cache.json` by hand. Now:

- The signing key is derived from the master key, and session records are
  saved to `role-sessions.json` next to the ACL file (no tokens or keys in
  it). Sessions and revocations survive a restart. Sessions of a role that
  was removed or changed are still ended at restart, so role edits take
  effect as before.
- The CLI and `phoenix mcp-server` replace a session that gets
  `SESSION_INVALID` or `SESSION_EXPIRED` once and retry the request once.
- Revoked sessions keep answering `SESSION_REVOKED` until they expire, before
  and after a restart.

**Upgrading:** nothing to configure. The server needs write access to the
ACL file's directory (it already writes `grants.json` there). The first
restart onto this version still ends old sessions (they were signed with the
old random key); clients on this CLI re-mint by themselves, older CLIs need
the cache cleared once more.

### `phoenix list` shows descriptions; new `phoenix info`

Most secrets have a description, but nothing showed it: the only route that
returned one also returned the value. Now:

- `phoenix list` prints each path with its description (and tags) under it,
  or `(no description)`. `--names` prints bare paths exactly as before, for
  scripts. `--tag <tag>` lists only secrets with that tag.
- `phoenix info <path>` shows description, tags, created and updated times,
  and who created and last changed the secret. Never the value.
- MCP `phoenix_list` returns `path — description [tags]` lines and takes an
  optional `tag`.
- `phoenix set` without a description that leaves the secret with none
  prints a one-line nudge. It never fails.
- New route `GET /v1/metadata/...`: needs only `list` permission, audited as
  `list`, never returns the value (see the API reference). `PUT
  /v1/secrets/...` now also returns `has_description` to callers who may list
  the path.
- The store keeps the original `created_by` on updates and records the last
  writer in a new `updated_by`. Older versions overwrote `created_by`, so on
  existing secrets it shows the last writer until they are next updated.

**Upgrading:** update the server first. A new CLI against an old server
still lists names (with a note) and `phoenix info` says the server is too old.

### Dashboard: several logins at once

Signing in on one device no longer locks every other device out. Up to 5
browsers can be signed in at once. The Sessions page lists each login with
its device, IP, when it signed in and when it was last used, and a
**Sign out** button. A 6th login signs out the one used least recently, so
whoever has the password is never locked out. Logout now ends the login on
the server as well. Password rate limiting and `session_ttl` are unchanged.

**Upgrading:** `dashboard.allow_multi_login` and the Force Login button are
removed. A config that still has `allow_multi_login` (true or false) refuses
to start; delete the line. New audit actions: `dashboard.login_revoke` and
`dashboard.login_evicted`; `dashboard.force_login` is gone.

## v0.22.0 (2026-11-11)

### Fixed: a typo in a command looks like a typo, not a permission wall

`phoenix list --prefix services/browser/` (no such option) used to send
`--prefix` to the server as a secret name; the answer was "read_value is not
allowed ... cannot be fixed by retrying", and an agent believed it for four
days. Now:

- Every command checks its options before contacting the server. An unknown
  option prints `phoenix <command>: no such option: <arg>`, the usage line
  and `Run 'phoenix <command> --help' for more`, and exits 2. `-h` / `--help`
  works on every command. A value after an option that takes one is a value
  (`-d -v` is a description of "-v"), and `--` ends the options, so a path
  that starts with `-` still works (one named exactly like one of the
  command's options is refused). A lone `-` is an unknown option, not a path.
- `phoenix list services/browser`, `services/browser/` and
  `services/browser/*` all list `services/browser/`; any other wildcard is a
  usage error. MCP `phoenix_list` takes the same forms.
- The server answers a single-secret read whose path contains `*` with 400
  "invalid secret path: wildcards are not secret names; to list a folder, end
  the path with /", decided before the ACL and attestation checks so it never
  reads as a permission problem and reveals nothing about what exists.
  Writing a secret whose name contains `*` is refused too (400), since it
  could not be read back. **Before deploying**, check that no stored secret
  name contains `*` (`phoenix list | grep '\*'`); rename any that do first.
- Removed flags (`set -v`, `exec --output-env`, ...) are recognised only
  where they are options: a description of "--value" no longer trips one,
  and `-d -- -v x` no longer slips one past.

### Removed (second cuts): secrets on the command line and in files, PIN login, old formats

The second round of cuts, decided by the owner on 2026-11-09. Ships as its
own version after the first cuts below. Same rule as before: a removed
setting stops the server at startup with a line saying why and what to use
instead, and a removed command or flag prints the same. Check before you
deploy:

```
phoenix-server --check-config --config /data/config.json
```

It now also checks the ACL file, and lists problems from the config, policy
and ACL files in one run instead of stopping at the first.

| Removed | Why | Instead |
|---|---|---|
| `phoenix exec --output-env <file>` | It wrote secret values to a plain-text file that outlives the command and ends up in backups. | Run the command under `phoenix exec --env KEY=phoenix://ns/secret -- <command>`. `examples/02-exec` shows how. |
| `phoenix set -v/--value <value>` | The value lands in shell history and the process list. | `phoenix set <path>` (hidden prompt), `--multiline` for PEM keys, or pipe it in with `--value-stdin`. |
| `phoenix-server --init --passphrase <value>` | Same: visible in the process list and history. | `--passphrase-stdin` or `PHOENIX_MASTER_PASSPHRASE`, which `--init` now honours (before, it ignored both). |
| Dashboard PIN: `dashboard.pin` | Stored in plain text in config.json. | `dashboard.password_hash` (`phoenix-server --hash-password`). |
| ACL action `"read"` | Shorthand for `list` + `read_value` that hid that it let the agent read values. An ACL file using it stops startup, naming each agent and path. | `"list", "read_value"` (or just `"list"`). |
| Policy file `"rules"` list (with `allowed_ips`) | The old format; every rule fits the `"attestation"` map. | `{"attestation": {"<path>": {"source_ip": [...]}}}`. |
| Role `attestation` list (`source_ip`, `require_sealed`) | It duplicated other settings: `source_ip` meant loopback only, and `require_sealed` only worked alongside `require_seal_key`. The `ATTESTATION_FAILED` denial it produced is gone too. | `bootstrap_trust: ["local"]` for loopback only; `require_seal_key: true` for sealed delivery. |
| `phoenix secret-provider openclaw`, `phoenix resolve --stdin-json` | Extra names for the OpenClaw exec provider. | `phoenix openclaw-exec-provider`. |

Kept on purpose: secret tags, `crypto.provider`, `phoenix policy show` /
`test`, `access_requests.grantable_actions` and `phoenix verify`.

### Changed: seal key pairs are made on the client

`phoenix keypair generate <agent>` used to have the server make the pair and
send the private key back. Now the CLI makes it, writes the private key
(mode `0600`), and sends only the public key to `POST /v1/keypair`
(`agent_name` + `seal_public_key`); the server never sees the private half.
Existing registered seal keys keep working unchanged. Upgrade the server and
the CLI together before generating or rotating a key: an older CLI gets a 400
from the new server saying to update, and the new CLI refuses an older
server (which would register a key it made itself) without touching the
existing key file.

## v0.21.0 (2026-11-11)

### Removed: features that checked nothing, dead code, mTLS, MCP over HTTP, step-up

Phoenix is getting ready to be released as open source. Several features
looked like security but believed what the caller said, some were dead, and
some had no users. They are gone, so there is less to read, configure and
trust.

**Upgrading:** a config, policy file or role that still uses a removed
setting now stops the server at startup, with one line per setting saying
why it went and what to use instead. Nothing is silently ignored. Check a
config before you deploy:

```
phoenix-server --check-config --config /data/config.json
```

It checks the config, the policy file it names and the HTTPS certificate,
and exits 0 ("config OK") or 1 with the list. It does not need the master
key or bind a port. Removed API routes answer `410 Gone` with the reason;
removed CLI commands and flags print why they went.

| Removed | Why | Instead |
|---|---|---|
| Process rules: policy `process` (`uid`, `binary_hash`), `require_fresh_attestation`, `credential_ttl` | The server took the process details from whatever an admin caller put in a token request. | `source_ip`. Real caller checks come with the local Phoenix service. |
| Short-lived tokens: `POST /v1/token/mint`, `attestation.token`, bootstrap method `"token"`, `phoenix token mint` | Same: the tokens only carried caller claims. | Session roles (`PHOENIX_ROLE`). Session tokens (`phxs_`) are the one short-lived credential. |
| Tool rules: `allowed_tools`, `deny_tools`, the `X-Phoenix-Tool` header, `PHOENIX_TOOL` | They matched a header the client sets itself. | ACL paths and session roles. |
| Nonce challenges: `POST /v1/challenge`, `attestation.nonce`, `require_nonce`, `nonce_max_age`, `require_signed`, `phoenix resolve --signed` | Only signed resolve with a client certificate could pass; `exec`, MCP and the SDKs never could. `nonce_max_age` was never enforced. `/v1/resolve` now answers 400 if a client sends a nonce or signature. | `source_ip`. |
| `POST /v1/proxy` | Never built; always answered 501. | Nothing. |
| `phoenix init` | It only printed a pointer. | `phoenix-server --init <dir>`. |
| `onepassword.enabled` | Nothing read it. The 1Password connector stays. | The connector is on when `store.backend` is `"1password"`. |
| Policy `time_window` / `time_zone`, `phoenix policy test --time` | Unused. | `source_ip`, or revoke access when it is not needed. |
| Client certificates (mTLS): `auth.mtls`, `phoenix cert issue`, `POST /v1/certs/issue` and `/revoke`, the CRL, policy `require_mtls` / `cert_fingerprint` / `deny_bearer`, bootstrap method `"mtls"`, role attestation `require_mtls` / `cert_fingerprint`, `PHOENIX_CLIENT_CERT` / `PHOENIX_CLIENT_KEY` | Off here, hard to run, unused. HTTPS already protects tokens in transit. With mTLS gone, `deny_bearer` could only lock everyone out. | Bearer tokens over HTTPS. The internal CA, the server certificate, `--reissue-cert`, seal key pairs and the SSH certificate CA all stay. The CLI warns if `PHOENIX_CLIENT_CERT` is still set. |
| MCP over HTTP: `phoenix mcp-server --http`, `PHOENIX_MCP_TOKEN`, `PHOENIX_MCP_TLS_CERT` / `KEY` | Half-built (no sealed mode, no session renewal) and unused. | `phoenix mcp-server` over stdio, started by the agent's harness. |
| Step-up: role `step_up`, `step_up_ttl`, `elevates_acl`, `allowed_agents`, `GET /v1/approvals`, `/v1/approval/...`, `apr_` IDs in `phoenix approve` / `deny` / `pending`, the step-up cards on the Approvals page, codes `APPROVAL_REQUIRED`, `STEP_UP_REAPPROVAL_REQUIRED`, `ROLE_NOT_ALLOWED` | 14 requests ever, mostly upgrade tests, and it overlapped with access requests. | Access requests and grants: the agent runs `phoenix request`, a human approves exact paths for a limited time. Roles and sessions stay. |
| The local agent socket: `internal/agent`, `attestation.local_agent`, `phoenix agent-sock` (all subcommands) | It ran inside phoenix-server, so it only worked on the server's own machine. The planned local Phoenix service runs on every machine as its own process, so the same job does not belong in two places. Its kernel caller check (`internal/agent/peercred_linux.go`, SO_PEERCRED) can be recovered with `git show d9cc1a4:internal/agent/peercred_linux.go` when that service is built. | Nothing yet; delete the block. `phoenix get`, `resolve` and `exec` work as before. |
| The `tls` config block | Three ways to turn on HTTPS (`tls.enabled`, `https_listener`, mTLS implying TLS) became one. | `https_listener`. Keep `server.listen` on `127.0.0.1`. |

Kept on purpose: sessions and roles, access requests and grants, `source_ip` rules,
sealed delivery and its settings, and the audit log format are unchanged.

### HTTPS: one switch

`https_listener` is now the only way to serve HTTPS. It gained optional
`ca_cert` and `ca_key`, which only `--reissue-cert` uses (they used to live
under `auth.mtls`). `--init` writes the block switched off with every path
filled in, so turning HTTPS on is `"enabled": true`. `server.listen` always
serves plain HTTP; the startup warning for a non-loopback `server.listen`
now points at `https_listener`.

### Fixed: `phoenix exec` passed Phoenix credentials to the command it ran

`phoenix exec` stripped seven variables from the child's environment but
passed `PHOENIX_MCP_TOKEN`, `PHOENIX_MASTER_PASSPHRASE`, `PHOENIX_ROLE`
(enough for the child to mint its own session) and
`OP_SERVICE_ACCOUNT_TOKEN` through. It now strips every `PHOENIX_*`
variable and the 1Password service account token (also under the name
`PHOENIX_OP_TOKEN_ENV` points at). Values mapped with `--env` still arrive.
`phoenix ssh` runs `ssh` with the same filtered environment.

## v0.20.0 (2026-11-11)

### SSH Certificates: Temporary Root Login, Approved Like a Grant

`phoenix ssh <machine>` logs an agent in with a human's approval and a certificate
that expires with it. The signing key stays on the server, the agent's key is
thrown away, and revoking blocks new logins at once and ends open sessions within
about 30 seconds. Off unless you add an `ssh_ca` block. See [SSH certificates](docs/ssh-certificates.md).

### Fast Dashboard and Audit Log Rotation

The Overview and Audit pages, `GET /v1/status` and `GET /v1/audit` used to
decode the whole audit log on every request: 7-8 seconds each for a 260 MB log
on one CPU, which also made other tabs lag while it ran. They now read from the
end of the file and stop once they have enough entries: every dashboard page
loads in under 150 ms with the same log.

- The audit log rotates at `audit.rotate_mb` (default 50 MB) into dated
  archives next to it. Archives are never deleted; all but the newest are
  gzipped. `"rotate_mb": -1` turns rotation off. See
  [Audit log rotation](docs/configuration.md#audit-log-rotation).
- Queries search the current file and the newest archive, at most 64 MB.
  The Audit page shows a note when that cut a search short, and
  `GET /v1/audit` returns `"truncated": true`.
- The Audit page's status filter now runs in the search: "denied, 50" shows
  the newest 50 denied entries, not the denied ones among the newest 50.
- `GET /v1/audit` without `limit` (and `phoenix audit` without `--last`)
  returns the newest 10,000 entries instead of the whole log.
- Secret paths are shown in full on every dashboard page (Overview and Audit
  used to cut them at 40 and 30 characters) and wrap on narrow screens.

## v0.19.0 (2026-11-01)

### Request-Use Grants: an Agent Asks, a Human Approves, Access Expires

An agent that is denied a secret can now ask for temporary use of it. A human
approves or denies in the dashboard, and the agent gets a grant: access to
those exact paths for a limited time, which the human can revoke at any time.
There is no new token to steal. The grant is a record that says "agent X,
using its own credential from IP Y, may read paths Z until time T".

- **Off unless you turn it on.** Configs without an `access_requests` block
  behave exactly as before. New installs (`--init`) get it enabled.
- **Agent side:** `phoenix request <path>... --reason "..." [--wait]`,
  `phoenix request status`, `phoenix whoami`, and MCP tools
  `phoenix_request_use`, `phoenix_request_status`, `phoenix_whoami`.
  Up to 10 exact paths per request; no wildcards.
- **Human side:** a "Secret access requests" section on the dashboard
  Approvals page shows who is asking, from where, for which paths, why
  (labelled "not verified"), and what each path requires. The approver can
  untick paths and shorten the time, never widen. A new Grants page lists
  active and recent grants with Revoke. `phoenix pending`, `phoenix approve`,
  `phoenix deny` and `phoenix grants` work for identities listed in
  `access_requests.approvers`; an agent can never approve its own request.
- **Using a grant:** `phoenix exec --redact-output --env NAME=phoenix://<path> -- <command>`.
  Granted values are delivered sealed to the agent's registered key by
  default, and `--redact-output` replaces them with `[REDACTED:NAME]` in the
  command's output, so they do not end up in an agent's chat.
- **Safety limits:** read access only; session tokens can never use or
  request grants; grants never bypass attestation and never unseal through
  `phoenix_unseal`; per-agent and global request limits, a 10-minute
  cooldown after a deny, and a cap on active grants. Grants are saved to
  `grants.json` (next to the ACL file by default) with fsync, and a revoke
  is never reported as done unless it was saved.
- **Notifications:** optional `notify_url` (ntfy works out of the box) pings
  on each new request with the agent, path count and a dashboard link. Paths
  only if you opt in; the agent's reason is never sent.
- **Docs:** [Access requests](docs/access-requests.md) is the full guide.

### Clear Denial Codes and Next Steps

Every access denial now carries a stable `code` and a `next_step`
(`request_use`, `wait`, `use_exec`, `remint_session`, `ask_user`, `none`), so
the CLI, MCP server and plugins can tell an agent what to do instead of
showing "access denied". `/v1/resolve` adds `error_codes` per ref next to
the unchanged `errors`. Clients show their own fixed hint text and clean
server text (control, bidi and zero-width characters dropped, length
capped); they no longer display the server's `remediation` field.
Attestation denials no longer reveal policy rules to the caller; the detail
goes to the audit log. See [Denial codes](docs/denial-codes.md).

### Step-Up Role Binding

- **`allowed_agents`** on a session role limits which agents may mint it,
  have its step-up approved, or renew it (`403 ROLE_NOT_ALLOWED`). Roles
  without the list behave as before, but the server warns at startup about
  step-up roles with no binding. A later release will require it for
  `elevates_acl` roles. See [Session identity](docs/session-identity.md).

**Upgrading:** no action required; nothing changes until you add an
`access_requests` block. Before turning it on, consider setting
`allowed_agents` on your step-up roles. The server refuses to start if the
grants file would be the same file as the ACL, audit log, secrets data file
or master key, or is a symlink; set `access_requests.store_path` to fix that.

## v0.18.0 (2026-10-26)

### Host-Scoped Opt-Out for the Plaintext Client Warning

- **`PHOENIX_ALLOW_PLAINTEXT=<host>[,<host>...]`** silences the CLI and Go
  SDK warning about plain `http://` to a non-loopback server, for the named
  hosts only. It is meant for clients that reach the server over a
  host-local virtual network (containers on one bridge), where the warning
  fired on every CLI command and cluttered scripts. Matching is strict: IP
  addresses compare as addresses with IPv6 zones matched exactly, hostnames
  ignore ASCII case only, and there are no wildcards. Any other server still warns,
  and the warning text now names the variable so it can be found. Server
  and MCP startup warnings are unchanged. See
  [LAN deployment](docs/lan-deployment.md#plaintext-on-a-single-host-opt-out).

**Upgrading:** no action required. Without the variable, behavior is
unchanged.

### Optional HTTPS Listener: Move Clients to HTTPS One at a Time

v0.17.0 made HTTPS a one-line switch, but flipping `tls.enabled` converts the
primary address for every client at once. On a fleet with many HTTP consumers
that is a flag day. v0.18.0 lets a server offer HTTPS on a second address while
the existing HTTP endpoint keeps working, so clients can move over gradually
and nothing breaks for the ones that have not moved yet.

- **New `https_listener` config block**, disabled by default. When enabled it
  serves HTTPS on its own `listen` address with its own `cert`/`key`. Both
  endpoints share one handler, so secrets, ACLs, policies, sessions, the bearer
  rate limiter, and the audit log are the same on either port. Source-IP policy
  uses the direct client address on both. HTTP is not redirected.
- **mTLS carries over.** If `auth.mtls` is enabled, its client-certificate
  verification and CRL revocation checks apply to the HTTPS listener too,
  including `auth.mtls.require`.
- **Misconfiguration is fatal, runtime failures are contained.** A blank
  `listen`, `cert`, or `key`, or a certificate that cannot be loaded, stops
  startup with `invalid config: ...`, the same as every other config error, so
  a bad deploy cannot look healthy. If the HTTPS address cannot be bound or the
  listener fails while running, Phoenix logs it and the primary keeps serving.
  The primary binds first, so an overlapping address cannot take its port.
  HTTPS never falls back to plaintext.
- **`--init` output** now includes `"https_listener": {"enabled": false}` in
  newly written config files.
- **Docs**: new "Optional HTTPS alongside the existing endpoint" section in
  `docs/configuration.md`, linked from `docs/getting-started.md` and
  `docs/lan-deployment.md`. e2e scenario 19 covers the shared state, the fatal
  misconfiguration cases, and bind-failure containment.

**Upgrading:** no action required. Configs without `https_listener` load with
it disabled and behave exactly as before. To use it, see the configuration
docs; monitor the HTTPS port separately, since the existing health check only
checks HTTP.

### Installer and Docker Fixes

- **`scripts/install.sh` works again.** It asked for `phoenix_vX.Y.Z_*`
  archives, but releases ship `phoenix_X.Y.Z_*`, so every install 404'd.
  It now hard-fails when it cannot verify the checksum, honours an explicit
  `INSTALL_DIR`, and accepts `PHOENIX_BASE_URL` for mirrors.
- **Docker first run works.** `--init /data` no longer fails with
  "permission denied"; `/data` is owned by the runtime user. The healthcheck
  follows TLS, `latest` no longer moves on `-rc` tags, and a new
  `.dockerignore` keeps local keys out of the build context.
- **New [Quickstart](docs/quickstart.md)**: binary and Docker paths in about
  two minutes, checked by `scripts/quickstart-smoke.sh`.

### Safer Store and Master Key Writes

- **Power-loss safe writes.** The store file and every master key file are
  now written with fsync before and after the rename, so a crash leaves the
  whole old file or the whole new file, never a truncated one.
- **Key rotation keeps a working backup.** The `.pre-rotate` backup is now
  taken from memory just before rotation, so a failed rotation followed by
  a retry can no longer replace the good backup with an unreadable one.
- **No unprotected emergency key.** When a rotation cannot finish, the
  `<store>.emergency-key` file is written only if the master key is
  passphrase-protected, and it is encrypted with that passphrase. Without a
  passphrase Phoenix no longer writes the new key to disk.
- **Recovery steps** for a failed rotation are in
  [Key management](docs/key-management.md#if-rotation-fails).

**Upgrading:** no action required.

## v0.17.1 (2026-10-25)

### Hidden Prompt for `phoenix set`

Adding a secret by hand no longer means putting it on the command line.

- **`phoenix set <path>` with no value now prompts with input hidden**
  when run in a terminal, like `ssh-keygen` or `sudo`. The value never
  reaches shell history, process listings, or the screen. Surrounding
  whitespace is trimmed (clipboard copies often carry a stray newline),
  and a masked preview (`Received 32 chars: sk-p…WXYZ`) confirms the
  right thing was pasted.
- **`--multiline`** for PEM keys and certs: paste the block with input
  hidden and finish with Ctrl-D. Nothing is written to disk, and Ctrl-C
  cancels cleanly with the terminal restored.
- **Docs** no longer show `echo "secret" | phoenix set ...` or `-v` as the
  way to store a secret; both leave it in shell history.

**Upgrading:** no action required. `-v` and `--value-stdin` behave exactly
as before, and scripts without a terminal still get the usage error rather
than a prompt.

## v0.17.0 (2026-08-20)

### Secure Transport: LAN-Scoped by Design, Loud When It Matters

Phoenix is **LAN-scoped by design**. Use outside a LAN — internet/WAN
exposure, public ingress, hostile-network operation — is out of scope and
unsupported. Being in scope is not the same as being trusted: a LAN
includes containers on shared bridges, IoT devices, and anything that has
compromised one host, so TLS matters whenever a request crosses a wire.

Plaintext on loopback remains the default and is unchanged. Loopback
traffic never reaches a network interface, so TLS adds nothing there.

- **New first-class `tls:` config block**, independent of `mtls:`. TLS
  serving previously existed only inside the mTLS block, so operators had
  to enable client-certificate authentication just to obtain HTTPS.
  `"tls": {"enabled": true}` now works on its own, defaulting to the
  server leaf certificate that `--init` already generates. `mtls:` is now
  purely the client-certificate layer.
- **Loud warning on insecure transport.** Binding a non-loopback address
  without TLS previously produced no signal at all — a one-line config
  change silently moved bearer tokens and secret values onto the wire.
  The server now prints a prominent startup banner naming exactly what is
  exposed and the one-line fix. It warns; it never refuses to start.
- **TLS for the MCP HTTP transport** — `phoenix mcp-server --http` gains
  `--tls-cert`/`--tls-key` (or `PHOENIX_MCP_TLS_CERT`/`PHOENIX_MCP_TLS_KEY`),
  and carries the same warning on plaintext non-loopback binds.
- **Client-side warnings** in the CLI and Go SDK for non-loopback
  `http://` server URLs. Warn and proceed; never fail.
- **Docs**: `docs/threat-model.md` gains a deployment-envelope section and
  its mitigations were re-audited against that envelope;
  `docs/lan-deployment.md` is rewritten onto the `tls:` block with mTLS as
  a separate optional step. No silent non-loopback `http://` examples
  remain anywhere in the docs.
- **New e2e scenario 19** covering transport behavior.

**Upgrading:** no action required. Existing configs behave identically,
including `auth.mtls.enabled: true`, which still implies TLS. If you bind
a non-loopback address without TLS you will now see a startup warning —
that is the point, and the fix is one line.

## v0.16.0 (2026-08-16)

### Hermes Caller Metadata Audit Capture

- Captures the sanitized `X-Hermes-Profile`, `X-Hermes-Session-Id`,
  `X-Hermes-Channel`, `X-Hermes-Tool`, and `X-Hermes-Task-Id` headers as
  audit-only metadata under `hermes.*` keys, for the `hermes-phoenix` plugin.
- Generalized the OpenClaw-specific header table into a single
  platform-neutral caller-metadata allowlist. The OpenClaw family, its
  `openclaw.*` audit keys, the 256-byte cap, and the sanitization rules are
  unchanged.
- The allowlist stays compiled in rather than operator-configurable, so no
  configuration change can route a credential header into the audit log.
- `X-Phoenix-Tool` remains an attestation policy input and is never recorded
  as caller metadata; the audit-only `X-Hermes-Tool` hint cannot satisfy
  `allowed_tools`.
- Added unit coverage for Hermes capture, absent headers, oversize/control
  sanitization, ACL and attestation spoof resistance, both families on one
  request, and an allowlist self-check that rejects credential-bearing or
  `X-Phoenix-*` entries. Added e2e scenario 20.
- `GET /v1/secrets` list responses now return `"paths": []` instead of
  `"paths": null` when no paths are visible.

> `v0.16.0` is the minimum Phoenix version for `hermes-phoenix` first-class
> audit metadata. Older servers ignore the `X-Hermes-*` family entirely.

## v0.15.2 (2026-07-12)

### OpenClaw Exec Provider Merge-Review Fixes

- Session mint with `PHOENIX_ROLE` no longer fails when the home directory
  cannot be determined and no `PHOENIX_SEAL_KEY` is set; the CLI now mints an
  unsealed session, matching the missing-key-file behavior.
- The exec provider short-circuits an empty `ids` list to an empty response
  without calling the resolve API.
- The exec provider rejects trailing non-whitespace data after the stdin JSON
  request object.
- Audit metadata sanitization now strips Unicode format/bidi control
  characters (category Cf, e.g. U+202E) from `X-OpenClaw-*` header values.
- Added tests for the sealed-envelope decrypt branch, non-200 server
  responses in the exec-provider path, missing-HOME session mint, and
  format-control sanitization.
- Documented the three exec-provider auth modes (bootstrap token + role,
  mTLS + role, pre-minted session token) and the invalid combinations,
  added `HOME` to the recommended `passEnv` example, documented the
  audit-only `X-OpenClaw-*` metadata headers, and noted that signed resolve
  is not supported in the exec-provider path. `phoenix openclaw-exec-provider`
  is now documented as the canonical command form.

## v0.15.1 (2026-06-17)

### OpenClaw Audit Metadata

- Captures sanitized allowlisted `X-OpenClaw-*` metadata headers on server audit entries as audit hints only.
- Omits raw `X-OpenClaw-Session-Key` from audit records.
- Added tests proving spoofed OpenClaw headers do not affect Phoenix authorization, attestation policy identity, or sealed-response policy decisions.

## v0.15.0 (2026-04-27)

### OpenClaw SecretRef Exec Provider

- Added `phoenix openclaw-exec-provider` for OpenClaw's built-in exec SecretRef provider protocol.
- Added `phoenix secret-provider openclaw` and `phoenix resolve --stdin-json` aliases for compatibility with OpenClaw exec-provider configuration.
- The provider reads OpenClaw's stdin JSON request, resolves requested ids through Phoenix using the existing auth/session/mTLS/sealed-response paths, and writes OpenClaw-compatible `values`/`errors` JSON to stdout.
- Added tests for request parsing, stdout response shape, id normalization, and partial per-id failures.
- Updated OpenClaw integration docs to distinguish bootstrap/config SecretRefs from runtime `openclaw-phoenix` plugin tools, and to stop claiming plain `phoenix resolve <ref>` is the exec-provider protocol.

## v0.13.5 (2026-04-07)

### Step-Up Authorization Hygiene

- Fixed step-up authorization semantics so approved step-up sessions can
  temporarily grant access beyond the base agent ACL when the role is
  explicitly configured with `elevates_acl: true`.
- Fixed elevated step-up session renewal so temporary ACL elevation cannot be
  extended transparently; elevated sessions now require a fresh mint and human
  approval to continue.
- Preserved path policy, attestation, seal-key binding, expiry, and revocation
  enforcement for elevated step-up sessions.
- Added targeted API/session tests covering elevated access, revocation,
  expiry, non-step-up ACL behavior, policy/seal-key enforcement, and
  reapproval-required renewal behavior.
- Updated session/auth/API docs and SDK approval classification for the new
  `STEP_UP_REAPPROVAL_REQUIRED` denial path.

## v0.13.4 (2026-04-04)

### Stabilization Fixes

- Fixed CLI role-session cache reuse so repeated `PHOENIX_ROLE` invocations
  reuse valid cached sessions and only renew near expiry instead of minting
  fresh sessions unnecessarily.
- Fixed role-bound sealed sessions so requests consistently use the same seal
  key resolution path as session minting, including
  `~/.phoenix/session-seal-<role>.key`.
- Fixed `phoenix list` and adjacent sealed request paths to send
  `X-Phoenix-Seal-Key` when using sealed role sessions.
- Added sealed-success audit metadata so allowed sealed reads and resolves are
  distinguishable from plaintext success paths.
- `phoenix policy show` now displays `require_sealed`.
- Clarified `phoenix keypair generate -o` as a file path, with fast failure for
  directory-style output values.
- Fixed dashboard template rendering so page-specific `content` blocks do not
  collide across pages.

## v0.13.3 (2026-03-20)

### Session Identity

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

### MCP Streamable HTTP Transport

The MCP server now supports Streamable HTTP in addition to stdio:

```bash
phoenix mcp-server --http 127.0.0.1:8080 --mcp-token <token>
```

Endpoint: `/mcp`. Auth via `Authorization: Bearer <mcp-token>`. Tool identity
headers carry through for policy evaluation.

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
