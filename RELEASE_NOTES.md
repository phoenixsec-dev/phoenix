# Release Notes

## Unreleased

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
