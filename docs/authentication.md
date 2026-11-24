# Phoenix Secrets — Authentication

Agents log in with a bearer token, usually to mint a short-lived session for
a role. Sealed-response key pairs add context-safe delivery on top. (Client
certificates (mTLS) and short-lived attestation tokens were removed.)

**Transport is separate from authentication.** HTTPS comes from the server's
`https_listener` block; bearer and session tokens work the same over it.
Whenever requests cross a wire, use HTTPS so tokens and secret values are
encrypted in transit. See
[Configuration](configuration.md#transport-security) and
[LAN Deployment](lan-deployment.md).

## Bearer tokens

Create an agent with scoped permissions:

```bash
phoenix agent create deployer \
  -t "deploy-token-abc" \
  --acl "myapp/**:list,read_value;staging/**:list,read_value,write"
```

The `deployer` agent can read anything under `myapp/` and read/write under `staging/`,
including nested paths.

### ACL path patterns

ACL paths are glob patterns matched against secret paths:

| Pattern | Matches |
|---------|---------|
| `myapp/db-password` | exactly that path |
| `myapp/*` | one level under `myapp/` (`myapp/db-password`, but **not** `myapp/gateway/auth-token`) |
| `myapp/**` | everything under `myapp/`, at any depth |
| `*` | every path |

`/*` is single-level by design — it grants the top of a namespace without
exposing nested sub-trees. If an agent with `ns/*:read_value` is denied on
`ns/sub/key`, that is why: use `ns/**:read_value` for namespace-wide access.

The same pattern semantics apply to policy path patterns
([Policy and Attestation](policy-and-attestation.md)) and session role
namespaces ([Session Identity](session-identity.md)).

## Who, authority and kind

An identity has a name, and may carry four labels beside it:

| Field | Says | Example |
|-------|------|---------|
| `who` | who uses it; leave empty for a service | `robin` |
| `authority` | the role it acts in | `night-desk` |
| `kind` | what sort of caller it is | `agent`, `service`, `person` |
| `formerly` | older names of this identity | `old-deployer` |

```bash
phoenix agent set deployer --who robin --authority night-desk --kind agent --formerly old-deployer
phoenix agent show deployer
phoenix whoami                 # an agent sees its own
```

- **The words are yours.** Phoenix has no list of allowed values. Up to 64
  characters, no control or invisible characters.
- **They grant nothing.** Access is the permissions, as before. Setting them
  needs admin, and changes neither the token nor any session.
- **Only an admin sets them.** Nothing a caller sends (header, query or body) can
  change what is recorded about it.
- **Every audit line shows them** as they were when the caller made the request,
  with `host` and `attested` beside them, also when a line about an access
  request or grant has to be written later. Older lines stay as written.
- **`attested` is `false` for a token,** and for a role session made from one: a
  token works for whoever holds it, so its `who` and `authority` are only
  *declared*. A line about a refused credential, the dashboard or Phoenix itself
  has none of them.
- **`host` is empty for a token.** It is only for a machine Phoenix has itself
  established.
- **`formerly`** lets a log search for an identity also find the lines written
  under its older names. A name with a comma can be set only through the API (`phoenix audit --agent`, the dashboard's agent filter).
  To rename: make the new identity with `--formerly <old>`, move its users over,
  and delete the old one.

Each identity also has a `serial` in the ACL file, made by the server and never
shown. It tells an identity apart from a later one with the same name, and stays
when the token is replaced; `credential_id` is per token and changes with it.
Identities from before v0.25.0 get one at the next change to any agent. Do not
copy or edit either by hand.

An older server reads an ACL file with these fields, but drops them at the first
change it saves.

## Sealed-response key pairs

When `PHOENIX_SEAL_KEY` points to a local private key file, Phoenix clients can:
- send the matching seal public key to the server
- receive sealed secret payloads instead of plaintext
- decrypt locally

This is especially important for MCP and multi-agent same-host workflows.
See [Sealed Responses](sealed-responses.md) and [Multi-Agent Setup](multi-agent-setup.md).

## Session identity (recommended for agents)

Session tokens replace static bearer tokens with short-lived, scoped credentials.
An agent authenticates once with a bootstrap token and receives a session token
bound to a named role.

```bash
export PHOENIX_TOKEN="bootstrap-token"
export PHOENIX_ROLE="dev"
phoenix get dev/api-key  # auto-mints session, then reads secret
```

Session tokens use a `phxs_` prefix and are scoped to specific namespaces and
actions. Sessions auto-renew and can be revoked individually. Deleting an agent
or replacing its token ends its sessions.

Do not combine `PHOENIX_ROLE` with a pre-minted `phxs_` session token in
`PHOENIX_TOKEN`: role mode always re-mints a session, and a session token is
rejected as bootstrap auth. Use a bootstrap token with
`PHOENIX_ROLE`, or a `phxs_` token alone without `PHOENIX_ROLE`.

Auth order: a `phxs_` token is checked as a session, anything else as a bearer
token.

See [Session Identity](session-identity.md) for full details on roles and
configuration. For temporary human-approved access to more paths, see
[Access Requests](access-requests.md).

## CLI environment variables

| Variable | Description |
|----------|-------------|
| `PHOENIX_SERVER` | Server URL (default: `http://127.0.0.1:9090`) |
| `PHOENIX_TOKEN` | Bearer token |
| `PHOENIX_CA_CERT` | CA certificate for HTTPS verification (the server's `ca.crt`). If it is set but cannot be used, HTTPS requests fail |
| `HTTPS_PROXY`, `NO_PROXY` | Standard proxy settings for an `https://` server; used with and without `PHOENIX_CA_CERT`. If the proxy's own address is `https://`, its CA must be in the `PHOENIX_CA_CERT` file too; whoever holds that CA can then also pose as the Phoenix server, so only add one you trust that far. Once the `PHOENIX_CA_CERT` file is loaded, a plain `http://` server is reached directly |
| `PHOENIX_ALLOW_PLAINTEXT` | Hosts (comma-separated) to skip the plaintext `http://` warning for; see [LAN deployment](lan-deployment.md#plaintext-on-a-single-host-opt-out) |
| `PHOENIX_SEAL_KEY` | Seal private key file path |
| `PHOENIX_ROLE` | Role name for auto-mint session identity |
| `PHOENIX_POLICY` | Policy file path for local `phoenix policy` commands |
| `PHOENIX_OP_TOKEN_ENV` | Import-only env var name holding 1Password token |

`PHOENIX_CLIENT_CERT` and `PHOENIX_CLIENT_KEY` are ignored (client
certificates were removed); the CLI prints a warning when they are set.
`PHOENIX_TOOL` is gone too. `phoenix exec` removes every `PHOENIX_*`
variable, `OP_SERVICE_ACCOUNT_TOKEN`, and the variable named by
`PHOENIX_OP_TOKEN_ENV` from the environment of the command it runs.

## Dashboard auth (separate surface)

The operator dashboard (`/dashboard/`) uses its own authentication — it does
**not** use bearer tokens or session tokens. Instead, it uses a shared
password (bcrypt hash in config) with cookie-based sessions.

This is intentional: the dashboard is a human operator interface, not an agent
interface. The API auth model (bearer and session tokens) is designed for
programmatic access with per-agent identity. The dashboard auth model is
designed for browser access with shared-credential simplicity.

See [Dashboard](dashboard.md) for the full security model, deployment
requirements, and threat analysis.

## Related docs

- [Getting Started](getting-started.md)
- [Session Identity](session-identity.md)
- [Dashboard](dashboard.md)
- [Policy and Attestation](policy-and-attestation.md)
- [Sealed Responses](sealed-responses.md)
- [Admin Token Lifecycle](admin-token-lifecycle.md)
