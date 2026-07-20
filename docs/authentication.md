# Phoenix Secrets — Authentication

Phoenix supports bearer tokens, mTLS client certificates, and sealed-response key
pairs. These can be combined — mTLS for identity, bearer for bootstrap, sealed keys
for context-safe delivery.

## Bearer tokens

Create an agent with scoped permissions:

```bash
phoenix agent create deployer \
  -t "deploy-token-abc" \
  --acl "myapp/**:read;staging/**:read,write"
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
exposing nested sub-trees. If an agent with `ns/*:read` is denied on
`ns/sub/key`, that is why: use `ns/**:read` for namespace-wide access.

The same pattern semantics apply to policy path patterns
([Policy and Attestation](policy-and-attestation.md)) and session role
namespaces ([Session Identity](session-identity.md)).

## Mutual TLS (recommended)

Issue a client certificate for an agent:

```bash
phoenix cert issue deployer -o /etc/phoenix/certs/
```

This writes `deployer.crt`, `deployer.key`, and `ca.crt`.

```bash
export PHOENIX_SERVER="https://phoenix.home:9090"
export PHOENIX_CA_CERT="/etc/phoenix/certs/ca.crt"
export PHOENIX_CLIENT_CERT="/etc/phoenix/certs/deployer.crt"
export PHOENIX_CLIENT_KEY="/etc/phoenix/certs/deployer.key"

phoenix get myapp/db-password
```

No bearer token is required when the cert identifies the agent.

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
actions. Non-elevated sessions auto-renew, and sessions can be revoked
individually. Elevated step-up sessions require fresh approval to extend.

Do not combine `PHOENIX_ROLE` with a pre-minted `phxs_` session token in
`PHOENIX_TOKEN`: role mode always re-mints a session, and a session token is
rejected as bootstrap auth. Use a bootstrap token (or mTLS) with
`PHOENIX_ROLE`, or a `phxs_` token alone without `PHOENIX_ROLE`.

Auth priority order: session token > mTLS > short-lived token > bearer.

See [Session Identity](session-identity.md) for full details on roles,
step-up approval, and configuration.

## CLI environment variables

| Variable | Description |
|----------|-------------|
| `PHOENIX_SERVER` | Server URL (default: `http://127.0.0.1:9090`) |
| `PHOENIX_TOKEN` | Bearer token |
| `PHOENIX_CA_CERT` | CA certificate for TLS verification |
| `PHOENIX_CLIENT_CERT` | Client certificate for mTLS |
| `PHOENIX_CLIENT_KEY` | Client key for mTLS |
| `PHOENIX_SEAL_KEY` | Seal private key file path |
| `PHOENIX_ROLE` | Role name for auto-mint session identity |
| `PHOENIX_POLICY` | Policy file path for local `phoenix policy` commands |
| `PHOENIX_OP_TOKEN_ENV` | Import-only env var name holding 1Password token |

## Dashboard auth (separate surface)

The operator dashboard (`/dashboard/`) uses its own authentication — it does
**not** use bearer tokens, mTLS, or session tokens. Instead, it uses a shared
password or PIN with cookie-based sessions.

This is intentional: the dashboard is a human operator interface, not an agent
interface. The API auth model (bearer, mTLS, session tokens) is designed for
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
