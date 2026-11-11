# Phoenix Secrets — Integrations

## MCP server (Claude Code / Claude Desktop)

Phoenix includes a built-in MCP server.

The MCP server speaks JSON-RPC over stdio (`phoenix mcp-server`), started by
the agent's harness. (MCP over HTTP, `--http`, was removed.)

`https://` server URLs below assume the Phoenix server has `https_listener`
enabled (port 9443 by default) and clients trust the CA via
`PHOENIX_CA_CERT` — see [LAN Deployment](lan-deployment.md).

Example Claude MCP config:

```json
{
  "mcpServers": {
    "phoenix": {
      "command": "phoenix",
      "args": ["mcp-server"],
      "env": {
        "PHOENIX_SERVER": "https://phoenix:9443",
        "PHOENIX_CA_CERT": "/etc/phoenix/certs/ca.crt",
        "PHOENIX_TOKEN": "..."
      }
    }
  }
}
```

> By default, `phoenix_get` and `phoenix_resolve` can return plaintext tool output.
> With sealed mode (`PHOENIX_SEAL_KEY`) they return opaque `PHOENIX_SEALED:` tokens
> instead. See [Sealed Responses](sealed-responses.md).

## Claude Code skill

Phoenix includes a reusable skill at `phoenix-skill/SKILL.md` for command-driven
integration without running MCP mode.

## OpenClaw

Phoenix supports two complementary OpenClaw integration paths. They solve different
problems and should be used together for a production deployment.

### 1. Built-in SecretRefs for bootstrap/config secrets

Use OpenClaw's built-in `{ source: "exec", provider, id }` SecretRefs for secrets
that OpenClaw must resolve while loading gateway/runtime configuration: gateway auth
tokens, model provider API keys, channel bot tokens, webhook secrets, and similar
startup configuration.

Phoenix provides an OpenClaw-compatible exec provider command:

```bash
phoenix openclaw-exec-provider
```

This command reads OpenClaw's exec-provider JSON request from stdin:

```json
{"protocolVersion":1,"provider":"phoenix","ids":["openclaw/shared/openai-api-key"]}
```

and writes OpenClaw's expected JSON response to stdout:

```json
{"protocolVersion":1,"values":{"openclaw/shared/openai-api-key":"..."}}
```

Per-id failures are returned under `errors` without logging or printing secret
values.

Configure the provider in OpenClaw with the Phoenix binary path available to the
OpenClaw process:

```json5
{
  secrets: {
    providers: {
      phoenix: {
        source: "exec",
        command: "/usr/local/bin/phoenix",
        args: ["openclaw-exec-provider"],
        passEnv: [
          "HOME",
          "PHOENIX_SERVER",
          "PHOENIX_TOKEN",
          "PHOENIX_ROLE",
          "PHOENIX_CA_CERT",
          "PHOENIX_SEAL_KEY"
        ],
        timeoutMs: 10000
      }
    },
    defaults: {
      exec: "phoenix"
    }
  }
}
```

Passing `HOME` lets the CLI find per-role session seal keys under `~/.phoenix/`
(optional — without it the CLI mints unsealed sessions — but recommended).

The provider config key must be named exactly `phoenix` — the Phoenix CLI
validates the `provider` field it receives and rejects any other name.

Then use OpenClaw SecretRef objects in fields that support secrets:

```json5
{
  providers: {
    openai: {
      apiKey: { source: "exec", provider: "phoenix", id: "openclaw/shared/openai-api-key" }
    }
  },
  gateway: {
    auth: {
      token: { source: "exec", provider: "phoenix", id: "openclaw/gateway/auth-token" }
    }
  }
}
```

The exec provider accepts ids either as Phoenix paths (`openclaw/shared/key`) or as
full refs (`phoenix://openclaw/shared/key`). It normalizes paths to Phoenix refs for
resolution, but the stdout `values`/`errors` keys match OpenClaw's input ids.

Set Phoenix credentials for the OpenClaw process. There are two valid auth
modes — pick exactly one:

**(a) Role auto-mint with a bootstrap token** — the CLI uses the bootstrap token
to mint a short-lived session for the role:

```bash
export PHOENIX_SERVER=https://phoenix:9443
export PHOENIX_CA_CERT=/etc/phoenix/ca.crt
export PHOENIX_TOKEN=<bootstrap-token>   # NOT a phxs_... session token
export PHOENIX_ROLE=openclaw-gateway
```

**(b) Pre-minted session token** — mint a session out of band and hand the
`phxs_...` token to the process directly:

```bash
export PHOENIX_SERVER=https://phoenix:9443
export PHOENIX_CA_CERT=/etc/phoenix/ca.crt
export PHOENIX_TOKEN=<phxs_session-token>
# Do NOT set PHOENIX_ROLE in this mode.
```

Combinations that do not work:

- `PHOENIX_ROLE` + `PHOENIX_TOKEN=phxs_...` — role mode always re-mints a
  session, and a session token is rejected as bootstrap auth.
- A `phxs_...` session token past its expiry — pre-minted tokens are not
  renewed by the exec provider; use role auto-mint for long-running processes.

Sealed responses and session auto-mint/renewal are handled by the same CLI
auth paths as `phoenix resolve`. Plain `phoenix resolve <ref>` remains the
general human/script command; use `phoenix openclaw-exec-provider` for
OpenClaw's stdin/stdout provider protocol.

### Audit-only OpenClaw metadata headers

The server records five `X-OpenClaw-*` headers as untrusted audit hints. See
[Caller metadata audit headers](#caller-metadata-audit-headers) for the full
list and the guarantees that apply to it.

### 2. Plugin tools for agent/tool runtime access

Use the separate [`openclaw-phoenix`](https://github.com/phoenixsec-dev/openclaw-phoenix) plugin for agent/tool-time workflows:

- `phoenix_resolve` for Phoenix-aware runtime resolution
- `phoenix_list` for listing visible paths
- `phoenix_status` for health/connectivity checks
- sealed-response and approval-aware UX as the plugin evolves

The plugin enhances OpenClaw runtime capabilities, but it does not replace built-in
SecretRef resolution for bootstrap/core config. Installing the plugin alone does not
make startup fields resolve through Phoenix; configure the exec provider above for
that.

### Migration from `.env` or plaintext OpenClaw config

1. Import or set secrets in Phoenix under a stable namespace, for example
   `openclaw/shared/openai-api-key` and `openclaw/gateway/auth-token`.
2. Create a scoped Phoenix identity for OpenClaw with read access only to the paths
   it needs.
3. Add the OpenClaw `secrets.providers.phoenix` exec provider config shown above.
4. Replace plaintext strings in OpenClaw config with `{ source: "exec", provider:
   "phoenix", id: "..." }` SecretRefs where OpenClaw supports secret inputs.
5. Restart or reload OpenClaw and verify resolution. Keep plaintext fallback values
   out of committed config.

### Containerized deployment (Docker Compose)

In Docker or Compose, Phoenix can run as a sidecar or network-adjacent service.
Mount or install the `phoenix` binary into the OpenClaw container and pass only the
Phoenix environment variables needed by the exec provider.

```yaml
services:
  phoenix:
    image: phoenixsecdev/phoenix:latest
    volumes:
      - phoenix-data:/data/phoenix

  openclaw:
    image: ghcr.io/openclaw/openclaw:latest
    environment:
      # Plaintext http:// is acceptable here ONLY because this traffic stays
      # on the single-host Compose default network (no published Phoenix
      # port, nothing crosses a physical wire). The Phoenix CLI still prints
      # a plaintext warning for this non-loopback URL — expected in this
      # topology. If Phoenix publishes a port or the network spans hosts,
      # turn on the server's https_listener and switch to https:// with
      # PHOENIX_CA_CERT (see the HTTPS variant below).
      PHOENIX_SERVER: "http://phoenix:9090"
      PHOENIX_TOKEN: "${OPENCLAW_PHOENIX_TOKEN}"
      PHOENIX_ROLE: "openclaw-gateway"
    volumes:
      - ./openclaw-config:/config
      - /usr/local/bin/phoenix:/usr/local/bin/phoenix:ro
    depends_on:
      - phoenix

volumes:
  phoenix-data:
```

HTTPS variant — set `"https_listener": {"enabled": true}` in the Phoenix config
(`--init` already wrote its `0.0.0.0:9443` listen address and certificate
paths), then:

```yaml
  openclaw:
    environment:
      PHOENIX_SERVER: "https://phoenix:9443"
      PHOENIX_CA_CERT: "/etc/phoenix/ca.crt"
      PHOENIX_TOKEN: "${OPENCLAW_PHOENIX_TOKEN}"
      PHOENIX_ROLE: "openclaw-gateway"
    volumes:
      - phoenix-data:/etc/phoenix:ro   # or copy just ca.crt
```

The `--init` server certificate covers `localhost`/`127.0.0.1` only; for the
`phoenix` service hostname, re-issue it once with
`phoenix-server --reissue-cert --san phoenix --config /data/phoenix/config.json`.

## Caller metadata audit headers

An agent platform can label its Phoenix requests so an audit entry can be traced
back to the conversation, task, or tool that triggered it. The server captures
one fixed header family per supported platform:

| Header | Audit metadata key |
|---|---|
| `X-OpenClaw-Agent` | `openclaw.agent` |
| `X-OpenClaw-Session-Id` | `openclaw.session_id` |
| `X-OpenClaw-Channel` | `openclaw.channel` |
| `X-OpenClaw-Requester-Sender` | `openclaw.requester_sender` |
| `X-OpenClaw-Sender-Is-Owner` | `openclaw.sender_is_owner` |
| `X-Hermes-Profile` | `hermes.profile` |
| `X-Hermes-Session-Id` | `hermes.session_id` |
| `X-Hermes-Channel` | `hermes.channel` |
| `X-Hermes-Tool` | `hermes.tool` |
| `X-Hermes-Task-Id` | `hermes.task_id` |

The `hermes-phoenix` plugin emits the `X-Hermes-*` family. Both families may
appear on the same request; they do not interact.

**These values are untrusted and audit-only.** Any caller can set them to
anything, so treat them as labels, not identity:

- They have zero effect on authentication, ACL authorization, attestation
  policy, session identity, role mapping, or sealed-response decisions.
  Spoofing them cannot elevate access.
- The audited actor is always the authenticated Phoenix agent. A spoofed
  `X-Hermes-Profile: admin` is recorded as a hint under `hermes.profile` while
  the `agent` field stays whatever the credential proved.
- The list above is exhaustive. Any other header — including other `X-Hermes-*`
  or `X-OpenClaw-*` names — is ignored entirely.
- Session keys (`X-OpenClaw-Session-Key`) are credentials. They are deliberately
  never captured and never written to audit logs.
- Each value is sanitized (format characters removed, control characters
  converted to spaces, whitespace collapsed) and capped at 256 bytes. Values
  that sanitize to empty are dropped rather than stored blank.

`X-Phoenix-Tool` is **not** part of this mechanism and is ignored. It used to feed
the `allowed_tools`/`deny_tools` policy rules, which were removed because the
caller sets the header itself. It is never recorded as caller metadata.

Adding a platform is a code change to the allowlist in `internal/api/api.go`,
not configuration — an operator cannot map arbitrary headers, so a credential
header can never be routed into the audit log by misconfiguration.

## Go SDK

The Go SDK is included in the repository at `sdk/go/phoenix/`.

```go
import "github.com/phoenixsec/phoenix/sdk/go/phoenix"

// Basic client
client := phoenix.New("https://phoenix:9443", "token")
val, err := client.Resolve("phoenix://myapp/api-key")
vals, err := client.ResolveBatch([]string{
    "phoenix://myapp/openai-key",
    "phoenix://myapp/db-password",
})

// Session identity
client, err := phoenix.NewWithRole("https://phoenix:9443", "bootstrap-token", "dev")
// Auto-mints a session; it auto-renews before expiry

// Sealed mode
client.SetSealKey("/path/to/agent.seal.key")

// Session management
sessions, _ := client.ListSessions()
client.RevokeSession("ses_abc123")

// Error classification
var perr *phoenix.Error
if errors.As(err, &perr) {
    if perr.IsSessionExpired()   { /* re-mint */ }
    if perr.IsScopeExceeded()    { /* wrong role */ }
}
```

## Python SDK

> **Note:** The `phoenix-secrets` package is not yet published to PyPI.
> For now, use the source at `sdk/python/` or call the API directly.

```python
from phoenix_secrets import PhoenixClient

client = PhoenixClient()
api_key = client.resolve("phoenix://myapp/api-key")
result = client.resolve_batch([
    "phoenix://myapp/openai-key",
    "phoenix://myapp/db-password",
])
check = client.verify(["phoenix://myapp/api-key"])
client.health()
```

## Direct API

```bash
curl -X POST $PHOENIX_SERVER/v1/resolve \
  -H "Authorization: Bearer $PHOENIX_TOKEN" \
  -d '{"refs": ["phoenix://myapp/api-key"]}'

curl $PHOENIX_SERVER/v1/secrets/myapp/api-key \
  -H "Authorization: Bearer $PHOENIX_TOKEN"
```

## Related docs

- [Sealed Responses](sealed-responses.md)
- [Multi-Agent Setup](multi-agent-setup.md)
- [API Reference Index](api-reference-index.md)
- [Runnable Examples](../examples/README.md)
