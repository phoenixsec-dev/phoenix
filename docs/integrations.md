# Phoenix Secrets — Integrations

## MCP server (Claude Code / Claude Desktop)

Phoenix includes a built-in MCP server.

Transport options:
- `phoenix mcp-server` → stdio JSON-RPC
- `phoenix mcp-server --http :8080 --mcp-token <token>` → Streamable HTTP on `/mcp`

Example Claude MCP config:

```json
{
  "mcpServers": {
    "phoenix": {
      "command": "phoenix",
      "args": ["mcp-server"],
      "env": {
        "PHOENIX_SERVER": "https://phoenix:9090",
        "PHOENIX_TOKEN": "..."
      }
    }
  }
}
```

Streamable HTTP mode example:

```bash
export PHOENIX_SERVER="https://phoenix:9090"
export PHOENIX_TOKEN="<phoenix-agent-token>"
export PHOENIX_MCP_TOKEN="<separate-mcp-client-token>"
phoenix mcp-server --http 127.0.0.1:8080
```

Tool identity headers let policy control which MCP tools may access which paths.

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
phoenix resolve --stdin-json
# equivalent aliases:
phoenix openclaw-exec-provider
phoenix secret-provider openclaw
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
        args: ["resolve", "--stdin-json"],
        passEnv: [
          "PHOENIX_SERVER",
          "PHOENIX_TOKEN",
          "PHOENIX_ROLE",
          "PHOENIX_CA_CERT",
          "PHOENIX_CLIENT_CERT",
          "PHOENIX_CLIENT_KEY",
          "PHOENIX_SEAL_KEY",
          "PHOENIX_TOOL"
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

Set Phoenix credentials for the OpenClaw process. Prefer scoped role/session or
mTLS credentials over a broad admin token:

```bash
export PHOENIX_SERVER=https://phoenix:9090
export PHOENIX_TOKEN=<bootstrap-or-session-token>
export PHOENIX_ROLE=openclaw-gateway
# Or use mTLS:
export PHOENIX_CA_CERT=/etc/phoenix/ca.crt
export PHOENIX_CLIENT_CERT=/etc/phoenix/openclaw.crt
export PHOENIX_CLIENT_KEY=/etc/phoenix/openclaw.key
```

`PHOENIX_ROLE`, mTLS, sealed responses, session auto-mint/renewal, and Phoenix
attestation headers are handled by the same CLI auth paths as `phoenix resolve`.
Plain `phoenix resolve <ref>` remains the general human/script command; use
`phoenix resolve --stdin-json` for OpenClaw's stdin/stdout provider protocol.

### 2. Plugin tools for agent/tool runtime access

Use the separate `openclaw-phoenix` plugin for agent/tool-time workflows:

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

For mTLS instead of bearer tokens, mount certs into the OpenClaw container and set
`PHOENIX_CA_CERT`, `PHOENIX_CLIENT_CERT`, and `PHOENIX_CLIENT_KEY`.

## Go SDK

The Go SDK is included in the repository at `sdk/go/phoenix/`.

```go
import "github.com/phoenixsec/phoenix/sdk/go/phoenix"

// Basic client
client := phoenix.New("https://phoenix:9090", "token")
val, err := client.Resolve("phoenix://myapp/api-key")
vals, err := client.ResolveBatch([]string{
    "phoenix://myapp/openai-key",
    "phoenix://myapp/db-password",
})

// Session identity
client, err := phoenix.NewWithRole("https://phoenix:9090", "bootstrap-token", "dev")
// Auto-mints a session; non-elevated sessions auto-renew before expiry

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
    if perr.IsApprovalRequired() { /* needs human */ }
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
