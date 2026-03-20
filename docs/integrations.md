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

## OpenClaw exec backend

Configure Phoenix as an external secrets provider through OpenClaw's exec backend:

```json
{
  "secrets": {
    "providers": {
      "phoenix": {
        "type": "exec",
        "command": "phoenix",
        "args": ["resolve"]
      }
    }
  }
}
```

Use SecretRefs backed by Phoenix:

```yaml
api_keys:
  openai: ${{ secrets.phoenix.phoenix://myapp/openai-key }}
  anthropic: ${{ secrets.phoenix.phoenix://myapp/anthropic-key }}
```

Set Phoenix credentials for the OpenClaw process:

```bash
export PHOENIX_SERVER=https://phoenix:9090
export PHOENIX_TOKEN=openclaw-agent-token
# Or use mTLS:
export PHOENIX_CA_CERT=/etc/phoenix/ca.crt
export PHOENIX_CLIENT_CERT=/etc/phoenix/openclaw.crt
export PHOENIX_CLIENT_KEY=/etc/phoenix/openclaw.key
```

Validate before deploying:

```bash
phoenix verify --dry-run gateway-config.yaml
phoenix policy test --agent openclaw --ip 10.0.0.5 myapp/openai-key
```

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
// Auto-mints a session; auto-renews before expiry

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
