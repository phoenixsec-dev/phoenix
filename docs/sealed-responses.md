# Sealed Responses

Sealed responses add end-to-end encryption between the Phoenix server and
individual agents. When sealed mode is enabled, secret values are encrypted
with NaCl box (X25519 + XSalsa20-Poly1305) to the requesting agent's public
key before leaving the server. Only the agent holding the corresponding
private key can decrypt.

## What sealed responses protect

- **Network observers** cannot read secret values, even with TLS terminated
  at a reverse proxy.
- **Shared-host agents** on the same machine each get values encrypted to
  their own key pair — one agent cannot read another's responses.
- **MCP tool output** contains opaque `PHOENIX_SEALED:...` tokens instead
  of plaintext, so values are not exposed in tool response text.

## What sealed responses do NOT protect

- If an agent's seal private key is compromised, all sealed values sent to
  that key are compromised.
- Sealed mode does not protect against a compromised agent process — once
  decrypted, the agent holds plaintext in memory.
- Server-side encryption at rest is unchanged. Sealed responses are a
  transport-layer control, not a storage control.

---

## Key pair generation

Generate an X25519 key pair per agent:

```bash
phoenix keypair generate myagent
```

This writes one file:
- `myagent.seal.key` (private key, base64-encoded 32 bytes, mode `0600`)

The derived public key is printed to stdout for reference (e.g., for
server-side registration). It is not written to a file.

Override the output directory:

```bash
phoenix keypair generate myagent -o /etc/phoenix/keys/
```

### Rotation

Generate a new key pair and reconfigure the agent. Old sealed responses
cannot be decrypted with the new key, but that is by design — sealed
responses are ephemeral transport encryption, not archival.

---

## Configuring sealed mode

### CLI

Set `PHOENIX_SEAL_KEY` to the path of the agent's private key file:

```bash
export PHOENIX_SEAL_KEY="/etc/phoenix/keys/myagent.seal.key"
```

When set, `phoenix get`, `phoenix resolve`, and `phoenix exec` automatically:
1. Derive the public key from the private key.
2. Send the public key in the `X-Phoenix-Seal-Key` request header.
3. Receive sealed envelopes instead of plaintext values.
4. Decrypt locally before returning to the caller.

### MCP server

```json
{
  "mcpServers": {
    "phoenix": {
      "command": "phoenix",
      "args": ["mcp-server"],
      "env": {
        "PHOENIX_SERVER": "https://phoenix:9090",
        "PHOENIX_TOKEN": "...",
        "PHOENIX_SEAL_KEY": "/etc/phoenix/keys/myagent.seal.key"
      }
    }
  }
}
```

When `PHOENIX_SEAL_KEY` is set in MCP mode:
- `phoenix_resolve` and `phoenix_get` return `PHOENIX_SEALED:<base64>`
  opaque tokens instead of plaintext.
- `phoenix_unseal` is added to the tool list, allowing the agent to
  explicitly decrypt a sealed token when policy permits.

### SDKs

**Go:**
```go
client := phoenix.New("https://phoenix:9090", "token")
client.SetSealKey("/path/to/agent.seal.key")

// Transparent — returns plaintext after local decryption
val, err := client.Resolve("phoenix://myapp/api-key")
```

**Python:**
```bash
pip install phoenix-secrets[sealed]  # installs PyNaCl
```

```python
from phoenix_secrets import PhoenixClient

client = PhoenixClient(seal_key_path="/path/to/agent.seal.key")
# or: client = PhoenixClient()  # reads PHOENIX_SEAL_KEY from env

val = client.resolve("phoenix://myapp/api-key")
```

**TypeScript:**
```bash
npm install phoenix-secrets  # tweetnacl is an optional dependency
```

```javascript
const { PhoenixClient } = require("phoenix-secrets");

const client = new PhoenixClient({
  sealKeyPath: "/path/to/agent.seal.key",
});
const val = await client.resolve("phoenix://myapp/api-key");
```

All SDKs handle sealed responses transparently — callers see plaintext
values without code changes.

---

## Policy controls

### `require_sealed`

Force agents to use sealed mode for specific paths. Requests without a
valid `X-Phoenix-Seal-Key` header are denied:

```json
{
  "attestation": {
    "production/*": {
      "require_sealed": true
    }
  }
}
```

### `allow_unseal`

Control whether the MCP `phoenix_unseal` tool can decrypt sealed tokens
for a given path. When `false` (default), sealed tokens remain opaque and
the agent must pass them to `phoenix exec` for injection:

```json
{
  "attestation": {
    "production/*": {
      "require_sealed": true,
      "allow_unseal": false
    },
    "dev/*": {
      "allow_unseal": true
    }
  }
}
```

The `allow_unseal` check is server-authoritative — the MCP client queries
`GET /v1/policy/check?path=<path>&check=allow_unseal` before decrypting.

---

## Wire format

When `X-Phoenix-Seal-Key` is present, the server returns `sealed_values`
instead of `values`:

```json
{
  "sealed_values": {
    "phoenix://myapp/api-key": {
      "version": 1,
      "algorithm": "x25519-xsalsa20-poly1305",
      "path": "myapp/api-key",
      "ref": "phoenix://myapp/api-key",
      "ephemeral_key": "<base64>",
      "nonce": "<base64>",
      "ciphertext": "<base64>"
    }
  }
}
```

Each envelope uses a fresh ephemeral key pair (forward secrecy). The
decrypted payload contains:

```json
{
  "path": "myapp/api-key",
  "ref": "phoenix://myapp/api-key",
  "value": "sk-live-abc123",
  "issued_at": "2026-03-08T12:00:00Z"
}
```

Inner `path` and `ref` fields are validated against the outer envelope to
prevent relabeling attacks.

### Dry-run behavior

`POST /v1/resolve?dry_run=true` always returns plaintext `values` with
`"ok"` status strings regardless of seal key presence. Dry-run never
returns sealed envelopes.

---

## MCP sealed token format

In MCP mode, sealed values are returned as opaque tokens:

```
PHOENIX_SEALED:eyJ2ZXJzaW9uIjoxLC...
```

The token is the base64-encoded JSON sealed envelope. This format is:
- Safe to store in environment variables
- Safe to pass through `phoenix exec --env`
- Not parseable without the private key

---

## Migration from plaintext to sealed

1. Generate key pairs for each agent: `phoenix keypair generate <name>`
2. Set `PHOENIX_SEAL_KEY` in each agent's environment.
3. Test: `phoenix resolve phoenix://test/secret` should work unchanged.
4. Optionally add `require_sealed: true` to policy for sensitive paths.
5. Optionally set `allow_unseal: false` for paths that should never be
   decrypted in MCP tool output.
