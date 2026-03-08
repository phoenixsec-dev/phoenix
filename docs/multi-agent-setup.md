# Multi-Agent Setup with Sealed Responses

This guide covers running multiple AI agents on the same host, each with
isolated sealed key pairs so that one agent cannot read another's secrets.

## Scenario

Two agents — `builder` and `deployer` — run on the same machine and share
a Phoenix server. Each should only see its own secrets, and secret values
should be encrypted per-agent even in transit.

## Setup

### 1. Create agents with scoped ACLs

Agents must exist before key pairs can be generated.

```bash
phoenix agent create builder \
  -t "$(openssl rand -hex 32)" \
  --acl "build/*:read"

phoenix agent create deployer \
  -t "$(openssl rand -hex 32)" \
  --acl "deploy/*:read;infra/*:read"
```

### 2. Generate key pairs

```bash
phoenix keypair generate builder -o /etc/phoenix/keys/
phoenix keypair generate deployer -o /etc/phoenix/keys/
```

### 3. Configure policy

```json
{
  "attestation": {
    "build/*": {
      "require_sealed": true,
      "allow_unseal": true
    },
    "deploy/*": {
      "require_sealed": true,
      "allow_unseal": false
    },
    "infra/*": {
      "require_sealed": true,
      "allow_unseal": false
    }
  }
}
```

- `build/*` allows MCP unseal (builder agent may need values in tool output)
- `deploy/*` and `infra/*` require sealed but deny unseal — values can only
  be consumed via `phoenix exec`

### 4. Configure each agent's environment

**Builder (e.g., Claude Code CLAUDE.md):**

```bash
export PHOENIX_SERVER="https://phoenix:9090"
export PHOENIX_TOKEN="<builder-token>"
export PHOENIX_SEAL_KEY="/etc/phoenix/keys/builder.seal.key"
```

**Deployer (e.g., systemd service):**

```bash
Environment=PHOENIX_SERVER=https://phoenix:9090
Environment=PHOENIX_TOKEN=<deployer-token>
Environment=PHOENIX_SEAL_KEY=/etc/phoenix/keys/deployer.seal.key
```

### 5. MCP configuration (per agent)

Each agent's MCP config points to its own seal key:

```json
{
  "mcpServers": {
    "phoenix": {
      "command": "phoenix",
      "args": ["mcp-server"],
      "env": {
        "PHOENIX_SERVER": "https://phoenix:9090",
        "PHOENIX_TOKEN": "<agent-specific-token>",
        "PHOENIX_SEAL_KEY": "/etc/phoenix/keys/<agent>.seal.key"
      }
    }
  }
}
```

## What this gives you

- Each agent's responses are encrypted to its own key pair.
- Even if both agents talk to the same server, they cannot decrypt each
  other's sealed responses.
- ACLs restrict which paths each agent can access at all.
- `require_sealed` ensures no agent can fetch plaintext over the wire.
- `allow_unseal` controls whether MCP tool output contains decrypted
  values or opaque tokens.

## Verification

```bash
# Check that sealed mode works (resolves successfully with seal key)
PHOENIX_SEAL_KEY=/etc/phoenix/keys/builder.seal.key \
  phoenix resolve phoenix://build/api-key
# If this prints the secret value, sealed mode is working — the CLI
# decrypts locally and prints plaintext for single refs.

# Verify deployer cannot access builder paths
PHOENIX_TOKEN=<deployer-token> \
  phoenix get build/api-key
# Expected: 403 denied

# Check audit trail
phoenix audit -n 20
```
