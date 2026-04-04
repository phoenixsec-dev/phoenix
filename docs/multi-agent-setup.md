# Phoenix Secrets — Multi-Agent Setup

Running multiple AI agents on the same host, each with isolated access and
sealed key pairs so one agent cannot read another's secrets.

## Scenario

Two agents — `builder` and `deployer` — run on the same machine and share
a Phoenix server. Each should only see its own secrets, and secret values
should be encrypted per-agent even in transit.

## Setup

### 1. Create agents with scoped ACLs

```bash
phoenix agent create builder \
  -t "$(openssl rand -hex 32)" \
  --acl "build/*:read"

phoenix agent create deployer \
  -t "$(openssl rand -hex 32)" \
  --acl "deploy/*:read;infra/*:read"
```

### 2. Generate sealed key pairs

Generate a key pair per agent so each gets encrypted responses only it can
decrypt. See [Sealed Responses](sealed-responses.md) for how this works.

```bash
phoenix keypair generate builder -o /etc/phoenix/keys/builder.seal.key
phoenix keypair generate deployer -o /etc/phoenix/keys/deployer.seal.key
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

- `build/*` allows MCP unseal (builder may need values in tool output)
- `deploy/*` and `infra/*` deny unseal — values can only be consumed via
  `phoenix exec`

See [Policy and Attestation](policy-and-attestation.md) for the full policy
reference.

### 4. Configure each agent's environment

**Builder (e.g., Claude Code):**

```bash
export PHOENIX_SERVER="https://phoenix:9090"
export PHOENIX_TOKEN="<builder-token>"
export PHOENIX_SEAL_KEY="/etc/phoenix/keys/builder.seal.key"
```

**Deployer (e.g., systemd service):**

```ini
Environment=PHOENIX_SERVER=https://phoenix:9090
Environment=PHOENIX_TOKEN=<deployer-token>
Environment=PHOENIX_SEAL_KEY=/etc/phoenix/keys/deployer.seal.key
```

For MCP configuration, add the same env vars to the agent's MCP server
config. See [Integrations](integrations.md) for the config format.

## What this gives you

- Each agent's responses are encrypted to its own key pair
- Agents on the same server cannot decrypt each other's sealed responses
- ACLs restrict which paths each agent can access at all
- `require_sealed` ensures no agent can fetch plaintext over the wire
- `allow_unseal` controls whether MCP tool output contains decrypted values

## Verification

```bash
# Sealed mode works — resolves and prints plaintext after local decryption
PHOENIX_SEAL_KEY=/etc/phoenix/keys/builder.seal.key \
  phoenix resolve phoenix://build/api-key

# Cross-agent access denied
PHOENIX_TOKEN=<deployer-token> phoenix get build/api-key
# Expected: 403 denied
```

## Related docs

- [Sealed Responses](sealed-responses.md) — how sealed delivery works
- [Authentication](authentication.md) — mTLS as an alternative to bearer tokens
- [LAN Deployment](lan-deployment.md) — multi-host variant of this pattern
