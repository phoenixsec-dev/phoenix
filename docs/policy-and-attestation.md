# Phoenix Policy and Attestation

Phoenix evaluates policy per path. Different secrets can require different proof.

## Example: graduated security

```json
{
  "attestation": {
    "dev/*": {
      "require_mtls": false,
      "deny_bearer": false
    },
    "staging/*": {
      "require_mtls": true,
      "source_ip": ["192.168.0.0/24"]
    },
    "production/*": {
      "require_mtls": true,
      "deny_bearer": true,
      "source_ip": ["192.168.0.110", "192.168.0.115"],
      "cert_fingerprint": "sha256:A1B2C3..."
    }
  }
}
```

- `dev/*` — any valid credential works
- `staging/*` — must use mTLS and come from the expected network
- `production/*` — must use a specific certificate from a specific IP, with no bearer fallback

Add the policy file in server config:

```json
{
  "policy": {
    "path": "/data/phoenix/policy.json"
  }
}
```

## Sealed policy controls

Sealed responses add per-path controls such as:
- `require_sealed`
- `allow_unseal`

Use them when you want agents to receive encrypted responses by default and avoid
plaintext MCP/tool output except where explicitly allowed.

See [Sealed Responses](sealed-responses.md) for rollout details.

## Test policies from the CLI

```bash
export PHOENIX_POLICY="/data/phoenix/policy.json"

# Show requirements for a path
phoenix policy show production/db-password

# Dry-run an attestation check
phoenix policy test --agent deployer --ip 192.168.0.110 production/db-password
```

`phoenix policy test` is a local approximation helper. It is useful for sanity
checks, but it does not fully simulate live cryptographic proof paths such as
mTLS handshakes or nonce freshness handling.

## Related docs

- [Authentication](authentication.md)
- [Sealed Responses](sealed-responses.md)
- [Threat Model](threat-model.md)
- [API Reference Index](api-reference-index.md)
