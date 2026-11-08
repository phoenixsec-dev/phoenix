# Phoenix Secrets — Policy and Attestation

Phoenix evaluates policy per path, on top of the ACL. Different secrets can
require different proof. Every check is one the server can make itself:
where the request came from (`source_ip`) and how the value is delivered
(`require_sealed`).

## Example: graduated security

```json
{
  "attestation": {
    "dev/**": {},
    "staging/**": {
      "source_ip": ["192.168.0.0/24"]
    },
    "production/**": {
      "source_ip": ["192.168.0.110", "192.168.0.115"],
      "require_sealed": true
    }
  }
}
```

- `dev/**` — any valid credential works
- `staging/**` — must come from the expected network
- `production/**` — must come from one of two hosts, and is only delivered sealed

Add the policy file in server config:

```json
{
  "policy": {
    "path": "/data/phoenix/policy.json"
  }
}
```

Check it before restarting: `phoenix-server --check-config --config <config>`
loads the policy file too.

## Removed policy fields

A policy file that still uses a removed field fails to load, with one line
per field. They went because the server could not actually check them:

| Field | Why it went |
|---|---|
| `process` (`uid`, `binary_hash`), `require_fresh_attestation`, `credential_ttl` | The server believed process details the caller claimed |
| `allowed_tools`, `deny_tools` | They matched `X-Phoenix-Tool`, a header the caller sets itself |
| `require_nonce`, `nonce_max_age`, `require_signed` | Only `phoenix resolve --signed` with a client certificate could pass; `nonce_max_age` was never enforced |
| `require_mtls`, `cert_fingerprint`, `deny_bearer` | Client certificates (mTLS) were removed |
| `time_window`, `time_zone` | Unused |

Use `source_ip` and `require_sealed` instead.

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

`phoenix policy test` is a local approximation helper: it evaluates `source_ip`
for the `--ip` you give. It does not present a seal key, so a
`require_sealed` path reports FAIL.

## Related docs

- [Authentication](authentication.md)
- [Sealed Responses](sealed-responses.md)
- [Threat Model](threat-model.md)
- [API Reference Index](api-reference-index.md)
