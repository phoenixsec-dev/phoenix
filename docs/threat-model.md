# Phoenix Threat Model

This document describes the core threats Phoenix is designed to mitigate, the trust boundaries, and what remains out of scope.

## Scope and assumptions

- Phoenix protects secret access for AI-agent-driven workflows.
- Agents and tools are treated as potentially untrusted consumers.
- The Phoenix host, config, and key material are assumed to be administratively controlled.
- Network attackers, prompt-injection side effects, and credential leakage are in scope.

## Security goals

1. Keep secrets encrypted at rest.
2. Ensure only authorized agents can read/write/delete allowed paths.
3. Require strong caller identity and optional attestation before revealing secret values.
4. Preserve an audit trail for every access decision.
5. Limit blast radius when credentials leak.

## Assets

- Secret values
- Master key / wrapped DEKs
- Agent credentials (bearer tokens, mTLS certs, short-lived tokens)
- ACL and attestation policy config
- Audit log integrity

## Trust boundaries

1. **Client/agent process** → **Phoenix API**  
   Authentication, ACL checks, and attestation are enforced here.
2. **Phoenix API** → **Secret backend**  
   File backend or external backend reads are mediated by Phoenix policy.
3. **Phoenix runtime** → **Storage and key files**  
   File permissions and host hardening matter for confidentiality.

## Threats Phoenix addresses

- **Prompt-injection-induced secret exfiltration**  
  Reference-first workflows (`phoenix://` + policy-gated resolution) reduce plaintext exposure in config/prompt paths.
- **Unauthorized cross-agent access**  
  Per-agent ACL path rules enforce least privilege.
- **Credential replay / misuse**  
  mTLS, IP binding, cert pinning, nonce challenge, and short-lived tokens reduce replay value.
- **Operational leakage**  
  Structured audit logs record allows/denies without writing secret values.
- **At-rest theft of store data**  
  AES-256-GCM envelope encryption protects persisted values.
- **Rotation failure corruption**  
  Two-phase key rotation + backup path supports recovery.

## Attestation controls (defense in depth)

Per-path policy can require combinations of:

- `require_mtls`
- `deny_bearer`
- `source_ip`
- `cert_fingerprint`
- `allowed_tools` / `deny_tools`
- `time_window`
- `process.uid` / `process.binary_hash`
- `require_nonce`
- `require_fresh_attestation`

## Out of scope / non-goals

- Host root compromise or kernel compromise
- Hardware side-channel attacks
- Physical extraction from an already-compromised host
- Full enterprise HSM/KMS assurance model

## Recommended operational controls

- Use mTLS + `deny_bearer` for high-value paths.
- Keep admin ACLs narrow and rotate credentials regularly.
- Enable nonce + short-lived tokens in higher-risk deployments.
- Store data/key/audit files on restricted paths with strict permissions.
- Monitor audit logs for denied access bursts and unusual path access.
