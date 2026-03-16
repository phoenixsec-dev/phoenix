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
- Agent credentials (bearer tokens, mTLS certs, short-lived tokens, session tokens)
- ACL and attestation policy config
- Audit log integrity
- Dashboard session cookies (when dashboard is enabled)

## Trust boundaries

1. **Client/agent process** → **Phoenix API**
   Authentication, ACL checks, and attestation are enforced here.
2. **Phoenix API** → **Secret backend**
   File backend or external backend reads are mediated by Phoenix policy.
3. **Phoenix runtime** → **Storage and key files**
   File permissions and host hardening matter for confidentiality.
4. **Browser** → **Dashboard** (when enabled)
   Cookie-based auth with separate credential. See "Dashboard attack surface" below.

## Threats Phoenix addresses

- **Prompt-injection-induced secret exfiltration**
  Reference-first workflows (`phoenix://` + policy-gated resolution) reduce plaintext exposure in config/prompt paths.
- **Unauthorized cross-agent access**
  Per-agent ACL path rules enforce least privilege.
- **Credential replay / misuse**
  mTLS, IP binding, cert pinning, nonce challenge, and short-lived tokens reduce replay value. Session tokens are scoped, time-limited, and individually revocable.
- **Operational leakage**
  Structured audit logs record allows/denies without writing secret values.
- **At-rest theft of store data**
  AES-256-GCM envelope encryption protects persisted values.
- **Rotation failure corruption**
  Two-phase key rotation + backup path supports recovery.

## Session identity threats

Session tokens (`phxs_` prefix) introduce additional attack surface:

- **Token theft**: Session tokens are bearer-like. If leaked, an attacker gains the
  role's scope until expiry or revocation. Mitigated by short TTLs (default 1h),
  per-session revocation, and binding to the minting agent's identity.
- **Privilege escalation via role config change**: Roles are re-checked at renewal
  time. A role config change that widens scope does not retroactively expand active
  sessions — the session keeps the scope it was minted with.
- **Step-up bypass**: Step-up approval is enforced server-side at mint time. An agent
  cannot mint a step-up role without human approval. The approval re-checks role
  config, bootstrap trust, attestation, and seal key requirements at approve time
  to prevent stale-config attacks.
- **Session token on admin endpoints**: Session tokens are explicitly rejected for
  admin operations (agent management, cert issuance, approval, revocation by other
  agents). This prevents a scoped session from escalating to admin access even if
  the underlying agent has admin ACL.

## Dashboard attack surface

When `dashboard.enabled` is `true`, the server exposes a browser-accessible admin
interface at `/dashboard/`. This is a materially different attack surface from the
API and must be evaluated separately.

### What the dashboard exposes

The dashboard can: view secret/agent/session counts, view and revoke active sessions,
approve and deny step-up requests (minting session tokens), view the full audit log,
and view role configuration.

The dashboard **cannot**: read or write secret values, create or modify agents, issue
or revoke certificates, or change server configuration.

Approval is the highest-risk action — it mints a session token for an agent.

### Authentication model

The dashboard uses a **separate auth surface** from the API:

- Single shared password (bcrypt) or PIN (constant-time compare)
- Cookie-based sessions with HMAC-SHA256 signed payloads
- CSRF tokens embedded in the cookie and validated on every POST (including logout)
- Exponential backoff rate limiting per source IP (5 attempts, then 1s–60s delay)
- Full audit trail: login success/failure, logout, expired cookie rejection,
  CSRF failures, and all mutations (approve, deny, revoke)

This is simpler than the API's auth model by design: the dashboard targets human
operators, not programmatic access. The trade-off is that all dashboard users share
one credential and are distinguished only by source IP in the audit trail
(`dashboard@<ip>`).

### Threats specific to the dashboard

| Threat | Mitigation | Residual risk |
|--------|-----------|---------------|
| Brute-force login | Rate limiting with exponential backoff, audit logging of failures | PIN mode has smaller keyspace; use password for non-loopback deployments |
| Session cookie theft (network) | `Secure` flag set when TLS detected; `HttpOnly` prevents JS access; `SameSite=Strict` prevents CSRF via cross-origin requests | Plain HTTP on a shared network exposes the cookie — **do not do this** |
| Session cookie theft (XSS) | `HttpOnly` flag; no user-supplied content rendered unescaped; embedded static assets (no CDN/external JS) | XSS in Go `html/template` is unlikely but not impossible if templates are modified |
| CSRF | Token-per-session in signed cookie, validated on all POST actions | Relies on `SameSite=Strict` + token check |
| Unauthorized approval | Same `ValidateForMint` safety checks as the API; role, bootstrap, attestation, and seal key all re-verified | A compromised dashboard session can approve any pending request |
| Shared credential | All operators share one password/PIN; no per-user identity | Forensic distinction limited to source IP (`dashboard@<ip>`) |
| Config file contains password | Config must be `chmod 600`; password is bcrypt-hashed at runtime, never stored as hash | If config is readable, password is exposed |

### Deployment requirements

The dashboard **must** be deployed behind one of:

1. **TLS reverse proxy** — proxy terminates TLS, sets `X-Forwarded-Proto: https`,
   Phoenix detects this and sets `Secure` on the cookie. The server itself can
   bind to loopback. This is the recommended approach.

2. **Native mTLS** — `auth.mtls.enabled: true`. TLS is native, cookie gets `Secure`
   via `r.TLS != nil`.

3. **Loopback only** — `server.listen: "127.0.0.1:..."`. Dashboard is unreachable
   from the network. Use SSH port forwarding for remote browser access.

Exposing the dashboard over plain HTTP on a network you do not fully control is
**not acceptable**. The session cookie would transit in cleartext.

### When to disable the dashboard

Disable the dashboard (`"enabled": false`) when:

- You have no step-up approval roles (the primary use case for browser access)
- All operators have CLI/SSH access to the server
- You want to minimize the server's attack surface
- You are running in a high-security environment where a shared-credential
  browser surface is not acceptable

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

## Sealed responses

Sealed responses add per-agent transport encryption (NaCl box: X25519 +
XSalsa20-Poly1305) with fresh ephemeral keys per response. This mitigates
network eavesdropping past TLS termination, cross-agent response interception
on shared hosts, MCP tool output leakage, and relabeling attacks.

It does not protect against a compromised agent private key, in-process
memory access after decryption, or server-side compromise.

For the full sealed responses design, wire format, policy controls
(`require_sealed`, `allow_unseal`), and SDK integration, see
[Sealed Responses](sealed-responses.md).

## Out of scope / non-goals

- Host root compromise or kernel compromise
- Hardware side-channel attacks
- Physical extraction from an already-compromised host
- Full enterprise HSM/KMS assurance model
- Per-operator identity on the dashboard (shared credential model)

## Recommended operational controls

- Use mTLS + `deny_bearer` for high-value paths.
- Keep admin ACLs narrow and rotate credentials regularly.
- Enable nonce + short-lived tokens in higher-risk deployments.
- Store data/key/audit files on restricted paths with strict permissions.
- Monitor audit logs for denied access bursts and unusual path access.
- If the dashboard is enabled: use TLS, use a strong password (not PIN),
  monitor for `dashboard.login` denied events in the audit trail, and
  restrict network access to the server to trusted hosts.
- Disable the dashboard when it is not needed.
