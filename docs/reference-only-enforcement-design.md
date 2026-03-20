# Reference-Only Enforcement Design (RFC)

Status: design RFC for planned policy-driven controls that restrict plaintext-return paths.
This feature is not yet implemented. See [Roadmap](roadmap.md) for timeline.

## Problem

Today, Phoenix supports reference-first workflows, but does not enforce them globally.
Any identity with `read` permission can use:

- `GET /v1/secrets/{path}` (`phoenix get`)
- `POST /v1/resolve` (`phoenix resolve`)

Both return plaintext secret values.

## Goal

Add policy-level controls so operators can deny plaintext-return operations for selected
paths/identities, similar to existing attestation controls.

## Proposed policy fields

Within each `attestation` path rule:

```json
{
  "attestation": {
    "production/*": {
      "deny_operations": ["get", "resolve"]
    }
  }
}
```

Alternative form (mutually exclusive with `deny_operations`):

```json
{
  "attestation": {
    "production/*": {
      "allow_operations": ["resolve"]
    }
  }
}
```

### Operation vocabulary (initial)

- `get` → `GET /v1/secrets/{path}`
- `resolve` → `POST /v1/resolve`
- `list` → `GET /v1/secrets/{prefix}/` (optional phase)

## Enforcement model

1. API handlers annotate request context with operation name.
2. Policy engine evaluates operation constraints in addition to existing checks.
3. Denied operations return `403` with clear reason (for audit and debugging).
4. Audit log records `denied` with reason (e.g., `operation blocked by policy`).

## Important caveat

Current `phoenix exec` resolves references client-side via API and ultimately handles
plaintext in the client process. So denying `resolve` for an identity will also deny
`phoenix exec` for that identity.

This design improves policy control, but does **not** by itself create a cryptographic
"agent never sees plaintext" guarantee.

## Suggested rollout

### Phase 1: Operation-aware policy guardrails

- Add policy fields + validation
- Add operation context to policy evaluation
- Gate `get` and `resolve` endpoints
- Update docs/examples

### Phase 2: ACL action split (optional)

Introduce distinct actions (for example):

- `read_value` (raw secret reads)
- `resolve_ref` (reference resolution)

This avoids overloading current `read` permission.

### Phase 3: Enforced broker pattern (future)

Design a server-mediated execution/injection path where plaintext is never returned to
general client calls, then offer a true "reference-only enforced mode."

## Open questions

1. Should operation restrictions be path-only, identity-only, or both?
2. Should default behavior remain permissive for backward compatibility?
3. Should policy violations include machine-readable error codes?
4. Do we need a migration helper to detect agents that would be broken by new rules?
