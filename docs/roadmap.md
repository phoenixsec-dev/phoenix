# Phoenix Public Roadmap

> This roadmap is directional and may change based on user feedback.
> It is not a contractual delivery commitment.

## Shipped (v0.13)

- Encrypted secret storage (AES-256-GCM envelope encryption)
- Per-agent ACL with namespace isolation and glob matching
- Bearer token and mTLS authentication
- Sealed responses (per-agent X25519 transport encryption)
- MCP server — stdio and Streamable HTTP transports
- `phoenix exec` with credential stripping
- Attestation policy engine (mTLS, IP binding, cert fingerprint, sealed requirements)
- Session identity — role-based, short-lived session tokens with auto-renewal
- Step-up approval — human-in-the-loop gating for sensitive roles
- Operator dashboard — browser-based approval, session, audit, and role management
- Go SDK with session support
- 1Password broker backend (read-only)
- Import from `.env` files and 1Password
- Emergency offline access (break-glass)
- Master key passphrase protection and rotation
- Internal CA with agent certificate lifecycle and CRL

## Planned (Near-Term)

### Reference-Only Enforcement

Policy-driven controls to restrict plaintext-return paths per identity and path.
Operators will be able to deny `get` and `resolve` operations for selected
namespaces, pushing agents toward `phoenix exec` as the only consumption path.

See `docs/reference-only-enforcement-design.md` for the design RFC.

### Server Certificate SAN Management

CLI support for re-issuing the server TLS certificate with custom SANs
(LAN IPs, hostnames), simplifying multi-host deployment without external
certificate tooling.

### SDK Publishing

Python (`phoenix-secrets`) and TypeScript (`phoenix-secrets`) SDK packages
on PyPI and npm respectively.

## Exploring (Post-Launch)

These are under consideration and will be prioritized by real-world usage:

- Multi-user/team workflows with per-operator identity
- Rotation automation and lifecycle UX improvements
- Advanced policy simulation and dry-run tooling
- Additional secret backends (Bitwarden, AWS Secrets Manager)
- Enterprise deployment and distribution options

---

Last updated: 2026-03-19
