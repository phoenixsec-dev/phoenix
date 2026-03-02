# Admin Token Lifecycle

The admin bearer token printed by `phoenix-server --init` is a **bootstrap credential**.
Treat it as break-glass admin power, not a daily-use token.

## 1) Capture it once, then store it safely

When init prints:

```text
*** ADMIN TOKEN (save this — it won't be shown again): ***
<token>
```

Immediately move it into a secure store:

- password manager entry (recommended)
- encrypted secrets vault
- sealed operational runbook notes (restricted access)

Do **not** leave it in:

- shell history
- chat logs/tickets
- plaintext notes
- committed files (`.env`, scripts, docs)

## 2) Bootstrap with the admin token, then reduce exposure

Use the admin token only for setup tasks:

- create scoped agents (`phoenix agent create ...`)
- issue mTLS certs (`phoenix cert issue ...`)
- configure policy/attestation

Example bootstrap flow:

```bash
export PHOENIX_SERVER="https://localhost:9090"
export PHOENIX_TOKEN="<admin-token>"
export PHOENIX_CA_CERT="/data/phoenix/ca.crt"

phoenix agent create app-runtime -t "runtime-token" --acl "myapp/*:read"
phoenix agent create app-deployer -t "deploy-token" --acl "myapp/*:read,write"
phoenix cert issue app-runtime -o /etc/phoenix/certs
```

Then remove the admin token from your active shell:

```bash
unset PHOENIX_TOKEN
```

## 3) Prefer scoped identities for normal operations

- CI deploy jobs: use deployer-scoped credentials
- App runtime: read-only runtime identity
- Human operator workflows: use named admin identities with mTLS where possible

Keep ACL scopes narrow (`namespace/*`) and action-specific (`read`, `write`, `delete`, `admin`).

## 4) Short-lived tokens (optional hardening)

If short-lived token minting is enabled (`attestation.token.enabled=true`), use:

- long-lived admin identity only to mint short-lived agent tokens
- short TTLs appropriate for task duration

This limits replay value of leaked bearer material.

## 5) Rotation and recovery practices

- rotate application secrets on a schedule
- rotate agent tokens/certs when staff or infrastructure changes
- keep emergency access documented and tested
- if you suspect admin token exposure, immediately shift operations to scoped credentials and rotate dependent access paths

## 6) Hardening target state

For higher-assurance deployments:

1. mTLS enabled and required for privileged paths
2. strict attestation on sensitive namespaces (`deny_bearer`, `source_ip`, `cert_fingerprint`)
3. bearer auth reduced or disabled where operationally feasible

This keeps the admin token as a fallback/bootstrap mechanism, not the backbone of day-to-day access.
