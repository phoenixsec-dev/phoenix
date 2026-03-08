<p align="center">
  <img src="docs/branding/phoenix-v0-w-name-H-E-unique.svg" alt="Phoenix logo" width="420"/>
</p>

<p align="center">
  <strong>Phoenix: Attested secrets for agents. Reference-first by design.</strong><br/>
  <em>Like a phoenix, access is short-lived by design—attested, scoped, and reborn only when needed.</em><br/>
  <strong>Mission: use <code>references</code> first and minimize raw secret exposure.</strong>
</p>

[![CI](https://github.com/phoenixsec/phoenix/actions/workflows/ci.yml/badge.svg)](https://github.com/phoenixsec/phoenix/actions/workflows/ci.yml)

### Branding assets

- Full logo: `docs/branding/phoenix-v0-w-name-H-E-unique.svg`
- Dark-mode monochrome: `docs/branding/phoenix-monochrome-icon.jpg`
- Color icon only: `docs/branding/phoenix-v0-color-icon-only.svg`

---

# Phoenix

Phoenix is a self-hosted secrets manager for AI agents.

It is built for people who know their current secret setup is sketchy — raw API keys in `.env` files, copied into prompts, passed through scripts, or scattered across agent configs — but do **not** want secret management to become a full-time job. Phoenix is especially aimed at practical self-hosted, homelab, small-team, and internal company deployments where you want real controls without enterprise-platform overhead.

Phoenix gives you a safer, more structured path:
- store secrets once
- use `phoenix://...` references instead of raw values
- control which agent can access what
- audit every access
- use sealed responses when you want context-safer secret delivery in CLI, SDK, and MCP workflows

**Context-safe** means an agent can use a secret without the raw value casually ending up in prompt text, tool responses, logs, or normal model context.

Phoenix is meant to be practical, not ceremonial: a single-binary tool with real security controls — encryption at rest, scoped access, attestation, audit, mTLS, sealed responses, and 1Password integration — but simple enough that your agent can help set it up, import secrets, and operate it.

Because “just trust the model stack with your secrets” is not a serious security plan.

```bash
# Store a secret
phoenix set myapp/api-key -v "sk-abc123" -d "OpenAI API key"

# Run a command with secrets injected (reference-first workflow)
phoenix exec --env OPENAI_KEY=phoenix://myapp/api-key -- python app.py

# Optional manual/debug inspection (plaintext output)
phoenix resolve phoenix://myapp/api-key
```

---

## Start Here

- **New install / first setup:** see [Getting Started](docs/getting-started.md)
- **CLI workflows:** see [CLI Usage](docs/cli-usage.md)
- **Auth and identity setup:** see [Authentication](docs/authentication.md)
- **Policy enforcement:** see [Policy and Attestation](docs/policy-and-attestation.md)
- **Agent integrations:** see [Integrations](docs/integrations.md)
- **Key rotation / passphrase protection / emergency access:** see [Key Management](docs/key-management.md)
- **Config, environment vars, Docker:** see [Configuration and Operations](docs/configuration.md)
- **Threat model and security boundaries:** see [Threat Model](docs/threat-model.md)
- **Runnable integration examples:** see [examples/README.md](examples/README.md)

---

## Context-safe usage

Phoenix now supports an end-to-end, context-safer workflow for agents: configure a seal key with `PHOENIX_SEAL_KEY`, enable per-path policy such as `require_sealed`, and Phoenix will return sealed secret payloads instead of plaintext. In MCP mode, tool output can stay opaque unless policy explicitly allows unsealing.

Plaintext read paths still exist for legacy, manual, and explicit local-use cases such as `phoenix get`, `phoenix resolve`, or direct API reads without sealed mode. `phoenix exec` remains context-safe in the original reference-first sense: Phoenix resolves locally and injects only the requested values into the child process without putting them in normal agent/tool context. So the right mental model is: Phoenix can keep secrets out of normal agent context, but sealed mode is what enforces encrypted response delivery for read/resolve-style workflows. See [docs/sealed-responses.md](docs/sealed-responses.md).

---

## Why Phoenix?

Traditional secret managers assume the consumer is a trusted process. That model breaks down with LLM agents, where prompt leakage, tool misuse, and context retention are real threats.

Secret-reference features in agent frameworks are still useful, but they mostly solve config hygiene: they help you avoid hard-coding raw values in config files. They do **not** replace a real secret system with encryption at rest, per-agent access control, attestation, and audit. Phoenix plugs into those workflows, but provides the actual security layer underneath them.

Phoenix adds the missing runtime layer:

- encrypted storage
- per-agent ACLs
- attestation and policy checks
- short-lived access patterns
- append-only audit logs
- sealed responses for multi-agent isolation

| | Config ref tools | Phoenix |
|---|---|---|
| Plaintext out of configs | Yes | Yes |
| Encrypted at rest | No | AES-256-GCM envelope encryption |
| Per-agent access control | No | Glob-pattern ACL per agent |
| Identity attestation | No | mTLS + policy checks + optional local attestation |
| Runtime audit trail | No | Every access logged with identity |
| Credential stripping | No | `phoenix exec` strips broker creds |
| Key rotation | No | Two-phase commit KEK rotation |
| Sealed transport to agents | No | Per-agent key pairs + sealed responses |

---

## Core Features

- **Encrypted storage** — AES-256-GCM envelope encryption with per-namespace DEKs
- **Authentication and attestation** — bearer tokens, mTLS certs, and per-path policy checks
- **Reference-first workflows** — `phoenix://...` refs for config-safe secret references
- **Context-safer delivery** — sealed responses for multi-agent and MCP workflows
- **Exec wrapper** — inject only the secrets a child process actually needs
- **Policy controls** — per-path requirements like mTLS, IP binding, tool identity, and `require_sealed`
- **Audit trail** — every secret access, denial, and resolution attempt is logged
- **Works with existing setups** — import from `.env`, migrate from 1Password, or broker runtime reads through 1Password
- **Agent-native integrations** — MCP, SDKs, OpenClaw exec backend, direct HTTP API
- **Homelab-friendly deployment** — self-hosted, single binary, no required external service

---

## Two-Minute Quick Start

### 1. Install or build

```bash
curl -fsSL https://raw.githubusercontent.com/phoenixsec/phoenix/main/scripts/install.sh | sh
# or build locally:
# git clone https://github.com/phoenixsec/phoenix.git && cd phoenix && go build -o bin/ ./cmd/...
```

### 2. Initialize Phoenix

```bash
./bin/phoenix-server --init /data/phoenix
```

Save the printed admin token immediately. Full bootstrap details: [docs/getting-started.md](docs/getting-started.md).

### 3. Start the server

```bash
./bin/phoenix-server --config /data/phoenix/config.json
```

### 4. Store and use a secret

```bash
export PHOENIX_SERVER="https://localhost:9090"
export PHOENIX_TOKEN="<your-admin-token>"
export PHOENIX_CA_CERT="/data/phoenix/ca.crt"

phoenix set myapp/api-key -v "sk-live-abc123" -d "API key"
phoenix exec --env API_KEY=phoenix://myapp/api-key -- env | grep API_KEY
```

For the full first-run path, auth setup, and policy examples, use:
- [Getting Started](docs/getting-started.md)
- [Authentication](docs/authentication.md)
- [Policy and Attestation](docs/policy-and-attestation.md)

---

## Docs Map

### Getting started and operations
- [Getting Started](docs/getting-started.md)
- [Configuration and Operations](docs/configuration.md)
- [Key Management](docs/key-management.md)
- [Release Runbook](docs/release-runbook.md)

### Security model and rollout
- [Threat Model](docs/threat-model.md)
- [Sealed Responses](docs/sealed-responses.md)
- [Multi-Agent Setup](docs/multi-agent-setup.md)
- [Admin Token Lifecycle](docs/admin-token-lifecycle.md)
- [Reference-Only Enforcement Design (WIP)](docs/reference-only-enforcement-design.md)

### Usage and integrations
- [CLI Usage](docs/cli-usage.md)
- [Authentication](docs/authentication.md)
- [Policy and Attestation](docs/policy-and-attestation.md)
- [Integrations](docs/integrations.md)
- [API Reference Index](docs/api-reference-index.md)
- [Migration Guide: `.env` to Phoenix](docs/migration-env-to-phoenix.md)
- [Runnable Examples](examples/README.md)

### Project direction
- [Public Roadmap](docs/roadmap.md)

---

## Security Model Summary

**Phoenix helps with:**
- reducing secret exposure in configs, prompts, and many tool flows
- per-agent authorization and policy checks
- cryptographic identity via mTLS and sealed-response key pairs
- audit visibility for reads, denies, and resolution attempts
- safer multi-agent operation on the same machine when identities are separated correctly

**Phoenix does not solve:**
- root/kernel compromise on the host
- malicious admins with direct file access
- every possible plaintext path in every client without policy and rollout discipline

See the full [Threat Model](docs/threat-model.md) and [Sealed Responses](docs/sealed-responses.md).

---

## Development

```bash
# Run all tests
go test ./... -count=1

# Run tests with verbose output
go test ./... -count=1 -v

# Build both binaries
go build -o bin/ ./cmd/...
```

External dependencies: `golang.org/x/crypto` and `golang.org/x/term`.

---

## License

MIT
