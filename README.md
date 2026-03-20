<p align="center">
  <img src="docs/branding/phoenix-v0-w-name-H-E-unique.svg" alt="Phoenix Secrets logo" width="420"/>
</p>

<p align="center">
  <strong>Context-safe secrets management for AI agents.</strong><br/>
  <em>Agents see references. Never raw values.</em>
</p>

<!-- CI badge: uncomment when GitHub Actions workflow is added
[![CI](https://github.com/phoenixsec-dev/phoenix/actions/workflows/ci.yml/badge.svg)](https://github.com/phoenixsec-dev/phoenix/actions/workflows/ci.yml)
-->

---

# Phoenix Secrets

Phoenix Secrets is a self-hosted secrets manager built for AI agent workflows.

Agents are taking on real work — running tools, installing skills from marketplaces, calling APIs with keys that cost real money. But the security story hasn't caught up. Frameworks like OpenClaw give agents serious capabilities while their credentials sit in plaintext environment variables and config files, readable by every skill and tool in the stack. Making agents smarter does not make them security-conscious. That gap is what Phoenix was built to close.

Phoenix introduces what we call **context-safe** secrets management: an agent can use a secret to do its job without the raw value ever appearing in prompts, tool responses, logs, or the model's context window. When a secret enters an LLM's context — through any of those paths — you are trusting the model provider's entire infrastructure with that value. You have no visibility into that chain of custody and no way to revoke it after the fact. No other secrets tool treats keeping values out of model context as a design goal.

Traditional managers like Vault and SOPS assume the consumer is a trusted process. Framework features like OpenClaw's SecretRef solve config hygiene — keeping values out of config files — but not out of model context. Phoenix is the security layer underneath.

**The OpenClaw problem:** OpenClaw came out of nowhere and changed the way the world thinks about using agents in their daily lives. But it also introduced significant security risks. Skills run with the same privileges as the agent — any skill, including ones downloaded from a marketplace, can read your environment variables and config files. If your API keys are in the environment, every skill you install has access to all of them. OpenClaw's own threat model calls this out as a critical open risk, and there is no sandboxing or credential isolation for skills today. Phoenix was built to close that gap — not just context-safety, but encrypted storage, per-agent access control, audit logging, and credential isolation that OpenClaw doesn't have on its own. See [Integrations](docs/integrations.md) for the full OpenClaw setup.

```bash
# Store a secret
phoenix set myapp/api-key -v "sk-abc123" -d "OpenAI API key"

# Run a command with secrets injected — context-safe, no raw values in agent context
phoenix exec --env OPENAI_KEY=phoenix://myapp/api-key -- python app.py

# Resolve a reference directly (plaintext output for manual/debug use)
phoenix resolve phoenix://myapp/api-key
```

---

## Why Phoenix Secrets?

You know your setup is sketchy. Raw API keys in `.env` files, pasted into prompts, passed through scripts, scattered across agent configs. If you're running an agent framework like OpenClaw, every skill you install gets the same access to those credentials that your agent has — and the ecosystem is moving fast enough that nobody has stopped to fix that yet. Secret management shouldn't become a full-time job, but ignoring it isn't an option anymore either. Enterprise platforms like Vault are overkill for a team of five.

Phoenix is built for the people actually running agents today — self-hosted, homelab, small-team, and internal deployments where you want real controls without the overhead. No database, no cloud account, no external service required — and your agent can help you set the whole thing up:

- **Context-safe delivery** — secrets stay out of agent prompts, tool output, and logs
- **Encrypted storage** — AES-256-GCM envelope encryption with per-namespace keys
- **Per-agent access control** — each agent only sees the paths it needs
- **Sealed responses** — end-to-end encrypted delivery per agent, even on shared hosts
- **Attestation and policy** — per-path requirements like mTLS, IP binding, and tool identity
- **Audit trail** — every access, denial, and resolution attempt is logged (secret values are never written to the log)
- **Reference-first workflows** — `phoenix://` URIs replace raw values in configs and scripts
- **Exec credential stripping** — `phoenix exec` injects secrets and strips broker credentials from the child process
- **Works with existing setups** — `phoenix import` pulls from `.env` files in one command; 1Password users can migrate secrets or broker reads at runtime without moving anything
- **Agent-native integrations** — built-in MCP server for Claude Code / Claude Desktop, Python/Go/TypeScript SDKs, OpenClaw exec backend, direct HTTP API
- **Emergency offline access** — break-glass secret retrieval directly from disk when the server is down

Two binaries (`phoenix` client + `phoenix-server`), single codebase, no external runtime dependencies.

**Sealed responses** mean one agent cannot read another agent's secrets, even on the same machine. The server encrypts each response to a specific agent's key pair, so intercepting the response is useless without the matching private key. In MCP mode, tool output contains opaque tokens instead of plaintext — the raw value never enters the model's context. Under the hood this is X25519 key agreement with per-response encryption. See [Sealed Responses](docs/sealed-responses.md).

Because "just trust the model stack with your secrets" is not a serious security plan.

|  | `.env` files | OpenClaw SecretRef | Phoenix Secrets |
|---|---|---|---|
| Secrets out of config files | No | Yes | Yes |
| Secrets out of model context | No | No | Yes |
| Encrypted at rest | No | No | Yes (AES-256-GCM) |
| Per-agent access control | No | No | Yes |
| Identity attestation | No | No | Yes (mTLS + policy) |
| Runtime audit trail | No | No | Yes |
| Credential stripping | No | No | Yes |
| Key rotation | No | No | Yes |

---

## Quick Start

### 1. Install

```bash
curl -fsSL https://raw.githubusercontent.com/phoenixsec-dev/phoenix/main/scripts/install.sh | sh

# Or build from source:
git clone https://github.com/phoenixsec-dev/phoenix.git && cd phoenix
go build -o bin/ ./cmd/...
```

### 2. Initialize

```bash
phoenix-server --init /data/phoenix
```

Save the printed admin token immediately — it is only shown once.

### 3. Start the server

```bash
phoenix-server --config /data/phoenix/config.json
```

### 4. Store and use a secret

```bash
export PHOENIX_SERVER="http://127.0.0.1:9090"
export PHOENIX_TOKEN="<your-admin-token>"

phoenix set myapp/api-key -v "sk-live-abc123" -d "API key"
phoenix exec --env API_KEY=phoenix://myapp/api-key -- env | grep API_KEY
```

> The default server config listens on `127.0.0.1:9090` over plain HTTP.
> This is safe for local-only use. For LAN or production deployment,
> enable TLS — see [LAN Deployment](docs/lan-deployment.md).

For the full first-run walkthrough, see [Getting Started](docs/getting-started.md).

---

## Documentation

| Topic | Guide |
|-------|-------|
| First install and setup | [Getting Started](docs/getting-started.md) |
| CLI commands and workflows | [CLI Usage](docs/cli-usage.md) |
| Auth, mTLS, and identity | [Authentication](docs/authentication.md) |
| Session tokens and role-based access | [Session Identity](docs/session-identity.md) |
| Operator dashboard (browser UI) | [Dashboard](docs/dashboard.md) |
| Per-path policy and attestation | [Policy and Attestation](docs/policy-and-attestation.md) |
| Sealed responses and multi-agent | [Sealed Responses](docs/sealed-responses.md) / [Multi-Agent Setup](docs/multi-agent-setup.md) |
| MCP, SDKs, OpenClaw, API | [Integrations](docs/integrations.md) |
| Key rotation and emergency access | [Key Management](docs/key-management.md) |
| Server config and Docker | [Configuration](docs/configuration.md) |
| LAN and multi-host deployment | [LAN Deployment](docs/lan-deployment.md) |
| Migrating from `.env` files | [Migration Guide](docs/migration-env-to-phoenix.md) |
| Threat model and security boundaries | [Threat Model](docs/threat-model.md) |
| API endpoint reference | [API Reference](docs/api-reference-index.md) |
| Admin token lifecycle | [Admin Token Lifecycle](docs/admin-token-lifecycle.md) |
| Roadmap | [Roadmap](docs/roadmap.md) |

---

## Security Model

**Phoenix helps with:**
- keeping secret values out of model context, prompts, and tool responses
- per-agent authorization and scoped access control
- cryptographic identity via mTLS and sealed-response key pairs
- audit visibility for every read, deny, and resolution attempt
- safer multi-agent operation on shared hosts with separated identities

**Phoenix does not solve:**
- root/kernel compromise on the host
- malicious admins with direct file access
- every possible plaintext path without policy and deployment discipline

See the full [Threat Model](docs/threat-model.md).

---

## Development

```bash
go test ./... -count=1        # run all tests
go build -o bin/ ./cmd/...    # build both binaries
```

Dependencies: `golang.org/x/crypto`, `golang.org/x/term`.

---

## License

MIT
