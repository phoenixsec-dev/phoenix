# Phoenix Public Roadmap

> This roadmap is directional and may change based on user feedback.
> It is not a contractual delivery commitment.

## In Progress

### 1) Reference-Only Enforcement (Agent Context Design Mode)

Primary near-term patch:

- enforce the reference-only design in Agent Context Design mode
- remove behavior/documentation drift so runtime behavior and docs match
- preserve explicit, auditable secret-resolution boundaries
- update examples/skill guidance to prefer `phoenix exec` reference workflows by default

## Planned (Near-Term)

### 2) HTTP MCP Server Integration

Planned for the upcoming release cycle:

- merge the completed HTTP MCP server patch
- include docs and release notes for the new MCP transport path
- keep existing local MCP workflows supported

### 3) Web UI (Read-Only First)

Initial direction for UI work:

- start with read-only visibility (inventory, audit timeline, status)
- keep secret mutation flows in CLI/API paths for strong auditability
- expand capabilities after validating user demand and threat model fit

## Exploring (Post-Launch)

These are under consideration and will be prioritized by real-world usage:

- multi-user/team workflows
- advanced policy controls and simulation
- rotation automation and lifecycle UX improvements
- enterprise deployment/distribution options

---

Last updated: 2026-03-02
