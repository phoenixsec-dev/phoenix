# Phoenix: notes for coding agents

Phoenix is a secrets manager, so a small mistake here can leak a credential. Read
`README.md` and `CONTRIBUTING.md` first. `CLAUDE.md` is a symlink to this file.

## Checks

Run the same checks CI runs before you call a change done:

```bash
go test ./... -count=1 -race
go vet ./...
gofmt -l .          # must print nothing
staticcheck ./...   # CI pins v0.7.0; see .github/workflows/ci.yml
```

## Rules

- **Stay inside the task.** If you find another problem, report it. Do not fix it in
  the same change.
- **Never print, log or commit a secret value,** in code, tests, examples or docs.
- **No new dependencies** without the maintainer's OK.
- **A removed setting, flag or command is never silently ignored.** The server refuses
  to start, or the CLI says why it went and what to use instead.
- **Agents learn Phoenix only from what ships with it:** `phoenix-skill/SKILL.md`, the
  MCP and plugin tool descriptions, and the suggested snippet. If your change affects
  what an agent should do, update those in the same change.
- **Docs travel with the code.** Update `docs/` and add a line under `## Unreleased`
  in `RELEASE_NOTES.md` for anything a user would notice.
- **Leave the version alone.** Do not edit `internal/version/version.go` or create
  tags. The maintainer does both at release.
- Put a short comment above each new function saying what it is for. Keep tests small
  and focused. Commit in logical pieces with plain-English messages.
