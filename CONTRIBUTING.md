# Contributing

Thanks for your interest in contributing to Phoenix.

## Development Setup

- Go 1.25+
- Clone repo and run:

```bash
go test ./... -count=1 -race
go vet ./...
```

## Pull Requests

Please keep PRs focused and include:
- problem statement
- summary of changes
- test coverage or validation notes
- docs updates when behavior changes

## Style / Quality

- Keep changes small and reviewable.
- Preserve security-first behavior (never log secret values).
- Add/adjust tests for security-sensitive paths.

## Commit Guidance

Conventional-style prefixes are preferred:
- `feat:`
- `fix:`
- `docs:`
- `test:`
- `chore:`

## Security Issues

If your finding is security-sensitive, follow `SECURITY.md` instead of opening a public issue.
