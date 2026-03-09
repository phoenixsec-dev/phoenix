# Release Runbook

## 1) Preflight

- Clean working tree on `main`
- CI passing
- Version string correct (`internal/version/version.go`)
- Confirm release tag (example: `v0.10.3`)

## 2) Tag and Push

```bash
git checkout main
git pull --ff-only
git tag -a vX.Y.Z -m "Phoenix vX.Y.Z"
git push origin main
git push origin vX.Y.Z
```

## 3) Verify GitHub Release Artifacts

Expected from GoReleaser:
- `phoenix_vX.Y.Z_linux_amd64.tar.gz`
- `phoenix_vX.Y.Z_linux_arm64.tar.gz`
- `phoenix_vX.Y.Z_darwin_amd64.tar.gz`
- `phoenix_vX.Y.Z_darwin_arm64.tar.gz`
- `checksums.txt`

## 4) Verify Docker Publish

After tagged workflow completes:

```bash
docker pull phoenixsecdev/phoenix:latest
docker pull phoenixsecdev/phoenix:vX.Y.Z
docker run --rm phoenixsecdev/phoenix:vX.Y.Z --version
docker run --rm phoenixsecdev/phoenix:vX.Y.Z phoenix-server --version
```

## 5) `phoenix-server --init` Smoke (<2 min target)

```bash
tmp="$(mktemp -d)"
phoenix-server --init "$tmp"
phoenix-server --config "$tmp/config.json" &
pid=$!
sleep 2
kill "$pid"
rm -rf "$tmp"
```

Success criteria:
- init prints admin token + generated file paths
- server starts cleanly from generated config

