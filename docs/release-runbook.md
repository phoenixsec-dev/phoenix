# Release Runbook

## 1) Preflight

- Clean working tree on `main`
- CI passing
- Version string correct (`internal/version/version.go`)
- Confirm release tag (example: `v0.13.3`)

## 1b) Local dry run (no publishing)

Run before tagging. GoReleaser must be the same version pinned in
`.github/workflows/release.yml` (currently v2.18.2; download the release
binary and verify it against its `checksums.txt`).

```bash
goreleaser check
goreleaser release --snapshot --clean --skip=publish   # builds dist/, publishes nothing

# install.sh against the snapshot, served locally
(cd dist && python3 -m http.server 18765 --bind 127.0.0.1 &)
V=$(ls dist/*_linux_amd64.tar.gz | sed 's/.*phoenix_\(.*\)_linux_amd64.tar.gz/\1/')
PHOENIX_VERSION="v$V" PHOENIX_BASE_URL=http://127.0.0.1:18765 \
  INSTALL_DIR=/tmp/phx-bin sh scripts/install.sh
PATH=/tmp/phx-bin:$PATH scripts/quickstart-smoke.sh

# Docker image: build locally (no push) and run the Docker quickstart
docker build -t phoenix:dryrun .
scripts/quickstart-smoke.sh --docker phoenix:dryrun
```

Stop the `http.server` afterwards. The CI `docker` job also builds both
platforms without pushing on every PR.

## 2) Tag and Push

```bash
git checkout main
git pull --ff-only
git tag -a vX.Y.Z -m "Phoenix vX.Y.Z"
git push origin main
git push origin vX.Y.Z
```

## 3) Verify GitHub Release Artifacts

Expected from GoReleaser (archive names carry the version **without** the
leading `v`; `scripts/install.sh` depends on this):
- `phoenix_X.Y.Z_linux_amd64.tar.gz`
- `phoenix_X.Y.Z_linux_arm64.tar.gz`
- `phoenix_X.Y.Z_darwin_amd64.tar.gz`
- `phoenix_X.Y.Z_darwin_arm64.tar.gz`
- `checksums.txt`

Tags with a `-` (e.g. `vX.Y.Z-rc1`) publish as GitHub pre-releases and do
not move Docker `latest`.

Then check the real installer end to end:

```bash
PHOENIX_VERSION=vX.Y.Z INSTALL_DIR=/tmp/phx-bin sh scripts/install.sh
/tmp/phx-bin/phoenix-server --version
```

## 4) Verify Docker Publish

After tagged workflow completes:

```bash
docker pull phoenixsecdev/phoenix:latest
docker pull phoenixsecdev/phoenix:vX.Y.Z
docker run --rm phoenixsecdev/phoenix:vX.Y.Z --version                       # phoenix-server (the entrypoint)
docker run --rm --entrypoint phoenix phoenixsecdev/phoenix:vX.Y.Z version    # CLI
scripts/quickstart-smoke.sh --docker phoenixsecdev/phoenix:vX.Y.Z
```

## 5) Quickstart smoke (<2 min target)

```bash
PATH=/tmp/phx-bin:$PATH scripts/quickstart-smoke.sh
```

This runs the [Quickstart](quickstart.md) commands exactly (init, start,
set, get, exec) and fails if any step breaks or the run exceeds 120s.
