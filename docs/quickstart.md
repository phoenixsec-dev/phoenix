# Quickstart: first secret in under 2 minutes

Two paths: native binaries or Docker. Both end with a secret stored and
read back. Everything after the install step
is exercised by [`scripts/quickstart-smoke.sh`](../scripts/quickstart-smoke.sh);
the installer itself is checked on every release
([Release Runbook](release-runbook.md)).

For the full walkthrough (file permissions, LAN, dashboard), see
[Getting Started](getting-started.md).

## Option A: binaries (Linux / macOS)

**1. Install** (verifies the release checksum before installing):

```bash
curl -fsSL https://raw.githubusercontent.com/phoenixsec-dev/phoenix/main/scripts/install.sh | sh
```

**2. Initialize** a data directory:

```bash
phoenix-server --init ~/.phoenix
```

Copy the `ADMIN TOKEN` it prints. It is shown once and never again.

**3. Start the server** (leave it running; use a second terminal for step 4):

```bash
phoenix-server --config ~/.phoenix/config.json
```

**4. Store and use a secret:**

```bash
export PHOENIX_TOKEN="<admin token from step 2>"

printf '%s' 'sk-demo-123' | phoenix set demo/api-key --value-stdin
phoenix get demo/api-key
phoenix exec --env API_KEY=phoenix://demo/api-key -- sh -c 'echo "API_KEY has ${#API_KEY} chars"'
```

The CLI talks to `http://127.0.0.1:9090` by default, so `PHOENIX_SERVER`
does not need setting. `--value-stdin` keeps the value out of the process
list; `phoenix exec` hands the secret to the child process without it
ever being printed.

## Option B: Docker

**1. Initialize** a named volume (prints the admin token once):

```bash
docker run --rm -v phoenix-data:/data phoenixsecdev/phoenix --init /data
```

**2. Start the server:**

```bash
docker run -d --name phoenix -v phoenix-data:/data --restart unless-stopped phoenixsecdev/phoenix
```

**3. Store and use a secret** with the CLI that ships inside the image:

```bash
export PHOENIX_TOKEN="<admin token from step 1>"

printf '%s' 'sk-demo-123' | docker exec -i -e PHOENIX_TOKEN phoenix phoenix set demo/api-key --value-stdin
docker exec -e PHOENIX_TOKEN phoenix phoenix get demo/api-key
```

`-e PHOENIX_TOKEN` (no `=value`) passes the variable through from your
shell, so the token never appears on the `docker` command line.

No `-p` port mapping yet, on purpose: the generated config listens on the
container's own loopback (`127.0.0.1:9090`), so nothing outside the
container can reach it. That is the safe default.

### Reaching the container from the host

To use the server from outside the container, it has to listen on the
container's network interface. That crosses a wire (the Docker bridge), so
turn TLS on at the same time. Phoenix treats every network, Docker bridges
included, as untrusted. The `--init` certificate already covers
`127.0.0.1` and `localhost`.

```bash
docker rm -f phoenix

# listen on all container interfaces + enable TLS (edits /data/config.json)
docker run --rm -v phoenix-data:/data --entrypoint sed phoenixsecdev/phoenix -i \
  -e 's/"listen": "127.0.0.1:9090"/"listen": "0.0.0.0:9090"/' \
  -e '/"tls": {/{n;s/"enabled": false/"enabled": true/;}' \
  /data/config.json

# publish to host loopback only
docker run -d --name phoenix -p 127.0.0.1:9090:9090 -v phoenix-data:/data \
  --restart unless-stopped phoenixsecdev/phoenix

# trust the Phoenix CA, then talk HTTPS from the host CLI
docker cp phoenix:/data/ca.crt ~/.phoenix-ca.crt
export PHOENIX_SERVER="https://127.0.0.1:9090"
export PHOENIX_CA_CERT=~/.phoenix-ca.crt
phoenix get demo/api-key
```

For other machines on your LAN, re-issue the server certificate with the
host's LAN IP and publish without the `127.0.0.1:` prefix. See
[LAN Deployment](lan-deployment.md).

## Next steps

- Stop using the admin token for day-to-day work: create scoped agents
  ([Multi-Agent Setup](multi-agent-setup.md),
  [Admin Token Lifecycle](admin-token-lifecycle.md)).
- Import an existing `.env` file:
  [Migration Guide](migration-env-to-phoenix.md).
- Connect Claude Code, OpenClaw, or an SDK:
  [Integrations](integrations.md).
