# Quickstart: first secret in under 2 minutes

Two paths: native binaries or Docker. Both end with a secret stored and
read back, and a dashboard where you can answer agents' requests. Storing,
reading and signing in to the dashboard are exercised by
[`scripts/quickstart-smoke.sh`](../scripts/quickstart-smoke.sh), and the
request-and-approve part by end-to-end scenario 24;
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

It asks for a dashboard password (press Enter to have one generated), then
prints the `ADMIN TOKEN` and, if it made one, the `DASHBOARD PASSWORD`. Copy what
it prints: it is shown once and never again. The password is stored only as a
bcrypt hash.

Run this yourself, not through an agent: the dashboard password is what stops
an agent from approving its own requests.

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

**5. Sign in to the dashboard** at `http://127.0.0.1:9090/dashboard/` with the
password from step 2. That is where you answer agents' requests; see
[Let an agent ask](#let-an-agent-ask).

## Option B: Docker

**1. Initialize** a named volume. `--https` turns on the HTTPS address, which is
how you reach the dashboard from outside the container:

```bash
docker run --rm -v phoenix-data:/data phoenixsecdev/phoenix --init /data --https
```

It prints the `ADMIN TOKEN` and a generated `DASHBOARD PASSWORD`. Copy both:
they are shown once and never again. (With `docker run -it` it asks for a
password instead.) As above, run this yourself, not through an agent.

**2. Start the server,** published to this machine only:

```bash
docker run -d --name phoenix -p 127.0.0.1:9443:9443 -v phoenix-data:/data \
  --restart unless-stopped phoenixsecdev/phoenix
```

**3. Store and use a secret** with the CLI that ships inside the image:

```bash
export PHOENIX_TOKEN="<admin token from step 1>"

printf '%s' 'sk-demo-123' | docker exec -i -e PHOENIX_TOKEN phoenix phoenix set demo/api-key --value-stdin
docker exec -e PHOENIX_TOKEN phoenix phoenix get demo/api-key
```

`-e PHOENIX_TOKEN` (no `=value`) passes the variable through from your
shell, so the token never appears on the `docker` command line.

**4. Sign in to the dashboard** at `https://127.0.0.1:9443/dashboard/` with the
password from step 1. The browser warns about the certificate, because
Phoenix's own CA signed it: import the `ca.crt` copied below, or accept it for
this machine. That is where you answer agents' requests; see
[Let an agent ask](#let-an-agent-ask).

### Reaching the container from the host

Traffic from the host crosses a wire (the Docker bridge), and Phoenix treats
every network, Docker bridges included, as untrusted. So only HTTPS on 9443
is published; its certificate covers `127.0.0.1` and `localhost`. Plain HTTP
stays on the container's own loopback.

```bash
# trust the Phoenix CA, then talk HTTPS from the host CLI
docker cp phoenix:/data/ca.crt ~/.phoenix-ca.crt
export PHOENIX_SERVER="https://127.0.0.1:9443"
export PHOENIX_CA_CERT=~/.phoenix-ca.crt
phoenix get demo/api-key
```

Initialized without `--https`? Set `https_listener.enabled` to `true` in
`/data/config.json` and restart the container.

For other machines on your LAN, re-issue the server certificate with the
host's LAN IP and publish without the `127.0.0.1:` prefix. See
[LAN Deployment](lan-deployment.md).

## Let an agent ask

Make an agent that may read nothing, and let it ask. With Docker, run the
`phoenix` commands through `docker exec -e PHOENIX_TOKEN phoenix phoenix ...`
(add `-e PHOENIX_SEAL_KEY`), and use paths inside the container.

```bash
# as admin: the agent, and a seal key so it only ever gets encrypted values
AGENT_TOKEN="$(openssl rand -hex 32)"
phoenix agent create demo-agent -t "$AGENT_TOKEN" --acl 'demo-none/*:list'
phoenix keypair generate demo-agent -o /tmp/demo-agent.seal.key

# as the agent
export PHOENIX_TOKEN="$AGENT_TOKEN" PHOENIX_SEAL_KEY=/tmp/demo-agent.seal.key
phoenix request demo/api-key --reason "trying it out" --ttl 15m
# you: dashboard -> Approvals -> Approve
phoenix exec --env API_KEY=phoenix://demo/api-key -- sh -c 'echo "API_KEY has ${#API_KEY} chars"'
```

More in [Access Requests](access-requests.md).

## Next steps

- Stop using the admin token for day-to-day work: create scoped agents
  ([Multi-Agent Setup](multi-agent-setup.md),
  [Admin Token Lifecycle](admin-token-lifecycle.md)).
- Import an existing `.env` file:
  [Migration Guide](migration-env-to-phoenix.md).
- Connect Claude Code, OpenClaw, or an SDK:
  [Integrations](integrations.md).
