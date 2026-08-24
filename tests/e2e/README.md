# Phoenix end-to-end harness

The canonical Phoenix e2e suite. It runs only throwaway state, localhost-bound services, and synthetic values. Run the full matrix in an isolated test environment.

## Run

```bash
./tests/e2e/run-all.sh --list
./tests/e2e/run-all.sh --scenarios 01,13,17
./tests/e2e/run-all.sh --format jsonl   # or: --format tap
```

The core suite needs Bash, Go, curl, Python 3, and jq. Set `GO_BIN` for a non-PATH Go executable, `E2E_BIN_DIR` to reuse prebuilt binaries, or `E2E_REBUILD=1` to force a rebuild.

> Binaries in `E2E_BIN_DIR` are reused whenever they already exist. After changing server behavior, run with `E2E_REBUILD=1` — otherwise scenarios silently test the previously built binary and a new assertion fails as if the feature were broken.

Scenario 09 additionally needs Docker Compose and `psql`; it chooses a per-run project and free localhost port. Scenario 12 is opt-in: it needs the `op` CLI, `OP_SERVICE_ACCOUNT_TOKEN`, and a read-only synthetic vault selected by `PHOENIX_E2E_OP_VAULT` (default `phoenix-test`). Manual `stack.sh` use can override `COMPOSE_PROJECT_NAME` and the `E2E_*_PORT` variables. Scenario 18 builds Git commit `21a6ca4` (v0.13.5) and the current checkout.

## Add a scenario

1. Add one executable `scenario-NN-name.sh`; do not edit a registry.
2. Source `lib.sh`, call `scenario_start`, and use a unique `init_scenario NN`.
3. Keep setup, assertions, and teardown in that file; shared mechanics belong in `lib.sh`.
4. Confirm discovery with `./run-all.sh --list`.
5. Confirm isolated execution with `./run-all.sh --scenarios NN --format jsonl`.

## Conventions for agents

- Exit `0` for pass, `77` for an explicit environmental skip, and nonzero for failure.
- Never use real secrets, production Phoenix, or production credentials. Values must be visibly synthetic.
- Bind listeners and fixture ports to localhost only.
- No prompts or manual approval steps; drive approval APIs programmatically.
- Every scenario must be repeatable and clean up its process, temporary state, and containers.
- Do not print tokens or resolved values except synthetic expected values in controlled assertions.
- Machine consumers should use JSON Lines or TAP rather than scrape colored human logs.

## Inventory

| ID | Coverage | Status |
|---:|---|---|
| 01–04 | lifecycle, ACL isolation, attestation, exec stripping | implemented |
| 05–08 | rotation under load, cert lifecycle, time/nonce, short-lived tokens | implemented |
| 09–11 | PostgreSQL rotation, MCP stdio, zero-plaintext config | implemented |
| 12 | 1Password read-only backend: resolve, write rejection, missing item | implemented; opt-in, exits 77 when `OP_SERVICE_ACCOUNT_TOKEN` is unset |
| 13 | OpenClaw exec-provider protocol and edge cases | implemented |
| 14 | bearer-role, mTLS-role, pre-minted session, invalid auth combinations | implemented |
| 15 | sanitized audit metadata and spoof resistance | implemented |
| 16 | elevated step-up deny/approve/expiry/renewal | implemented |
| 17 | sealed-response S1–S8 plus policy/keypair regressions | implemented |
| 18 | v0.13.5 → current in-place data/config/ACL/audit upgrade | implemented |
| 19 | secure transport: `tls:` block HTTPS, non-loopback plaintext warnings (server/CLI/MCP), mTLS backward compat, MCP `--tls-cert`/`--tls-key` | implemented; non-loopback warning asserted via unbindable TEST-NET-1 address so no listener leaves loopback |
| 20 | Hermes caller metadata: capture, sanitization/cap, unlisted-header exclusion, ACL spoof resistance, `X-Hermes-Tool` vs `X-Phoenix-Tool` | implemented |

Active sessions are intentionally memory-only. Scenario 18 verifies that an old in-memory token is rejected after restart and that the preserved role configuration can mint a new compatible session.
