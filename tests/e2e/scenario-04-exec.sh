#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 04 exec-credential-stripping
init_scenario 04
start_server
phoenix_admin set exec/key -v synthetic-exec-value >/dev/null
# Phoenix credentials in the caller's environment must never reach the child.
PHOENIX_TOKEN="$ADMIN_TOKEN" PHOENIX_MCP_TOKEN=synthetic-mcp-token PHOENIX_MASTER_PASSPHRASE=synthetic-passphrase \
  OP_SERVICE_ACCOUNT_TOKEN=synthetic-op-token \
  "$PHOENIX" exec --env APP_SECRET=phoenix://exec/key -- env >"$RUN_DIR/env"
grep -qx 'APP_SECRET=synthetic-exec-value' "$RUN_DIR/env" || die "secret not injected"
for key in PHOENIX_TOKEN PHOENIX_SERVER PHOENIX_MCP_TOKEN PHOENIX_MASTER_PASSPHRASE OP_SERVICE_ACCOUNT_TOKEN; do ! grep -q "^$key=" "$RUN_DIR/env" || die "$key leaked"; done
PHOENIX_TOKEN="$ADMIN_TOKEN" "$PHOENIX" exec --output-env "$RUN_DIR/out.env" --env APP_SECRET=phoenix://exec/key -- true >/dev/null
grep -qx 'APP_SECRET=synthetic-exec-value' "$RUN_DIR/out.env" || die "output-env mismatch"
[[ "$(stat -c %a "$RUN_DIR/out.env")" == 600 ]] || die "output-env mode is not 0600"
ok "Scenario 04 PASS"
