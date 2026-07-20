#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 04 exec-credential-stripping
init_scenario 04
start_server
phoenix_admin set exec/key -v synthetic-exec-value >/dev/null
PHOENIX_TOKEN="$ADMIN_TOKEN" "$PHOENIX" exec --env APP_SECRET=phoenix://exec/key -- env >"$RUN_DIR/env"
grep -qx 'APP_SECRET=synthetic-exec-value' "$RUN_DIR/env" || die "secret not injected"
for key in PHOENIX_TOKEN PHOENIX_CLIENT_CERT PHOENIX_CLIENT_KEY PHOENIX_SERVER; do ! grep -q "^$key=" "$RUN_DIR/env" || die "$key leaked"; done
PHOENIX_TOKEN="$ADMIN_TOKEN" "$PHOENIX" exec --output-env "$RUN_DIR/out.env" --env APP_SECRET=phoenix://exec/key -- true >/dev/null
grep -qx 'APP_SECRET=synthetic-exec-value' "$RUN_DIR/out.env" || die "output-env mismatch"
[[ "$(stat -c %a "$RUN_DIR/out.env")" == 600 ]] || die "output-env mode is not 0600"
ok "Scenario 04 PASS"
