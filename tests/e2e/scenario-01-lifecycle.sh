#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 01 lifecycle
init_scenario 01
start_server
phoenix_admin set lifecycle/one -v synthetic-one >/dev/null
printf 'synthetic-two' | phoenix_admin set lifecycle/two --value-stdin >/dev/null
assert_eq "$(phoenix_admin get lifecycle/one)" synthetic-one "get"
assert_contains "$(phoenix_admin list lifecycle/)" lifecycle/two "list"
phoenix_admin export lifecycle/ -f env >"$RUN_DIR/export.env"
phoenix_admin delete lifecycle/two >/dev/null
assert_not_contains "$(phoenix_admin list lifecycle/ || true)" lifecycle/two "delete"
assert_not_contains "$(cat "$RUN_DIR/store.json")" synthetic-one "plaintext at rest"
assert_contains "$(phoenix_admin audit -n 20)" lifecycle/one "audit"
ok "Scenario 01 PASS"
