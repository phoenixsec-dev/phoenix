#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 02 multi-agent-isolation
init_scenario 02
start_server
printf '%s' synthetic-dev | phoenix_admin set dev/key --value-stdin >/dev/null
printf '%s' synthetic-prod | phoenix_admin set prod/key --value-stdin >/dev/null
phoenix_admin agent create dev-agent -t synthetic-dev-token --acl 'dev/*:list,read_value,write' >/dev/null
phoenix_admin agent create prod-agent -t synthetic-prod-token --acl 'prod/*:list,read_value' >/dev/null
assert_eq "$(PHOENIX_TOKEN=synthetic-dev-token "$PHOENIX" get dev/key)" synthetic-dev
assert_eq "$(PHOENIX_TOKEN=synthetic-prod-token "$PHOENIX" get prod/key)" synthetic-prod
if PHOENIX_TOKEN=synthetic-dev-token "$PHOENIX" get prod/key >"$RUN_DIR/deny" 2>&1; then die "cross-namespace read allowed"; fi
assert_contains "$(phoenix_admin audit -n 30)" denied "denial audit"
ok "Scenario 02 PASS"
