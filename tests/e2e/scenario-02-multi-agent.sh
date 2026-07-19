#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 02 multi-agent-isolation
init_scenario 02
start_server
phoenix_admin set dev/key -v synthetic-dev >/dev/null
phoenix_admin set prod/key -v synthetic-prod >/dev/null
phoenix_admin agent create dev-agent -t synthetic-dev-token --acl 'dev/*:read,write' >/dev/null
phoenix_admin agent create prod-agent -t synthetic-prod-token --acl 'prod/*:read' >/dev/null
assert_eq "$(PHOENIX_TOKEN=synthetic-dev-token "$PHOENIX" get dev/key)" synthetic-dev
assert_eq "$(PHOENIX_TOKEN=synthetic-prod-token "$PHOENIX" get prod/key)" synthetic-prod
if PHOENIX_TOKEN=synthetic-dev-token "$PHOENIX" get prod/key >"$RUN_DIR/deny" 2>&1; then die "cross-namespace read allowed"; fi
assert_contains "$(phoenix_admin audit -n 30)" denied "denial audit"
ok "Scenario 02 PASS"
