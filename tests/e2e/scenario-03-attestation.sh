#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 03 attestation-policy
init_scenario 03
start_server
for p in local/key denied/key mtls/key; do phoenix_admin set "$p" -v synthetic-attestation >/dev/null; done
stop_server
cat >"$RUN_DIR/policy.json" <<'JSON'
{"attestation":{"local/*":{"source_ip":["127.0.0.1","::1"]},"denied/*":{"source_ip":["192.0.2.9"]},"mtls/*":{"require_mtls":true}}}
JSON
config_patch "d['policy']={'path':'$RUN_DIR/policy.json'}"
start_server
assert_eq "$(phoenix_admin get local/key)" synthetic-attestation
for p in denied/key mtls/key; do if phoenix_admin get "$p" >"$RUN_DIR/deny" 2>&1; then die "$p unexpectedly allowed"; fi; done
assert_contains "$(phoenix_admin audit -n 30)" attestation "attestation audit"
ok "Scenario 03 PASS"
