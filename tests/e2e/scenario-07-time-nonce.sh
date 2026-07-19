#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 07 time-window-and-nonce
init_scenario 07
start_server
phoenix_admin set window/key -v synthetic-window >/dev/null
phoenix_admin set nonce/key -v synthetic-nonce >/dev/null
stop_server
cat >"$RUN_DIR/policy.json" <<'JSON'
{"attestation":{"window/*":{"time_window":"00:00-23:59","time_zone":"UTC"},"nonce/*":{"require_nonce":true,"nonce_max_age":"5s"}}}
JSON
config_patch "d['policy']={'path':'$RUN_DIR/policy.json'}; d['attestation']['nonce']={'enabled':True,'max_age':'5s'}"
start_server
assert_eq "$(phoenix_admin get window/key)" synthetic-window
if phoenix_admin resolve phoenix://nonce/key >"$RUN_DIR/no-nonce" 2>&1; then die "nonce policy allowed unsigned request"; fi
challenge="$(api_admin POST /v1/challenge '{}')"; nonce="$(jq -r .nonce <<<"$challenge")"
body="$(jq -cn --arg n "$nonce" '{refs:["phoenix://nonce/key"],nonce:$n}')"
first="$(api_admin POST /v1/resolve "$body")"
assert_eq "$(jq -r '.values["phoenix://nonce/key"]' <<<"$first")" synthetic-nonce
code="$(curl -sS -o "$RUN_DIR/replay" -w '%{http_code}' -X POST "$PHOENIX_SERVER/v1/resolve" -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' --data "$body")"
assert_eq "$code" 403 "nonce replay status"
ok "Scenario 07 PASS"
