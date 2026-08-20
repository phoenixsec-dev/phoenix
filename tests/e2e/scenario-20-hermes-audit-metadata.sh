#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 20 hermes-audit-metadata
init_scenario 20
start_server
phoenix_admin set hermesmeta/allowed -v synthetic-hermes-audit >/dev/null
phoenix_admin set restricted/key -v synthetic-restricted >/dev/null
phoenix_admin set tooled/key -v synthetic-tooled >/dev/null
phoenix_admin agent create hermes-reader -t synthetic-hermes-reader --acl 'hermesmeta/*:read;tooled/*:read' >/dev/null
long="$(python3 -c 'print("x"*300)')"; formatted=$'kit\u202Emain'; sentinel=synthetic-hermes-key-must-not-log

# All five Hermes headers, plus unlisted and credential-shaped headers that must be ignored.
curl -fsS "$PHOENIX_SERVER/v1/secrets/hermesmeta/allowed" -H 'Authorization: Bearer synthetic-hermes-reader' \
  -H "X-Hermes-Profile: $formatted" -H 'X-Hermes-Session-Id: hermes-session-77' -H "X-Hermes-Channel: $long" \
  -H 'X-Hermes-Tool: phoenix_get' -H 'X-Hermes-Task-Id: task-104' \
  -H "X-Hermes-Session-Key: $sentinel" -H 'X-Hermes-Role: admin' -H 'X-Hermes-Agent: admin' >/dev/null

# Spoofed Hermes identity must not widen ACL.
code="$(curl -sS -o "$RUN_DIR/spoof" -w '%{http_code}' "$PHOENIX_SERVER/v1/secrets/restricted/key" \
  -H 'Authorization: Bearer synthetic-hermes-reader' -H 'X-Hermes-Profile: admin' -H 'X-Hermes-Tool: phoenix_get')"
assert_eq "$code" 403 "spoofed authorization"

audit="$(api_admin GET /v1/audit)"
assert_not_contains "$audit" "$sentinel" "hermes session key leaked"
entry="$(jq -c '[.entries[] | select(.path=="hermesmeta/allowed" and .action=="read_value")][-1]' <<<"$audit")"
assert_eq "$(jq -r .agent <<<"$entry")" hermes-reader "authenticated agent preserved"
assert_eq "$(jq -r '.metadata["hermes.profile"]' <<<"$entry")" kitmain "format controls stripped"
assert_eq "$(jq -r '.metadata["hermes.session_id"]' <<<"$entry")" hermes-session-77
assert_eq "$(jq -r '.metadata["hermes.channel"] | length' <<<"$entry")" 256 "256-char cap"
assert_eq "$(jq -r '.metadata["hermes.tool"]' <<<"$entry")" phoenix_get
assert_eq "$(jq -r '.metadata["hermes.task_id"]' <<<"$entry")" task-104
assert_eq "$(jq -r '.metadata | keys | length' <<<"$entry")" 5 "exactly the five allowlisted keys"
for k in hermes.session_key hermes.role hermes.agent; do
  [[ "$(jq -r --arg k "$k" '.metadata | has($k)' <<<"$entry")" == false ]] || die "unlisted header captured: $k"
done
deny="$(jq -c '[.entries[] | select(.path=="restricted/key" and .status=="denied")][-1]' <<<"$audit")"
assert_eq "$(jq -r .agent <<<"$deny")" hermes-reader "denial records real agent"
assert_eq "$(jq -r '.metadata["hermes.profile"]' <<<"$deny")" admin "spoof recorded as hint only"

# X-Hermes-Tool is an audit hint; X-Phoenix-Tool is the attestation input.
stop_server
cat >"$RUN_DIR/policy.json" <<'JSON'
{"attestation":{"tooled/*":{"allowed_tools":["phoenix_resolve"]}}}
JSON
config_patch "d['policy']={'path':'$RUN_DIR/policy.json'}"
start_server
code="$(curl -sS -o "$RUN_DIR/toolspoof" -w '%{http_code}' "$PHOENIX_SERVER/v1/secrets/tooled/key" \
  -H 'Authorization: Bearer synthetic-hermes-reader' -H 'X-Hermes-Tool: phoenix_resolve' -H 'X-Phoenix-Tool: wrong_tool')"
assert_eq "$code" 403 "X-Hermes-Tool must not satisfy allowed_tools"
body="$(curl -fsS "$PHOENIX_SERVER/v1/secrets/tooled/key" \
  -H 'Authorization: Bearer synthetic-hermes-reader' -H 'X-Hermes-Tool: anything-at-all' -H 'X-Phoenix-Tool: phoenix_resolve')"
assert_eq "$(jq -r .value <<<"$body")" synthetic-tooled "genuine X-Phoenix-Tool still attests"
audit="$(api_admin GET /v1/audit)"
tooldeny="$(jq -c '[.entries[] | select(.path=="tooled/key" and .status=="denied")][-1]' <<<"$audit")"
assert_eq "$(jq -r '.metadata["hermes.tool"]' <<<"$tooldeny")" phoenix_resolve "hermes tool recorded as hint"
[[ "$(jq -r '[.entries[].metadata // {} | keys[]] | map(select(startswith("phoenix."))) | length' <<<"$audit")" == 0 ]] \
  || die "X-Phoenix-Tool captured as caller metadata"
ok "Scenario 20 PASS"
