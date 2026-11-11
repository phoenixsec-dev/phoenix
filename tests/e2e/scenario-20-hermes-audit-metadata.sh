#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 20 hermes-audit-metadata
init_scenario 20
start_server
printf '%s' synthetic-hermes-audit | phoenix_admin set hermesmeta/allowed --value-stdin >/dev/null
printf '%s' synthetic-restricted | phoenix_admin set restricted/key --value-stdin >/dev/null
printf '%s' synthetic-tooled | phoenix_admin set tooled/key --value-stdin >/dev/null
phoenix_admin agent create hermes-reader -t synthetic-hermes-reader --acl 'hermesmeta/*:list,read_value;tooled/*:list,read_value' >/dev/null
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

# Tool headers decide nothing: X-Hermes-Tool is an audit hint only, and
# X-Phoenix-Tool (once a tool-rule input, now removed) is ignored entirely.
body="$(curl -fsS "$PHOENIX_SERVER/v1/secrets/tooled/key" \
  -H 'Authorization: Bearer synthetic-hermes-reader' -H 'X-Hermes-Tool: phoenix_resolve' -H 'X-Phoenix-Tool: wrong_tool')"
assert_eq "$(jq -r .value <<<"$body")" synthetic-tooled "tool headers must not change access"
audit="$(api_admin GET /v1/audit)"
toolread="$(jq -c '[.entries[] | select(.path=="tooled/key" and .status=="allowed")][-1]' <<<"$audit")"
assert_eq "$(jq -r '.metadata["hermes.tool"]' <<<"$toolread")" phoenix_resolve "hermes tool recorded as hint"
[[ "$(jq -r '[.entries[].metadata // {} | keys[]] | map(select(startswith("phoenix."))) | length' <<<"$audit")" == 0 ]] \
  || die "X-Phoenix-Tool captured as caller metadata"
ok "Scenario 20 PASS"
