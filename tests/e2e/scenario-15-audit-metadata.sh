#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 15 openclaw-audit-metadata
init_scenario 15
start_server
phoenix_admin set auditmeta/allowed -v synthetic-audit >/dev/null
phoenix_admin set restricted/key -v synthetic-restricted >/dev/null
phoenix_admin agent create audit-reader -t synthetic-audit-reader --acl 'auditmeta/*:read' >/dev/null
long="$(python3 -c 'print("x"*300)')"; formatted=$'agent\u202Ename'; sentinel=synthetic-session-key-must-not-log
curl -fsS "$PHOENIX_SERVER/v1/secrets/auditmeta/allowed" -H 'Authorization: Bearer synthetic-audit-reader' -H "X-OpenClaw-Agent: $formatted" -H 'X-OpenClaw-Session-Id: session-123' -H "X-OpenClaw-Channel: $long" -H 'X-OpenClaw-Requester-Sender: synthetic@example.invalid' -H 'X-OpenClaw-Sender-Is-Owner: true' -H "X-OpenClaw-Session-Key: $sentinel" >/dev/null
code="$(curl -sS -o "$RUN_DIR/spoof" -w '%{http_code}' "$PHOENIX_SERVER/v1/secrets/restricted/key" -H 'Authorization: Bearer synthetic-audit-reader' -H 'X-OpenClaw-Agent: admin' -H 'X-OpenClaw-Sender-Is-Owner: true')"
assert_eq "$code" 403 "spoofed authorization"
audit="$(api_admin GET /v1/audit)"
assert_not_contains "$audit" "$sentinel" "session key leaked"
entry="$(jq -c '[.entries[] | select(.path=="auditmeta/allowed" and .action=="read_value")][-1]' <<<"$audit")"
assert_eq "$(jq -r .agent <<<"$entry")" audit-reader
assert_eq "$(jq -r '.metadata["openclaw.agent"]' <<<"$entry")" agentname
assert_eq "$(jq -r '.metadata["openclaw.channel"] | length' <<<"$entry")" 256
[[ "$(jq -r '.metadata | has("openclaw.session_key")' <<<"$entry")" == false ]] || die "session key metadata captured"
deny="$(jq -c '[.entries[] | select(.path=="restricted/key" and .status=="denied")][-1]' <<<"$audit")"
assert_eq "$(jq -r .agent <<<"$deny")" audit-reader
assert_eq "$(jq -r '.metadata["openclaw.agent"]' <<<"$deny")" admin
ok "Scenario 15 PASS"
