#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 16 elevated-step-up
init_scenario 16
config_patch "d['session']={'enabled':True,'ttl':'3s','roles':{'prod-stepup':{'namespaces':['prod/*'],'actions':['read_value'],'bootstrap_trust':['bearer'],'step_up':True,'step_up_ttl':'5s','elevates_acl':True}}}"
start_server
phoenix_admin set prod/key -v synthetic-prod-stepup >/dev/null
phoenix_admin agent create stepup-reader -t synthetic-stepup-reader --acl 'dev/*:read' >/dev/null
mint() { curl -fsS -X POST "$PHOENIX_SERVER/v1/session/mint" -H 'Authorization: Bearer synthetic-stepup-reader' -H 'Content-Type: application/json' --data '{"role":"prod-stepup"}'; }
first="$(mint)"; deny_id="$(jq -r .approval_id <<<"$first")"
api_admin POST "/v1/approval/$deny_id/deny" '{}' >/dev/null
status="$(api_token synthetic-stepup-reader GET "/v1/approval/$deny_id")"
assert_eq "$(jq -r .status <<<"$status")" denied
second="$(mint)"; approve_id="$(jq -r .approval_id <<<"$second")"
api_admin POST "/v1/approval/$approve_id/approve" '{}' >/dev/null
approved="$(api_token synthetic-stepup-reader GET "/v1/approval/$approve_id")"; session="$(jq -r .session_token <<<"$approved")"
[[ "$session" == phxs_* ]] || die "approved session token missing"
assert_eq "$(PHOENIX_TOKEN="$session" "$PHOENIX" get prod/key)" synthetic-prod-stepup
renew_code="$(curl -sS -o "$RUN_DIR/renew" -w '%{http_code}' -X POST "$PHOENIX_SERVER/v1/session/renew" -H "Authorization: Bearer $session" -H 'Content-Type: application/json' --data '{}')"
assert_eq "$renew_code" 403 "elevated renewal status"
assert_eq "$(jq -r .code "$RUN_DIR/renew")" STEP_UP_REAPPROVAL_REQUIRED
sleep 4
if PHOENIX_TOKEN="$session" "$PHOENIX" get prod/key >"$RUN_DIR/expired" 2>&1; then die "expired step-up session accepted"; fi
ok "Scenario 16 PASS"
