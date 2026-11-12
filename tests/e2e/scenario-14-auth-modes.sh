#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 14 openclaw-auth-modes
init_scenario 14
config_patch "d['session']={'enabled':True,'ttl':'3s','roles':{'openclaw':{'namespaces':['auth/*'],'actions':['read_value'],'bootstrap_trust':['bearer']}}}"
start_server
base=(PHOENIX_SERVER="$PHOENIX_SERVER")
printf '%s' synthetic-auth | env "${base[@]}" PHOENIX_TOKEN="$ADMIN_TOKEN" "$PHOENIX" set auth/key --value-stdin >/dev/null
env "${base[@]}" PHOENIX_TOKEN="$ADMIN_TOKEN" "$PHOENIX" agent create openclaw-agent -t synthetic-openclaw-bootstrap --acl 'auth/*:list,read_value' >/dev/null
request='{"protocolVersion":1,"provider":"phoenix","ids":["auth/key"]}'
provider_value() { jq -r '.values["auth/key"]'; }
bearer="$(printf '%s' "$request" | env "${base[@]}" HOME="$RUN_DIR/home-bearer" PHOENIX_TOKEN=synthetic-openclaw-bootstrap PHOENIX_ROLE=openclaw "$PHOENIX" openclaw-exec-provider | provider_value)"
assert_eq "$bearer" synthetic-auth "bearer role mode"
mint="$(curl -fsS -X POST "$PHOENIX_SERVER/v1/session/mint" -H 'Authorization: Bearer synthetic-openclaw-bootstrap' -H 'Content-Type: application/json' --data '{"role":"openclaw"}')"; session="$(jq -r .session_token <<<"$mint")"
preminted="$(printf '%s' "$request" | env "${base[@]}" PHOENIX_TOKEN="$session" PHOENIX_ROLE= "$PHOENIX" openclaw-exec-provider | provider_value)"
assert_eq "$preminted" synthetic-auth "pre-minted mode"
homeless="$(printf '%s' "$request" | env -u HOME "${base[@]}" PHOENIX_TOKEN=synthetic-openclaw-bootstrap PHOENIX_ROLE=openclaw "$PHOENIX" openclaw-exec-provider | provider_value)"
assert_eq "$homeless" synthetic-auth "HOME-unset bootstrap"
fresh="$(curl -fsS -X POST "$PHOENIX_SERVER/v1/session/mint" -H 'Authorization: Bearer synthetic-openclaw-bootstrap' -H 'Content-Type: application/json' --data '{"role":"openclaw"}' | jq -r .session_token)"
if printf '%s' "$request" | env "${base[@]}" HOME="$RUN_DIR/home-invalid" PHOENIX_TOKEN="$fresh" PHOENIX_ROLE=openclaw "$PHOENIX" openclaw-exec-provider >"$RUN_DIR/invalid" 2>&1; then die "PHOENIX_ROLE plus phxs token accepted"; fi
sleep 4
if printf '%s' "$request" | env "${base[@]}" PHOENIX_TOKEN="$fresh" PHOENIX_ROLE= "$PHOENIX" openclaw-exec-provider >"$RUN_DIR/expired" 2>&1; then die "expired pre-minted session accepted"; fi
ok "Scenario 14 PASS"
