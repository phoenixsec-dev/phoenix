#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 14 openclaw-auth-modes
init_scenario 14
config_patch "d['auth']['mtls']['enabled']=True; d['session']={'enabled':True,'ttl':'3s','roles':{'openclaw':{'namespaces':['auth/*'],'actions':['read_value'],'bootstrap_trust':['bearer','mtls']},'approval':{'namespaces':['auth/*'],'actions':['read_value'],'bootstrap_trust':['bearer'],'step_up':True,'step_up_ttl':'1s'}}}"
PHOENIX_SERVER="https://${PHOENIX_SERVER#http://}"; export PHOENIX_SERVER
start_server
base=(PHOENIX_SERVER="$PHOENIX_SERVER" PHOENIX_CA_CERT="$RUN_DIR/ca.crt")
env "${base[@]}" PHOENIX_TOKEN="$ADMIN_TOKEN" "$PHOENIX" set auth/key -v synthetic-auth >/dev/null
env "${base[@]}" PHOENIX_TOKEN="$ADMIN_TOKEN" "$PHOENIX" agent create openclaw-agent -t synthetic-openclaw-bootstrap --acl 'auth/*:read' >/dev/null
mkdir "$RUN_DIR/client"
env "${base[@]}" PHOENIX_TOKEN="$ADMIN_TOKEN" "$PHOENIX" cert issue openclaw-agent -o "$RUN_DIR/client" >/dev/null
request='{"protocolVersion":1,"provider":"phoenix","ids":["auth/key"]}'
provider_value() { jq -r '.values["auth/key"]'; }
bearer="$(printf '%s' "$request" | env "${base[@]}" HOME="$RUN_DIR/home-bearer" PHOENIX_TOKEN=synthetic-openclaw-bootstrap PHOENIX_ROLE=openclaw "$PHOENIX" openclaw-exec-provider | provider_value)"
assert_eq "$bearer" synthetic-auth "bearer role mode"
mtls="$(printf '%s' "$request" | env "${base[@]}" HOME="$RUN_DIR/home-mtls" PHOENIX_TOKEN= PHOENIX_ROLE=openclaw PHOENIX_CLIENT_CERT="$RUN_DIR/client/openclaw-agent.crt" PHOENIX_CLIENT_KEY="$RUN_DIR/client/openclaw-agent.key" "$PHOENIX" openclaw-exec-provider | provider_value)"
assert_eq "$mtls" synthetic-auth "mTLS role mode"
mint="$(curl --cacert "$RUN_DIR/ca.crt" -fsS -X POST "$PHOENIX_SERVER/v1/session/mint" -H 'Authorization: Bearer synthetic-openclaw-bootstrap' -H 'Content-Type: application/json' --data '{"role":"openclaw"}')"; session="$(jq -r .session_token <<<"$mint")"
preminted="$(printf '%s' "$request" | env "${base[@]}" PHOENIX_TOKEN="$session" PHOENIX_ROLE= "$PHOENIX" openclaw-exec-provider | provider_value)"
assert_eq "$preminted" synthetic-auth "pre-minted mode"
homeless="$(printf '%s' "$request" | env -u HOME "${base[@]}" PHOENIX_TOKEN=synthetic-openclaw-bootstrap PHOENIX_ROLE=openclaw "$PHOENIX" openclaw-exec-provider | provider_value)"
assert_eq "$homeless" synthetic-auth "HOME-unset bootstrap"
fresh="$(curl --cacert "$RUN_DIR/ca.crt" -fsS -X POST "$PHOENIX_SERVER/v1/session/mint" -H 'Authorization: Bearer synthetic-openclaw-bootstrap' -H 'Content-Type: application/json' --data '{"role":"openclaw"}' | jq -r .session_token)"
if printf '%s' "$request" | env "${base[@]}" HOME="$RUN_DIR/home-invalid" PHOENIX_TOKEN="$fresh" PHOENIX_ROLE=openclaw "$PHOENIX" openclaw-exec-provider >"$RUN_DIR/invalid" 2>&1; then die "PHOENIX_ROLE plus phxs token accepted"; fi
sleep 4
if printf '%s' "$request" | env "${base[@]}" PHOENIX_TOKEN="$fresh" PHOENIX_ROLE= "$PHOENIX" openclaw-exec-provider >"$RUN_DIR/expired" 2>&1; then die "expired pre-minted session accepted"; fi
approval_code="$(curl --cacert "$RUN_DIR/ca.crt" -sS -o "$RUN_DIR/approval" -w '%{http_code}' -X POST "$PHOENIX_SERVER/v1/session/mint" -H 'Authorization: Bearer synthetic-openclaw-bootstrap' -H 'Content-Type: application/json' --data '{"role":"approval"}')"
assert_eq "$approval_code" 202 "step-up role response"
assert_eq "$(jq -r .code "$RUN_DIR/approval")" APPROVAL_REQUIRED
ok "Scenario 14 PASS"
