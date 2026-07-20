#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 17 sealed-responses-s1-s8
init_scenario 17
start_server
phoenix_admin set open/key -v synthetic-open >/dev/null
phoenix_admin set sealed/key -v synthetic-sealed >/dev/null
assert_eq "$(phoenix_admin get open/key)" synthetic-open "S1 plaintext-compatible open path"
stop_server
cat >"$RUN_DIR/policy.json" <<'JSON'
{"attestation":{"sealed/*":{"require_sealed":true,"allow_unseal":false},"open/*":{"allow_unseal":true}}}
JSON
config_patch "d['policy']={'path':'$RUN_DIR/policy.json'}"
start_server
keyfile="$RUN_DIR/seal.key"
phoenix_admin agent create sealed-agent -t synthetic-sealed-agent --acl 'sealed/*:read;open/*:read' >/dev/null
keyout="$(phoenix_admin keypair generate sealed-agent -o "$keyfile")"
[[ "$(stat -c %a "$keyfile")" == 600 ]] || die "S2 seal key mode is not 0600"
public="$(awk '/public key:/ {print $3}' <<<"$keyout")"; [[ -n "$public" ]] || die "S2 public key missing"
assert_eq "$(PHOENIX_TOKEN=synthetic-sealed-agent PHOENIX_SEAL_KEY="$keyfile" "$PHOENIX" get open/key)" synthetic-open "S3 sealed open read"
if PHOENIX_TOKEN=synthetic-sealed-agent "$PHOENIX" get sealed/key >"$RUN_DIR/unsealed" 2>&1; then die "S4 require_sealed allowed plaintext"; fi
assert_eq "$(PHOENIX_TOKEN=synthetic-sealed-agent PHOENIX_SEAL_KEY="$keyfile" "$PHOENIX" get sealed/key)" synthetic-sealed "S5 sealed required read"
wire="$(curl -fsS -X POST "$PHOENIX_SERVER/v1/resolve" -H 'Authorization: Bearer synthetic-sealed-agent' -H 'Content-Type: application/json' -H "X-Phoenix-Seal-Key: $public" --data '{"refs":["phoenix://sealed/key"]}')"
[[ "$(jq -r 'has("sealed_values") and (has("values")|not)' <<<"$wire")" == true ]] || die "S6 wire response was not sealed-only"
code="$(curl -sS -o "$RUN_DIR/badseal" -w '%{http_code}' -X POST "$PHOENIX_SERVER/v1/resolve" -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' -H 'X-Phoenix-Seal-Key: invalid' --data '{"refs":["phoenix://sealed/key"]}')"
assert_eq "$code" 400 "S7 invalid seal key"
show="$(PHOENIX_TOKEN="$ADMIN_TOKEN" PHOENIX_POLICY="$RUN_DIR/policy.json" "$PHOENIX" policy show sealed/key)"
assert_contains "$show" 'require_sealed: true' "S8 policy show regression"
if phoenix_admin keypair generate bad-output -o "$RUN_DIR" >"$RUN_DIR/keypair-dir" 2>&1; then die "S8 keypair directory output accepted"; fi
assert_contains "$(cat "$RUN_DIR/keypair-dir")" 'output must be a file path' "S8 keypair regression message"
ok "Scenario 17 PASS (S1-S8)"
