#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 06 certificate-lifecycle
require_cmd openssl
init_scenario 06
config_patch "d['auth']['mtls']['enabled']=True"
PHOENIX_SERVER="https://${PHOENIX_SERVER#http://}"; export PHOENIX_SERVER
start_server
PHOENIX_CA_CERT="$RUN_DIR/ca.crt" PHOENIX_TOKEN="$ADMIN_TOKEN" "$PHOENIX" set certs/key -v synthetic-cert >/dev/null
PHOENIX_CA_CERT="$RUN_DIR/ca.crt" PHOENIX_TOKEN="$ADMIN_TOKEN" "$PHOENIX" agent create cert-agent -t synthetic-unused --acl 'certs/*:read' >/dev/null
mkdir "$RUN_DIR/client"
PHOENIX_CA_CERT="$RUN_DIR/ca.crt" PHOENIX_TOKEN="$ADMIN_TOKEN" "$PHOENIX" cert issue cert-agent -o "$RUN_DIR/client" >/dev/null
cert_env=(PHOENIX_CA_CERT="$RUN_DIR/ca.crt" PHOENIX_CLIENT_CERT="$RUN_DIR/client/cert-agent.crt" PHOENIX_CLIENT_KEY="$RUN_DIR/client/cert-agent.key" PHOENIX_TOKEN=)
assert_eq "$(env "${cert_env[@]}" "$PHOENIX" get certs/key)" synthetic-cert
serial="$(openssl x509 -in "$RUN_DIR/client/cert-agent.crt" -noout -serial | cut -d= -f2)"
serial_dec="$(python3 -c 'import sys; print(int(sys.argv[1],16))' "$serial")"
curl --cacert "$RUN_DIR/ca.crt" -fsS -X POST "$PHOENIX_SERVER/v1/certs/revoke" -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' --data "{\"serial_number\":\"$serial_dec\",\"agent_name\":\"cert-agent\"}" >/dev/null
if env "${cert_env[@]}" "$PHOENIX" get certs/key >"$RUN_DIR/revoked" 2>&1; then die "revoked certificate accepted"; fi
ok "Scenario 06 PASS"
