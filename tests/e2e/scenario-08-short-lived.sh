#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 08 short-lived-token
init_scenario 08
config_patch "d['attestation']['token']={'enabled':True,'ttl':'2s'}"
start_server
phoenix_admin set ephemeral/key -v synthetic-ephemeral >/dev/null
phoenix_admin agent create ephemeral-agent -t synthetic-bootstrap --acl 'ephemeral/*:read' >/dev/null
mint="$(api_admin POST /v1/token/mint '{"agent":"ephemeral-agent"}')"; tok="$(jq -r .token <<<"$mint")"
assert_eq "$(PHOENIX_TOKEN="$tok" "$PHOENIX" get ephemeral/key)" synthetic-ephemeral
sleep 3
if PHOENIX_TOKEN="$tok" "$PHOENIX" get ephemeral/key >"$RUN_DIR/expired" 2>&1; then die "expired token accepted"; fi
mint2="$(api_admin POST /v1/token/mint '{"agent":"ephemeral-agent"}')"; tok2="$(jq -r .token <<<"$mint2")"
assert_eq "$(PHOENIX_TOKEN="$tok2" "$PHOENIX" get ephemeral/key)" synthetic-ephemeral
ok "Scenario 08 PASS"
