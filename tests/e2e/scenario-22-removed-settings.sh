#!/usr/bin/env bash
# Scenario 22 — removed settings are refused by name, never silently ignored.
#
# A config and policy that still use removed settings must fail
# phoenix-server --check-config (exit 1) with one line per field, and the
# server must refuse to start. The same files with those fields removed pass.
# Removed CLI commands and API routes explain themselves too.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 22 removed-settings
init_scenario 22

cat >"$RUN_DIR/policy.json" <<'JSON'
{"attestation":{"infra/*":{"source_ip":["127.0.0.1"],"require_mtls":true,"allowed_tools":["x"],"time_window":"09:00-17:00"}}}
JSON
config_patch "d['policy']={'path':'$RUN_DIR/policy.json'}; d['tls']={'enabled':False}; d['attestation']={'nonce':{'enabled':False},'local_agent':{'enabled':False}}; d['session']={'enabled':True,'roles':{'old':{'namespaces':['infra/*'],'bootstrap_trust':['bearer'],'step_up':True}}}"

# 1. The config's removed fields: one line each, exit 1.
rc=0
"$PHOENIX_SERVER_BIN" --check-config --config "$RUN_DIR/config.json" >"$RUN_DIR/check.out" 2>&1 || rc=$?
[[ "$rc" -eq 1 ]] || die "--check-config accepted removed settings (rc=$rc)"
out="$(cat "$RUN_DIR/check.out")"
for field in "tls: removed" "attestation.nonce: removed" "session.roles.old.step_up: removed"; do
  assert_contains "$out" "$field" "check-config must name $field"
done
assert_eq "$(grep -c ': removed. Why: ' "$RUN_DIR/check.out")" 3 "one line per removed config field"

# 2. Startup refuses the same config.
rc=0
timeout 10 "$PHOENIX_SERVER_BIN" --config "$RUN_DIR/config.json" >"$RUN_DIR/start.out" 2>&1 || rc=$?
[[ "$rc" -ne 0 && "$rc" -ne 124 ]] || die "server started with removed settings (rc=$rc)"
assert_contains "$(cat "$RUN_DIR/start.out")" "session.roles.old.step_up: removed" "startup refusal must name the field"

# 3. With the config clean, the policy's removed fields are named next.
config_patch "d.pop('tls'); d['attestation'].pop('nonce'); d['session']['roles']['old'].pop('step_up')"
rc=0
"$PHOENIX_SERVER_BIN" --check-config --config "$RUN_DIR/config.json" >"$RUN_DIR/check-policy.out" 2>&1 || rc=$?
[[ "$rc" -eq 1 ]] || die "--check-config accepted a policy with removed fields (rc=$rc)"
out="$(cat "$RUN_DIR/check-policy.out")"
for field in "attestation.infra/*.require_mtls: removed" "attestation.infra/*.allowed_tools: removed" "attestation.infra/*.time_window: removed"; do
  assert_contains "$out" "$field" "check-config must name $field"
done
assert_eq "$(grep -c ': removed. Why: ' "$RUN_DIR/check-policy.out")" 3 "one line per removed policy field"

# 4. Clean config and policy pass and the server starts.
cat >"$RUN_DIR/policy.json" <<'JSON'
{"attestation":{"infra/*":{"source_ip":["127.0.0.1"]}}}
JSON
out="$("$PHOENIX_SERVER_BIN" --check-config --config "$RUN_DIR/config.json")"
assert_contains "$out" "config OK: $RUN_DIR/config.json" "clean config must pass"
assert_contains "$out" "policy OK" "clean policy must pass"
start_server

# 5. Removed API routes answer 410 with the reason; removed commands explain.
code="$(curl -sS -o "$RUN_DIR/gone" -w '%{http_code}' -X POST "$PHOENIX_SERVER/v1/token/mint")"
assert_eq "$code" 410 "removed route must answer 410 Gone"
assert_contains "$(cat "$RUN_DIR/gone")" "removed" "410 body must give the reason"
rc=0
phoenix_admin cert issue someone >"$RUN_DIR/cert.out" 2>&1 || rc=$?
[[ "$rc" -eq 1 ]] || die "phoenix cert issue did not fail (rc=$rc)"
assert_contains "$(cat "$RUN_DIR/cert.out")" "was removed" "removed command must say so"
ok "Scenario 22 PASS"
