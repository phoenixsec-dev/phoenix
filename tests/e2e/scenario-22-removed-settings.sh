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

# 1. The config's and the policy's removed fields: one line each, all in one
# run, exit 1.
rc=0
"$PHOENIX_SERVER_BIN" --check-config --config "$RUN_DIR/config.json" >"$RUN_DIR/check.out" 2>&1 || rc=$?
[[ "$rc" -eq 1 ]] || die "--check-config accepted removed settings (rc=$rc)"
out="$(cat "$RUN_DIR/check.out")"
for field in "tls: removed" "attestation.nonce: removed" "attestation.local_agent: removed" "session.roles.old.step_up: removed" "attestation.infra/*.require_mtls: removed"; do
  assert_contains "$out" "$field" "check-config must name $field"
done
assert_eq "$(grep -c ': removed. Why: ' "$RUN_DIR/check.out")" 7 "one line per removed config and policy field"

# 2. Startup refuses the same config.
rc=0
timeout 10 "$PHOENIX_SERVER_BIN" --config "$RUN_DIR/config.json" >"$RUN_DIR/start.out" 2>&1 || rc=$?
[[ "$rc" -ne 0 && "$rc" -ne 124 ]] || die "server started with removed settings (rc=$rc)"
assert_contains "$(cat "$RUN_DIR/start.out")" "session.roles.old.step_up: removed" "startup refusal must name the field"

# 3. With the config clean, the policy's removed fields are named next.
config_patch "d.pop('tls'); d.pop('attestation'); d['session']['roles']['old'].pop('step_up')"
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

# 6. Second cuts. A copy of the config with a dashboard pin, a role
# attestation list, an old-format policy and an ACL using "read": one
# --check-config run names all four.
python3 - "$RUN_DIR" <<'PY'
import json, sys
r = sys.argv[1]
d = json.load(open(r + '/config.json'))
d['dashboard'] = {'enabled': True, 'pin': '1234'}
d['session']['roles']['old']['attestation'] = ['source_ip']
d['policy'] = {'path': r + '/policy2.json'}
d['acl'] = {'path': r + '/acl2.json'}
json.dump(d, open(r + '/config2.json', 'w'))
json.dump({'rules': [{'path': 'infra/*', 'allowed_ips': ['127.0.0.1']}]}, open(r + '/policy2.json', 'w'))
json.dump({'agents': {'old-agent': {'name': 'old-agent', 'token_hash': 'x', 'permissions': [{'path': 'infra/*', 'actions': ['read']}]}}}, open(r + '/acl2.json', 'w'))
PY
rc=0
"$PHOENIX_SERVER_BIN" --check-config --config "$RUN_DIR/config2.json" >"$RUN_DIR/check2.out" 2>&1 || rc=$?
[[ "$rc" -eq 1 ]] || die "--check-config accepted second-pass removals (rc=$rc)"
out="$(cat "$RUN_DIR/check2.out")"
for field in "dashboard.pin: removed" "session.roles.old.attestation: removed" "rules: removed" 'agent "old-agent" path "infra/*"'; do
  assert_contains "$out" "$field" "check-config must name $field"
done

# Removed CLI flags and the server's --passphrase explain themselves and do nothing.
for cmd in "set infra/x -v value" "exec --output-env $RUN_DIR/out.env --env A=phoenix://infra/x -- true" "secret-provider openclaw" "resolve --stdin-json"; do
  rc=0
  # shellcheck disable=SC2086
  phoenix_admin $cmd </dev/null >"$RUN_DIR/flag.out" 2>&1 || rc=$?
  [[ "$rc" -eq 1 ]] || die "phoenix $cmd did not fail (rc=$rc)"
  assert_contains "$(cat "$RUN_DIR/flag.out")" "was removed" "phoenix $cmd must say it was removed"
done
[[ ! -e "$RUN_DIR/out.env" ]] || die "exec --output-env wrote a file"
rc=0
"$PHOENIX_SERVER_BIN" --init "$RUN_DIR/init2" --passphrase synthetic >"$RUN_DIR/pp.out" 2>&1 || rc=$?
[[ "$rc" -eq 2 ]] || die "phoenix-server --passphrase did not fail (rc=$rc)"
assert_contains "$(cat "$RUN_DIR/pp.out")" "--passphrase-stdin" "--passphrase must name what to use"
[[ ! -e "$RUN_DIR/init2" ]] || die "--init ran with --passphrase"
ok "Scenario 22 PASS"
