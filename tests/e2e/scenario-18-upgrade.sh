#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 18 upgrade-0.13.5-to-current
require_cmd git
require_cmd tar
require_cmd curl
require_cmd python3
require_cmd jq
build_current
NEW_PHOENIX="$PHOENIX"; NEW_SERVER="$PHOENIX_SERVER_BIN"
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/phoenix-e2e-s18.XXXXXX")"; SERVER_PID=""; trap cleanup_scenario EXIT INT TERM
mkdir "$RUN_DIR/old-src" "$RUN_DIR/old-bin" "$RUN_DIR/state"
git -C "$REPO_ROOT" archive 21a6ca4 | tar -x -C "$RUN_DIR/old-src"
(cd "$RUN_DIR/old-src" && "$GO_BIN" build -o "$RUN_DIR/old-bin/" ./cmd/...)
PHOENIX="$RUN_DIR/old-bin/phoenix"; PHOENIX_SERVER_BIN="$RUN_DIR/old-bin/phoenix-server"
"$PHOENIX_SERVER_BIN" --init "$RUN_DIR/state" >"$RUN_DIR/init.out"
ADMIN_TOKEN="$(python3 - "$RUN_DIR/init.out" <<'PY'
import re,sys
s=open(sys.argv[1]).read(); m=re.search(r'ADMIN TOKEN.*?\n([a-f0-9]{32,})',s,re.S); print(m.group(1) if m else '')
PY
)"; [[ -n "$ADMIN_TOKEN" ]] || die "old init token missing"
port="$(free_port)"
python3 - "$RUN_DIR/state/config.json" "$port" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p)); d['server']['listen']='127.0.0.1:'+sys.argv[2]; d['session']={'enabled':True,'ttl':'10m','roles':{'upgrade-reader':{'namespaces':['upgrade/*'],'actions':['read_value'],'bootstrap_trust':['bearer']}}}; json.dump(d,open(p,'w'),indent=2)
PY
PHOENIX_SERVER="http://127.0.0.1:$port"; export PHOENIX_SERVER
# Helpers expect config at RUN_DIR/config.json; point through a temporary symlink.
ln -s "$RUN_DIR/state/config.json" "$RUN_DIR/config.json"
start_server
phoenix_admin set upgrade/key -v synthetic-upgrade >/dev/null
phoenix_admin agent create upgrade-agent -t synthetic-upgrade-agent --acl 'upgrade/*:read' >/dev/null
old_mint="$(curl -fsS -X POST "$PHOENIX_SERVER/v1/session/mint" -H 'Authorization: Bearer synthetic-upgrade-agent' -H 'Content-Type: application/json' --data '{"role":"upgrade-reader"}')"; old_session="$(jq -r .session_token <<<"$old_mint")"
assert_eq "$(PHOENIX_TOKEN="$old_session" "$PHOENIX" get upgrade/key)" synthetic-upgrade
old_audit_count="$(wc -l <"$RUN_DIR/state/audit.log")"
stop_server
PHOENIX="$NEW_PHOENIX"; PHOENIX_SERVER_BIN="$NEW_SERVER"
# An old config still carries settings that were since removed (auth.mtls,
# the attestation block, onepassword.enabled). The new server must refuse
# it by name, both at startup and with --check-config, until they are gone.
rc=0; "$NEW_SERVER" --check-config --config "$RUN_DIR/config.json" >"$RUN_DIR/check-old.out" 2>&1 || rc=$?
[[ "$rc" -eq 1 ]] || die "--check-config accepted an old config with removed settings (rc=$rc)"
check_out="$(cat "$RUN_DIR/check-old.out")"
assert_contains "$check_out" "auth.mtls: removed" "removed mTLS block must be named"
assert_contains "$check_out" "onepassword.enabled: removed" "removed onepassword.enabled must be named"
rc=0; timeout 10 "$NEW_SERVER" --config "$RUN_DIR/config.json" >"$RUN_DIR/start-old.out" 2>&1 || rc=$?
[[ "$rc" -ne 0 && "$rc" -ne 124 ]] || die "new server started on an old config with removed settings (rc=$rc)"
assert_contains "$(cat "$RUN_DIR/start-old.out")" "auth.mtls: removed" "startup refusal must name the field"
# The upgrade edit: drop the removed settings, keep the CA paths for
# --reissue-cert by moving them into https_listener.
python3 - "$RUN_DIR/state/config.json" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p))
m=d['auth'].pop('mtls', {})
d.pop('tls', None)
d.pop('attestation', None)
d.get('onepassword',{}).pop('enabled', None)
d['https_listener']={'enabled':False,'listen':'127.0.0.1:0','cert':m.get('server_cert',''),'key':m.get('server_key',''),'ca_cert':m.get('ca_cert',''),'ca_key':m.get('ca_key','')}
json.dump(d,open(p,'w'),indent=2)
PY
assert_contains "$("$NEW_SERVER" --check-config --config "$RUN_DIR/config.json")" "config OK" "cleaned config must pass --check-config"
assert_contains "$("$NEW_SERVER" --reissue-cert --san 127.0.0.1 --config "$RUN_DIR/config.json")" "Server certificate reissued" "reissue-cert with moved CA paths"
start_server
assert_eq "$(phoenix_admin get upgrade/key)" synthetic-upgrade "store compatibility"
assert_eq "$(PHOENIX_TOKEN=synthetic-upgrade-agent "$PHOENIX" get upgrade/key)" synthetic-upgrade "ACL compatibility"
if PHOENIX_TOKEN="$old_session" "$PHOENIX" get upgrade/key >"$RUN_DIR/old-session" 2>&1; then die "pre-restart in-memory session unexpectedly survived"; fi
new_mint="$(curl -fsS -X POST "$PHOENIX_SERVER/v1/session/mint" -H 'Authorization: Bearer synthetic-upgrade-agent' -H 'Content-Type: application/json' --data '{"role":"upgrade-reader"}')"; new_session="$(jq -r .session_token <<<"$new_mint")"
assert_eq "$(PHOENIX_TOKEN="$new_session" "$PHOENIX" get upgrade/key)" synthetic-upgrade "session config compatibility"
[[ "$(wc -l <"$RUN_DIR/state/audit.log")" -gt "$old_audit_count" ]] || die "audit log was not preserved/appended"
provider="$(printf '%s' '{"protocolVersion":1,"provider":"phoenix","ids":["upgrade/key"]}' | PHOENIX_TOKEN="$new_session" "$PHOENIX" openclaw-exec-provider)"
assert_eq "$(jq -r '.values["upgrade/key"]' <<<"$provider")" synthetic-upgrade "new feature after upgrade"
ok "Scenario 18 PASS"
