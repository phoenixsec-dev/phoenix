#!/usr/bin/env bash
# A fresh install can approve: nothing but "phoenix-server --init" and CLI
# commands (no config editing), then an agent's request is answered on the
# dashboard with the password --init printed. Also checks that the password is
# not on disk and that --init --https serves the dashboard over HTTPS.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 24 fresh-install-can-approve
init_scenario 24   # only the listen port is changed, so it cannot collide

password="$(password_from_init "$RUN_DIR/init.out")"
[[ -n "$password" ]] || die "--init printed no dashboard password"
assert_eq "$(grep -cF -- "$password" "$RUN_DIR/init.out")" 1 "the password must be printed exactly once"
rm "$RUN_DIR/init.out"
if grep -rqF -- "$password" "$RUN_DIR"; then die "the dashboard password is stored in plain text"; fi
start_server
assert_not_contains "$(cat "$RUN_DIR/server.log")" "nobody can approve" "fresh install has an approver"

printf '%s' synthetic-fresh | phoenix_admin set demo/api-key --value-stdin -d "Synthetic demo key" >/dev/null
phoenix_admin agent create demo-agent -t synthetic-demo-agent --acl 'demo-none/*:list' >/dev/null
phoenix_admin keypair generate demo-agent -o "$RUN_DIR/demo.seal.key" >/dev/null
agent() { PHOENIX_TOKEN=synthetic-demo-agent PHOENIX_SEAL_KEY="$RUN_DIR/demo.seal.key" "$PHOENIX" "$@"; }
if agent exec --env KEY=phoenix://demo/api-key -- true >"$RUN_DIR/denied" 2>&1; then die "agent could read before approval"; fi
out="$(agent request demo/api-key --reason "e2e: fresh install" --ttl 5m)"
req="$(awk '/^Request:/ {print $2}' <<<"$out")"; [[ "$req" == req_* ]] || die "phoenix request printed no id: $out"

dash() { curl -sS -b "$RUN_DIR/jar" -c "$RUN_DIR/jar" -o "$RUN_DIR/dash.html" -w '%{http_code}' "$@"; }
# A wrong password shows the login form again and gives no login.
dash -X POST --data-urlencode "credential=wrong-$password" "$PHOENIX_SERVER/dashboard/login" >/dev/null
[[ "$(dash "$PHOENIX_SERVER/dashboard/approvals")" != 200 ]] || die "a wrong password logged in"
assert_eq "$(dash -X POST --data-urlencode "credential=$password" "$PHOENIX_SERVER/dashboard/login")" 303 "login with the printed password"
# Every page works on a config nobody touched.
for page in "" approvals grants sessions audit roles; do
  assert_eq "$(dash "$PHOENIX_SERVER/dashboard/$page")" 200 "dashboard page /$page"
done
dash "$PHOENIX_SERVER/dashboard/approvals" >/dev/null
csrf="$(grep -o 'name="_csrf" value="[0-9a-f]*"' "$RUN_DIR/dash.html" | head -1 | sed 's/.*value="//; s/"//')"
assert_eq "$(dash -X POST --data "_csrf=$csrf&path=demo/api-key&ttl=5m" "$PHOENIX_SERVER/dashboard/access-requests/$req/approve")" 303 "dashboard approve"
assert_eq "$(agent exec --env KEY=phoenix://demo/api-key -- sh -c 'printf %s "$KEY"')" synthetic-fresh "approved use"
ok "a fresh install approves on the dashboard with no file editing"
stop_server

# --https: the new config has HTTPS on, with a certificate that verifies.
# The address is fixed (0.0.0.0:9443), so only the check runs here.
"$PHOENIX_SERVER_BIN" --init "$RUN_DIR/https" --https >"$RUN_DIR/https.out" </dev/null
assert_eq "$(jq -r .https_listener.enabled "$RUN_DIR/https/config.json")" true "--https turns HTTPS on"
assert_contains "$("$PHOENIX_SERVER_BIN" --check-config --config "$RUN_DIR/https/config.json")" "config OK" "--https config"
rc=0; "$PHOENIX_SERVER_BIN" --https >"$RUN_DIR/https-alone" 2>&1 || rc=$?
assert_eq "$rc" 2 "--https without --init"
ok "Scenario 24 PASS"
