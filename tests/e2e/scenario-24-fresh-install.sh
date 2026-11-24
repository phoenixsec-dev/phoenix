#!/usr/bin/env bash
# A fresh install can approve: nothing but "phoenix-server --init" and CLI
# commands (no config editing), then an agent's request is answered on the
# dashboard with the password --init printed. Also checks that the password is
# not on disk and that --init --https serves the dashboard over HTTPS with a
# certificate that verifies.
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
printf %s synthetic-demo-agent | phoenix_admin agent create demo-agent --token-stdin --acl 'demo-none/*:list' >/dev/null
phoenix_admin keypair generate demo-agent -o "$RUN_DIR/demo.seal.key" >/dev/null
agent() { PHOENIX_TOKEN=synthetic-demo-agent PHOENIX_SEAL_KEY="$RUN_DIR/demo.seal.key" "$PHOENIX" "$@"; }
if agent exec --env KEY=phoenix://demo/api-key -- true >"$RUN_DIR/denied" 2>&1; then die "agent could read before approval"; fi
out="$(agent request demo/api-key --reason "e2e: fresh install" --ttl 5m)"
req="$(awk '/^Request:/ {print $2}' <<<"$out")"; [[ "$req" == req_* ]] || die "phoenix request printed no id: $out"

dash() { curl -sS --no-location -b "$RUN_DIR/jar" -c "$RUN_DIR/jar" -o "$RUN_DIR/dash.html" -w '%{http_code}' "$@"; }
# A wrong password shows the login form again and gives no login.
dash -X POST --data-urlencode "credential=wrong-$password" "$PHOENIX_SERVER/dashboard/login" >/dev/null
[[ "$(dash "$PHOENIX_SERVER/dashboard/requests")" != 200 ]] || die "a wrong password logged in"
assert_eq "$(dash -X POST --data-urlencode "credential=$password" "$PHOENIX_SERVER/dashboard/login")" 303 "login with the printed password"
# Every page works on a config nobody touched.
for page in "" requests sessions audit roles; do
  assert_eq "$(dash "$PHOENIX_SERVER/dashboard/$page")" 200 "dashboard page /$page"
done
dash "$PHOENIX_SERVER/dashboard/requests" >/dev/null
csrf="$(grep -o 'name="_csrf" value="[0-9a-f]*"' "$RUN_DIR/dash.html" | head -1 | sed 's/.*value="//; s/"//')"
assert_eq "$(dash -X POST --data "_csrf=$csrf&path=demo/api-key&choice=once" "$PHOENIX_SERVER/dashboard/requests/$req/answer")" 303 "dashboard approve"
assert_secret "$(agent exec --env KEY=phoenix://demo/api-key -- sh -c 'printf %s "$KEY"')" synthetic-fresh "approved use"
ok "a fresh install approves on the dashboard with no file editing"
stop_server

# --https: the new config has HTTPS on. Only the two ports are changed before
# it runs, so it cannot collide with a real server.
"$PHOENIX_SERVER_BIN" --init "$RUN_DIR/https" --https >"$RUN_DIR/https.out" </dev/null
assert_eq "$(jq -r .https_listener.enabled "$RUN_DIR/https/config.json")" true "--https turns HTTPS on"
assert_contains "$("$PHOENIX_SERVER_BIN" --check-config --config "$RUN_DIR/https/config.json")" "config OK" "--https config"
https_port="$(python3 - "$RUN_DIR/https/config.json" <<'PY'
import json, socket, sys
p = sys.argv[1]; d = json.load(open(p))
with socket.socket() as a, socket.socket() as b:  # both held, so they differ
    a.bind(('127.0.0.1', 0)); b.bind(('127.0.0.1', 0))
    http, https = a.getsockname()[1], b.getsockname()[1]
d['server']['listen'] = '127.0.0.1:%d' % http
d['https_listener']['listen'] = '127.0.0.1:%d' % https
json.dump(d, open(p, 'w'), indent=2)
print(https)
PY
)"
"$PHOENIX_SERVER_BIN" --config "$RUN_DIR/https/config.json" >"$RUN_DIR/https.log" 2>&1 &
SERVER_PID=$!
url="https://127.0.0.1:$https_port"; ca="$RUN_DIR/https/ca.crt"
for _ in $(seq 1 100); do curl -fsS --cacert "$ca" "$url/v1/health" >/dev/null 2>&1 && break; sleep 0.1; done
dashboard_login "$url" "$(password_from_init "$RUN_DIR/https.out")" "$RUN_DIR/jar-https" --cacert "$ca" || die "dashboard over HTTPS with the printed password"
if dashboard_login "$url" "not-the-password" "$RUN_DIR/jar-wrong" --cacert "$ca"; then die "a wrong password signed in over HTTPS"; fi
rc=0; curl -sS --noproxy '*' --cacert "$ca" --resolve "wrong.invalid:$https_port:127.0.0.1" "https://wrong.invalid:$https_port/v1/health" >/dev/null 2>&1 || rc=$?
assert_eq "$rc" 60 "curl must reject the certificate for another name (exit 60)"
stop_server
rc=0; "$PHOENIX_SERVER_BIN" --https >"$RUN_DIR/https-alone" 2>&1 || rc=$?
assert_eq "$rc" 2 "--https without --init"
ok "Scenario 24 PASS"
