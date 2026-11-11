#!/usr/bin/env bash
# Scenario 19 — secure transport: https_listener, plaintext warnings.
#
# Covers the transport model:
#   - loopback plaintext is the default and starts silently (no warning)
#   - a non-loopback bind of server.listen emits the loud INSECURE TRANSPORT
#     warning and Phoenix still proceeds (warn, never refuse)
#   - CLI warns (but works) on plaintext non-loopback PHOENIX_SERVER
#   - the removed "tls" block stops startup with a clear line, and
#     mcp-server --http (MCP over HTTP, removed) says why instead of starting
#   - https_listener (the one way to serve HTTPS) shares HTTP auth, store,
#     session, policy and dashboard state
#   - https_listener misconfiguration (blank address, bad certificate) stops
#     startup; a bind failure is logged and HTTP stays available
#
# Per harness convention, nothing here binds a non-loopback interface. The
# non-loopback warning is asserted with a TEST-NET-1 address (192.0.2.1,
# RFC 5737): the warning is emitted before the bind attempt, so the log
# proves Phoenix warned and proceeded; the bind then fails at the OS level.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

scenario_start 19 "secure transport: https_listener, plaintext warnings"
init_scenario 19
PORT="${PHOENIX_SERVER##*:}"

# --- 1. Loopback plaintext default: starts, serves, and does not warn ---
start_server
log "loopback plaintext default"
server_log="$(cat "$RUN_DIR/server.log")"
assert_not_contains "$server_log" "INSECURE TRANSPORT" "loopback plaintext must not warn"

cli_stderr="$(phoenix_admin status 2>&1 >/dev/null)"
assert_not_contains "$cli_stderr" "WARNING" "CLI must not warn on loopback http://"
ok "loopback plaintext: silent, serving"

# --- 2. CLI warns (but works) on plaintext non-loopback PHOENIX_SERVER ---
# 0.0.0.0 is judged non-loopback (it binds/means all interfaces) but on
# Linux connecting to it reaches the loopback listener, so the command
# must warn on stderr AND still succeed.
cli_stderr="$(PHOENIX_SERVER="http://0.0.0.0:$PORT" phoenix_admin status 2>&1 >/dev/null)"
assert_contains "$cli_stderr" "WARNING" "CLI must warn on non-loopback http://"
assert_contains "$cli_stderr" "unencrypted" "CLI warning must name the exposure"
ok "CLI warns on non-loopback plaintext and still completes"
stop_server

# --- 3. Non-loopback plaintext server: loud warning, no refusal ---
run_expect_warning() {
  local logfile="$1"; shift
  local rc=0
  timeout 10 "$PHOENIX_SERVER_BIN" --config "$RUN_DIR/config.json" >"$logfile" 2>&1 || rc=$?
  # TEST-NET-1 cannot be assigned here, so the OS rejects the bind after
  # the warning is printed. rc 0 would mean it served — also a failure.
  [[ "$rc" -ne 0 ]] || die "server unexpectedly bound a TEST-NET-1 address"
}

config_patch "d['server']['listen']='192.0.2.1:$PORT'"
run_expect_warning "$RUN_DIR/warn.log"
warn_log="$(cat "$RUN_DIR/warn.log")"
assert_contains "$warn_log" "INSECURE TRANSPORT: PLAINTEXT HTTP ON A NON-LOOPBACK ADDRESS" "non-loopback plaintext must warn"
assert_contains "$warn_log" "bearer tokens" "warning must name bearer token exposure"
assert_contains "$warn_log" "secret value" "warning must name secret value exposure"
assert_contains "$warn_log" '"https_listener": { "enabled": true }' "warning must show the fix"
assert_contains "$warn_log" "server error: listen" "warning must precede the bind attempt (warn, never refuse)"
assert_not_contains "$warn_log" "dashboard" "no dashboard line when dashboard is disabled"
ok "non-loopback plaintext: loud warning, startup not refused"

# --- 4. Dashboard enabled adds the dashboard exposure line ---
config_patch "d['dashboard']={'enabled': True, 'password_hash': '\$2a\$10\$HLVxwM4wKNkthQOq6HXfuOj6tC68h.gfwNjx2MSHkqPXkgvrMpK3a'}"
run_expect_warning "$RUN_DIR/warn-dash.log"
warn_log="$(cat "$RUN_DIR/warn-dash.log")"
assert_contains "$warn_log" "dashboard passwords and session cookies" "dashboard exposure line missing"
ok "dashboard on non-loopback plaintext: warning names the cookie exposure"
config_patch "d['dashboard']={'enabled': False}"

# --- 5. The removed "tls" block stops startup, by name ---
config_patch "d['server']['listen']='127.0.0.1:$PORT'; d['tls']={'enabled': True}"
rc=0
"$PHOENIX_SERVER_BIN" --check-config --config "$RUN_DIR/config.json" >"$RUN_DIR/tls-check.log" 2>&1 || rc=$?
[[ "$rc" -eq 1 ]] || die "--check-config accepted the removed tls block (rc=$rc)"
assert_contains "$(cat "$RUN_DIR/tls-check.log")" "tls: removed" "tls refusal must name the field"
assert_contains "$(cat "$RUN_DIR/tls-check.log")" "https_listener" "tls refusal must name the replacement"
rc=0
timeout 10 "$PHOENIX_SERVER_BIN" --config "$RUN_DIR/config.json" >"$RUN_DIR/tls-start.log" 2>&1 || rc=$?
[[ "$rc" -ne 0 && "$rc" -ne 124 ]] || die "server started with the removed tls block (rc=$rc)"
assert_contains "$(cat "$RUN_DIR/tls-start.log")" "tls: removed" "startup refusal must name the field"
config_patch "d.pop('tls')"
ok "removed tls block refused at startup and by --check-config"

# --- 6. MCP over HTTP was removed: --http explains instead of starting ---
rc=0
PHOENIX_TOKEN="$ADMIN_TOKEN" timeout 10 "$PHOENIX" mcp-server --http "127.0.0.1:$(free_port)" >"$RUN_DIR/mcp-http.log" 2>&1 </dev/null || rc=$?
[[ "$rc" -eq 1 ]] || die "mcp-server --http did not exit 1 (rc=$rc)"
assert_contains "$(cat "$RUN_DIR/mcp-http.log")" "was removed" "mcp-server --http must say it was removed"
ok "mcp-server --http reports the removal"

start_server

# --- 7. https_listener preserves HTTP and shares application state ---
printf '%s' synthetic-dual | phoenix_admin set dual/key --value-stdin >/dev/null
printf '%s' synthetic-denied | phoenix_admin set forbidden/key --value-stdin >/dev/null
printf '%s' synthetic-ip-denied | phoenix_admin set source-denied/key --value-stdin >/dev/null
phoenix_admin agent create dual-reader -t synthetic-dual-reader --acl 'dual/*:list,read_value' >/dev/null
stop_server
HTTPS_PORT="$(free_port)"
HTTP_URL="$PHOENIX_SERVER"
HTTPS_URL="https://127.0.0.1:$HTTPS_PORT"
cat >"$RUN_DIR/dual-policy.json" <<'JSON'
{"attestation":{"dual/*":{"source_ip":["127.0.0.1"]},"source-denied/*":{"source_ip":["192.0.2.1"]}}}
JSON
config_patch "d['https_listener']={'enabled':True,'listen':'127.0.0.1:$HTTPS_PORT','cert':'$RUN_DIR/server.crt','key':'$RUN_DIR/server.key'}; d['policy']={'path':'$RUN_DIR/dual-policy.json'}; d['session']={'enabled':True,'roles':{'dual-reader':{'namespaces':['dual/*'],'actions':['read_value'],'bootstrap_trust':['bearer']}}}; d['dashboard']={'enabled':True,'password_hash':'\$2a\$10\$HLVxwM4wKNkthQOq6HXfuOj6tC68h.gfwNjx2MSHkqPXkgvrMpK3a','allow_multi_login':True}"
start_server
assert_contains "$(cat "$RUN_DIR/server.log")" "Optional HTTPS listener serving" "optional listener startup missing"
if curl -fsS -m 3 "http://127.0.0.1:$HTTPS_PORT/v1/health" >/dev/null 2>&1; then
  die "plaintext request succeeded against the HTTPS listener"
fi
cli_stderr="$(PHOENIX_SERVER="$HTTPS_URL" PHOENIX_CA_CERT="$RUN_DIR/ca.crt" phoenix_admin status 2>&1 >/dev/null)"
assert_not_contains "$cli_stderr" "WARNING" "CLI must not warn on https://"

dual_status() {
  local url="$1" path="$2" token="${3:-}"
  curl -sS --max-time 3 --cacert "$RUN_DIR/ca.crt" -o /dev/null -w '%{http_code}' \
    "$url$path" -H "Authorization: Bearer $token"
}
for url in "$HTTP_URL" "$HTTPS_URL"; do
  assert_eq "$(dual_status "$url" /v1/secrets/dual/key)" 401 "empty bearer denied"
  assert_eq "$(dual_status "$url" /v1/secrets/dual/key invalid-synthetic)" 401 "invalid bearer denied"
  assert_eq "$(dual_status "$url" /v1/secrets/forbidden/key synthetic-dual-reader)" 403 "ACL denied on both transports"
  assert_eq "$(dual_status "$url" /v1/secrets/dual/key synthetic-dual-reader)" 200 "scoped bearer and loopback source policy"
  assert_eq "$(curl -sS --max-time 3 --cacert "$RUN_DIR/ca.crt" -o /dev/null -w '%{http_code}' \
    "$url/v1/secrets/source-denied/key" -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'X-Forwarded-For: 192.0.2.1')" 403 "forwarded IP must not bypass direct source policy"
done
printf '%s' synthetic-updated | PHOENIX_SERVER="$HTTPS_URL" PHOENIX_CA_CERT="$RUN_DIR/ca.crt" phoenix_admin set dual/key --value-stdin >/dev/null
assert_eq "$(phoenix_admin get dual/key)" synthetic-updated "HTTPS write visible over existing HTTP"
printf '%s' synthetic-http-update | phoenix_admin set dual/key --value-stdin >/dev/null
assert_eq "$(PHOENIX_SERVER="$HTTPS_URL" PHOENIX_CA_CERT="$RUN_DIR/ca.crt" phoenix_admin get dual/key)" synthetic-http-update "HTTP write visible over HTTPS"

mint="$(curl -fsS "$HTTP_URL/v1/session/mint" -H 'Authorization: Bearer synthetic-dual-reader' \
  -H 'Content-Type: application/json' --data '{"role":"dual-reader"}')"
dual_session="$(jq -r .session_token <<<"$mint")"
assert_eq "$(dual_status "$HTTPS_URL" /v1/secrets/dual/key "$dual_session")" 200 "HTTP session usable over HTTPS"
mint="$(curl -fsS --cacert "$RUN_DIR/ca.crt" "$HTTPS_URL/v1/session/mint" -H 'Authorization: Bearer synthetic-dual-reader' \
  -H 'Content-Type: application/json' --data '{"role":"dual-reader"}')"
assert_eq "$(dual_status "$HTTP_URL" /v1/secrets/dual/key "$(jq -r .session_token <<<"$mint")")" 200 "HTTPS session usable over HTTP"

for url in "$HTTP_URL" "$HTTPS_URL"; do
  headers="$(curl -sS --max-time 3 --cacert "$RUN_DIR/ca.crt" -D - -o /dev/null \
    "$url/dashboard/login" --data 'credential=e2e-dash-password')"
  # HTTP/2 lowercases header names; compare without depending on the protocol.
  assert_contains "${headers,,}" 'set-cookie: phoenix_dash=' "dashboard login on both transports"
  if [[ "$url" == https://* ]]; then
    assert_contains "$headers" '; Secure' "HTTPS dashboard cookie must be secure"
  else
    assert_not_contains "$headers" '; Secure' "HTTP dashboard cookie remains request-based"
  fi
  assert_eq "$(dual_status "$url" /dashboard/login)" 200 "portal remains available"
done

# Failures across both ports must share the same source-IP limiter. Five
# failures lock the IP out for 1s, and each later failure doubles that, but a
# failure only counts once the previous lockout has expired. So wait out the
# 1s and 2s windows: the seventh failure leaves a 4s lockout, wide enough that
# a slow box cannot let the proving request below slip past it.
assert_eq "$(dual_status "$HTTP_URL" /v1/secrets/dual/key "$ADMIN_TOKEN")" 200
for url in "$HTTP_URL" "$HTTPS_URL" "$HTTP_URL" "$HTTPS_URL" "$HTTP_URL"; do
  assert_eq "$(dual_status "$url" /v1/secrets/dual/key invalid-synthetic)" 401
done
sleep 1.2
assert_eq "$(dual_status "$HTTPS_URL" /v1/secrets/dual/key invalid-synthetic)" 401
sleep 2.2
assert_eq "$(dual_status "$HTTP_URL" /v1/secrets/dual/key invalid-synthetic)" 401
# Phoenix intentionally reports all bearer authentication failures as 401.
# A known-good token being denied here proves the shared limiter is active.
assert_eq "$(dual_status "$HTTPS_URL" /v1/secrets/dual/key "$ADMIN_TOKEN")" 401 "switching ports must not reset rate limiting"
ok "optional HTTPS shares auth, ACL, source-IP policy, store, sessions, dashboard and rate limits"
stop_server

# --- 8. https_listener misconfiguration is fatal; a bind failure is not ---
# A static config mistake must stop startup (like every other config error),
# so a bad deploy cannot look healthy while the HTTPS endpoint is missing.
run_expect_fatal() {
  local logfile="$1" want="$2" rc=0
  timeout 10 "$PHOENIX_SERVER_BIN" --config "$RUN_DIR/config.json" >"$logfile" 2>&1 || rc=$?
  [[ "$rc" -ne 0 && "$rc" -ne 124 ]] || die "server did not refuse to start (rc=$rc)"
  assert_contains "$(cat "$logfile")" "$want" "fatal startup reason missing"
  if curl -fsS --max-time 2 "$PHOENIX_SERVER/v1/health" >/dev/null 2>&1; then
    die "primary endpoint served despite fatal optional misconfiguration"
  fi
}
config_patch "d['https_listener']['cert']='$RUN_DIR/missing.crt'"
run_expect_fatal "$RUN_DIR/fatal-cert.log" "invalid config: https_listener: loading certificate"
config_patch "d['https_listener']['cert']='$RUN_DIR/server.crt'; d['https_listener']['listen']=''"
run_expect_fatal "$RUN_DIR/fatal-listen.log" "invalid config: https_listener.listen is required"
ok "optional HTTPS misconfiguration stops startup"

# A runtime bind failure is contained: the primary reserves its port first,
# so pointing the optional listener at it fails only the optional endpoint.
config_patch "d['https_listener']['listen']='127.0.0.1:$PORT'"
start_server
assert_contains "$(cat "$RUN_DIR/server.log")" "primary endpoint continues" "overlapping optional port not reported"
assert_eq "$(phoenix_admin get dual/key)" synthetic-http-update "primary reserves its port before optional HTTPS"
stop_server
config_patch "d['https_listener']['enabled']=False; d['https_listener']['cert']='$RUN_DIR/missing.crt'"
start_server
assert_eq "$(phoenix_admin get dual/key)" synthetic-http-update "disabled optional config ignored"
assert_not_contains "$(cat "$RUN_DIR/server.log")" "Optional HTTPS listener" "disabled optional listener attempted setup"
ok "optional bind failure and disabled configuration preserve HTTP"

stop_server
ok "Scenario 19 passed"
