#!/usr/bin/env bash
# Scenario 19 — secure transport: tls block, plaintext warnings, mTLS compat.
#
# Covers the transport model:
#   - loopback plaintext is the default and starts silently (no warning)
#   - a non-loopback bind without TLS emits the loud INSECURE TRANSPORT
#     warning and Phoenix still proceeds (warn, never refuse)
#   - "tls": {"enabled": true} serves HTTPS with the --init leaf, no mTLS
#   - auth.mtls.enabled continues to serve TLS unchanged (backward compat)
#   - CLI warns (but works) on plaintext non-loopback PHOENIX_SERVER
#   - MCP HTTP transport serves TLS via --tls-cert/--tls-key and warns on
#     plaintext non-loopback binds
#   - optional HTTPS shares HTTP auth/store/session/policy/dashboard state
#   - optional HTTPS misconfiguration (blank address, bad certificate) stops
#     startup; an optional bind failure is logged and HTTP stays available
#
# Per harness convention, nothing here binds a non-loopback interface. The
# non-loopback warning is asserted with a TEST-NET-1 address (192.0.2.1,
# RFC 5737): the warning is emitted before the bind attempt, so the log
# proves Phoenix warned and proceeded; the bind then fails at the OS level.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

scenario_start 19 "secure transport: tls block, plaintext warnings, mTLS compat"
init_scenario 19
PORT="${PHOENIX_SERVER##*:}"

# --- 1. Loopback plaintext default: starts, serves, and does not warn ---
start_server
log "loopback plaintext default"
server_log="$(cat "$RUN_DIR/server.log")"
assert_contains "$server_log" "TLS: disabled (plaintext HTTP)" "loopback plaintext should state TLS is off"
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
assert_contains "$warn_log" '"tls": { "enabled": true }' "warning must show the one-line fix"
assert_contains "$warn_log" "server error: listen" "warning must precede the bind attempt (warn, never refuse)"
assert_not_contains "$warn_log" "dashboard" "no dashboard line when dashboard is disabled"
ok "non-loopback plaintext: loud warning, startup not refused"

# --- 4. Dashboard enabled adds the dashboard exposure line ---
config_patch "d['dashboard']={'enabled': True, 'pin': '123456'}"
run_expect_warning "$RUN_DIR/warn-dash.log"
warn_log="$(cat "$RUN_DIR/warn-dash.log")"
assert_contains "$warn_log" "dashboard passwords and session cookies" "dashboard exposure line missing"
ok "dashboard on non-loopback plaintext: warning names the cookie exposure"
config_patch "d['dashboard']={'enabled': False}"

# --- 5. tls.enabled=true: HTTPS with the --init leaf, no mTLS involved ---
config_patch "d['server']['listen']='127.0.0.1:$PORT'; d['tls']={'enabled': True}"
PHOENIX_SERVER="https://127.0.0.1:$PORT"
export PHOENIX_SERVER
start_server
server_log="$(cat "$RUN_DIR/server.log")"
assert_contains "$server_log" "TLS: enabled" "tls.enabled must serve TLS"
assert_not_contains "$server_log" "INSECURE TRANSPORT" "TLS-enabled server must not warn"
assert_not_contains "$server_log" "mTLS: enabled" "tls block must not activate mTLS"

# Plain http against the TLS listener must fail.
if curl -fsS -m 3 "http://127.0.0.1:$PORT/v1/health" >/dev/null 2>&1; then
  die "plaintext request succeeded against a TLS listener"
fi

# CLI over https with the CA cert: works, no warning.
cli_out="$(PHOENIX_CA_CERT="$RUN_DIR/ca.crt" phoenix_admin status 2>"$RUN_DIR/cli-tls.stderr")"
assert_contains "$cli_out" "Server: ok" "CLI status over TLS should report ok"
cli_stderr="$(cat "$RUN_DIR/cli-tls.stderr")"
assert_not_contains "$cli_stderr" "WARNING" "CLI must not warn on https://"
ok "tls.enabled serves HTTPS with the --init certificate (no mTLS)"
stop_server

# --- 6. Backward compat: mtls.enabled alone still serves TLS unchanged ---
config_patch "d['tls']={'enabled': False}; d['auth']['mtls']['enabled']=True; d['auth']['mtls']['require']=False"
start_server
server_log="$(cat "$RUN_DIR/server.log")"
assert_contains "$server_log" "mTLS: enabled (require=false)" "mtls-only config must keep enabling mTLS"
assert_contains "$server_log" "TLS: enabled" "mtls-only config must keep serving TLS"
ok "existing mtls-only configs serve TLS unchanged"
stop_server

# --- 7. MCP HTTP transport: TLS serving and plaintext warning ---
MCP_PORT="$(free_port)"
MCP_TOKEN="synthetic-mcp-token-scenario19"
PHOENIX_SERVER="http://127.0.0.1:$PORT"
export PHOENIX_SERVER
config_patch "d['auth']['mtls']['enabled']=False"
start_server

PHOENIX_TOKEN="$ADMIN_TOKEN" "$PHOENIX" mcp-server \
  --http "127.0.0.1:$MCP_PORT" --mcp-token "$MCP_TOKEN" \
  --tls-cert "$RUN_DIR/server.crt" --tls-key "$RUN_DIR/server.key" \
  >"$RUN_DIR/mcp.log" 2>&1 &
MCP_PID=$!
for i in $(seq 1 50); do
  if curl -fsS --cacert "$RUN_DIR/ca.crt" -m 2 -o /dev/null -w '' \
    -X POST "https://127.0.0.1:$MCP_PORT/mcp" \
    -H "Authorization: Bearer $MCP_TOKEN" -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' 2>/dev/null; then
    break
  fi
  kill -0 "$MCP_PID" 2>/dev/null || { cat "$RUN_DIR/mcp.log" >&2; die "MCP TLS server exited during startup"; }
  sleep 0.1
done
mcp_resp="$(curl -fsS --cacert "$RUN_DIR/ca.crt" -X POST "https://127.0.0.1:$MCP_PORT/mcp" \
  -H "Authorization: Bearer $MCP_TOKEN" -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')"
assert_contains "$mcp_resp" '"result"' "MCP initialize over TLS should answer"
assert_contains "$(cat "$RUN_DIR/mcp.log")" "(TLS)" "MCP log should state TLS listening"
kill "$MCP_PID" 2>/dev/null || true
wait "$MCP_PID" 2>/dev/null || true
ok "MCP HTTP transport serves TLS with --tls-cert/--tls-key"

# Mismatched flags fail closed.
rc=0
PHOENIX_TOKEN="$ADMIN_TOKEN" "$PHOENIX" mcp-server --http "127.0.0.1:$MCP_PORT" \
  --mcp-token "$MCP_TOKEN" --tls-cert "$RUN_DIR/server.crt" >"$RUN_DIR/mcp-mismatch.log" 2>&1 || rc=$?
[[ "$rc" -ne 0 ]] || die "mcp-server accepted --tls-cert without --tls-key"
assert_contains "$(cat "$RUN_DIR/mcp-mismatch.log")" "--tls-cert and --tls-key must be set together" "mismatch error missing"
ok "MCP HTTP transport rejects a lone --tls-cert"

# Plaintext non-loopback MCP bind warns before the (failing) bind attempt.
rc=0
PHOENIX_TOKEN="$ADMIN_TOKEN" timeout 10 "$PHOENIX" mcp-server --http "192.0.2.1:$MCP_PORT" \
  --mcp-token "$MCP_TOKEN" >"$RUN_DIR/mcp-warn.log" 2>&1 || rc=$?
[[ "$rc" -ne 0 ]] || die "MCP server unexpectedly bound a TEST-NET-1 address"
mcp_warn="$(cat "$RUN_DIR/mcp-warn.log")"
assert_contains "$mcp_warn" "INSECURE TRANSPORT" "MCP non-loopback plaintext must warn"
assert_contains "$mcp_warn" "MCP bearer token" "MCP warning must name the token exposure"
ok "MCP HTTP transport warns on non-loopback plaintext"

# --- 8. Optional HTTPS preserves HTTP and shares application state ---
phoenix_admin set dual/key -v synthetic-dual >/dev/null
phoenix_admin set forbidden/key -v synthetic-denied >/dev/null
phoenix_admin set source-denied/key -v synthetic-ip-denied >/dev/null
phoenix_admin agent create dual-reader -t synthetic-dual-reader --acl 'dual/*:read' >/dev/null
stop_server
HTTPS_PORT="$(free_port)"
HTTP_URL="$PHOENIX_SERVER"
HTTPS_URL="https://127.0.0.1:$HTTPS_PORT"
cat >"$RUN_DIR/dual-policy.json" <<'JSON'
{"attestation":{"dual/*":{"source_ip":["127.0.0.1"]},"source-denied/*":{"source_ip":["192.0.2.1"]}}}
JSON
config_patch "d['https_listener']={'enabled':True,'listen':'127.0.0.1:$HTTPS_PORT','cert':'$RUN_DIR/server.crt','key':'$RUN_DIR/server.key'}; d['policy']={'path':'$RUN_DIR/dual-policy.json'}; d['session']={'enabled':True,'roles':{'dual-reader':{'namespaces':['dual/*'],'actions':['read_value'],'bootstrap_trust':['bearer']}}}; d['dashboard']={'enabled':True,'pin':'123456','allow_multi_login':True}"
start_server
assert_contains "$(cat "$RUN_DIR/server.log")" "Optional HTTPS listener serving" "optional listener startup missing"

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
PHOENIX_SERVER="$HTTPS_URL" PHOENIX_CA_CERT="$RUN_DIR/ca.crt" phoenix_admin set dual/key -v synthetic-updated >/dev/null
assert_eq "$(phoenix_admin get dual/key)" synthetic-updated "HTTPS write visible over existing HTTP"
phoenix_admin set dual/key -v synthetic-http-update >/dev/null
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
    "$url/dashboard/login" --data 'credential=123456')"
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

# --- 9. Optional misconfiguration is fatal; optional bind failure is not ---
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
