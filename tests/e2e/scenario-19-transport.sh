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

stop_server
ok "Scenario 19 passed"
