#!/usr/bin/env bash
set -euo pipefail

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$E2E_DIR" rev-parse --show-toplevel)"
E2E_BIN_DIR="${E2E_BIN_DIR:-${TMPDIR:-/tmp}/phoenix-e2e-bin-$(id -u)}"
GO_BIN="${GO_BIN:-$(command -v go 2>/dev/null || true)}"
PHOENIX="$E2E_BIN_DIR/phoenix"
PHOENIX_SERVER_BIN="$E2E_BIN_DIR/phoenix-server"

# Scenarios opt into auth inputs explicitly. Never inherit a developer's live
# Phoenix role, token, certificate, seal key, or policy configuration.
unset PHOENIX_TOKEN PHOENIX_ROLE PHOENIX_CLIENT_CERT PHOENIX_CLIENT_KEY
unset PHOENIX_CA_CERT PHOENIX_SEAL_KEY PHOENIX_POLICY

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[1;34m'; NC='\033[0m'
log()  { printf "${BLUE}[INFO]${NC} %s\n" "$*"; }
ok()   { printf "${GREEN}[OK]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }
fail() { printf "${RED}[FAIL]${NC} %s\n" "$*" >&2; return 1; }
die()  { fail "$*"; exit 1; }
skip() { warn "SKIP: $*"; exit 77; }
scenario_start() { log "Scenario $1: $2"; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || skip "$1 is not installed"; }
assert_eq() { [[ "$1" == "$2" ]] || die "${3:-values differ}: got '$1', want '$2'"; }
assert_contains() { [[ "$1" == *"$2"* ]] || die "${3:-output missing expected text}: $2"; }
assert_not_contains() { [[ "$1" != *"$2"* ]] || die "${3:-output contains forbidden text}: $2"; }

build_current() {
  [[ -n "$GO_BIN" && -x "$GO_BIN" ]] || die "Go is not available; set GO_BIN to the Go executable"
  mkdir -p "$E2E_BIN_DIR"
  if [[ ! -x "$PHOENIX" || ! -x "$PHOENIX_SERVER_BIN" || "${E2E_REBUILD:-0}" == 1 ]]; then
    log "Building current Phoenix binaries into $E2E_BIN_DIR"
    (cd "$REPO_ROOT" && "$GO_BIN" build -o "$E2E_BIN_DIR/" ./cmd/...)
  fi
}

free_port() {
  python3 - <<'PY'
import socket
with socket.socket() as s:
    s.bind(('127.0.0.1', 0))
    print(s.getsockname()[1])
PY
}

init_scenario() {
  local id="$1" port="${2:-}"
  require_cmd python3
  require_cmd curl
  require_cmd jq
  [[ -n "$port" ]] || port="$(free_port)"
  build_current
  RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/phoenix-e2e-s${id}.XXXXXX")"
  SERVER_PID=""
  "$PHOENIX_SERVER_BIN" --init "$RUN_DIR" >"$RUN_DIR/init.out"
  ADMIN_TOKEN="$(python3 - "$RUN_DIR/init.out" <<'PY'
import re, sys
s=open(sys.argv[1], encoding='utf-8').read()
m=re.search(r'ADMIN TOKEN.*?\n([a-f0-9]{32,})', s, re.S)
print(m.group(1) if m else '')
PY
)"
  [[ -n "$ADMIN_TOKEN" ]] || die "could not parse generated admin token"
  python3 - "$RUN_DIR/config.json" "$port" <<'PY'
import json, sys
p=sys.argv[1]; d=json.load(open(p, encoding='utf-8'))
d['server']['listen']='127.0.0.1:'+sys.argv[2]
json.dump(d, open(p,'w', encoding='utf-8'), indent=2)
PY
  PHOENIX_SERVER="http://127.0.0.1:$port"
  export RUN_DIR ADMIN_TOKEN PHOENIX_SERVER
  trap cleanup_scenario EXIT INT TERM
}

config_patch() {
  local python_body="$1"
  PYTHON_BODY="$python_body" python3 - "$RUN_DIR/config.json" <<'PY'
import json, os, sys
p=sys.argv[1]; d=json.load(open(p, encoding='utf-8'))
exec(os.environ['PYTHON_BODY'], {'d': d})
json.dump(d, open(p,'w', encoding='utf-8'), indent=2)
PY
}

start_server() {
  "$PHOENIX_SERVER_BIN" --config "$RUN_DIR/config.json" >"$RUN_DIR/server.log" 2>&1 &
  SERVER_PID=$!
  local i
  local -a health_args=(-fsS)
  [[ "$PHOENIX_SERVER" != https://* ]] || health_args+=(--cacert "$RUN_DIR/ca.crt")
  for i in $(seq 1 100); do
    if curl "${health_args[@]}" "$PHOENIX_SERVER/v1/health" >/dev/null 2>&1; then
      kill -0 "$SERVER_PID" >/dev/null 2>&1 || { tail -50 "$RUN_DIR/server.log" >&2; die "health answered but scenario server exited (port collision likely)"; }
      sleep 0.05
      kill -0 "$SERVER_PID" >/dev/null 2>&1 || { tail -50 "$RUN_DIR/server.log" >&2; die "scenario server exited after health check"; }
      return 0
    fi
    kill -0 "$SERVER_PID" >/dev/null 2>&1 || { tail -50 "$RUN_DIR/server.log" >&2; die "server exited during startup"; }
    sleep 0.1
  done
  die "server did not become healthy"
}

stop_server() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
    SERVER_PID=""
  fi
}

cleanup_scenario() {
  local rc=$?
  stop_server
  if [[ -n "${RUN_DIR:-}" && -d "$RUN_DIR" ]]; then
    find "$RUN_DIR" -depth -mindepth 1 -delete 2>/dev/null || true
    rmdir "$RUN_DIR" 2>/dev/null || true
  fi
  return "$rc"
}

phoenix_admin() { PHOENIX_TOKEN="$ADMIN_TOKEN" "$PHOENIX" "$@"; }
api_admin() {
  local method="$1" path="$2" body="${3:-}"
  local -a args=(-fsS -X "$method" "$PHOENIX_SERVER$path" -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json')
  [[ "$PHOENIX_SERVER" != https://* ]] || args+=(--cacert "$RUN_DIR/ca.crt")
  [[ -z "$body" ]] || args+=(--data "$body")
  curl "${args[@]}"
}
api_token() {
  local token="$1" method="$2" path="$3" body="${4:-}"
  local -a args=(-fsS -X "$method" "$PHOENIX_SERVER$path" -H "Authorization: Bearer $token" -H 'Content-Type: application/json')
  [[ "$PHOENIX_SERVER" != https://* ]] || args+=(--cacert "$RUN_DIR/ca.crt")
  [[ -z "$body" ]] || args+=(--data "$body")
  curl "${args[@]}"
}
