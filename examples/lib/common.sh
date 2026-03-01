#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PHX_BIN="${PHX_BIN:-$ROOT_DIR/bin/phoenix}"
PHX_SERVER_BIN="${PHX_SERVER_BIN:-$ROOT_DIR/bin/phoenix-server}"

GO_BIN="${GO_BIN:-}"
if [[ -z "$GO_BIN" ]]; then
  if command -v go >/dev/null 2>&1; then
    GO_BIN="$(command -v go)"
  elif [[ -x "/home/aaron/.local/go/bin/go" ]]; then
    GO_BIN="/home/aaron/.local/go/bin/go"
  else
    echo "error: go binary not found in PATH" >&2
    exit 1
  fi
fi

ensure_binaries() {
  if [[ -x "$PHX_BIN" && -x "$PHX_SERVER_BIN" ]]; then
    return
  fi

  echo "Building phoenix binaries..."
  mkdir -p "$ROOT_DIR/bin"
  "$GO_BIN" build -o "$PHX_BIN" "$ROOT_DIR/cmd/phoenix"
  "$GO_BIN" build -o "$PHX_SERVER_BIN" "$ROOT_DIR/cmd/phoenix-server"
}

pick_free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

start_local_phoenix() {
  ensure_binaries

  EXAMPLE_DATA_DIR="$(mktemp -d -t phoenix-example-XXXXXX)"
  export EXAMPLE_DATA_DIR

  local init_output
  init_output="$($PHX_SERVER_BIN --init "$EXAMPLE_DATA_DIR")"

  PHOENIX_ADMIN_TOKEN="$(printf "%s\n" "$init_output" | awk '/ADMIN TOKEN/{getline; print; exit}')"
  if [[ -z "$PHOENIX_ADMIN_TOKEN" ]]; then
    echo "error: failed to parse admin token from init output" >&2
    exit 1
  fi

  EXAMPLE_PORT="$(pick_free_port)"
  export EXAMPLE_PORT

  python3 - "$EXAMPLE_DATA_DIR/config.json" "$EXAMPLE_PORT" <<'PY'
import json, pathlib, sys
cfg_path = pathlib.Path(sys.argv[1])
port = sys.argv[2]
cfg = json.loads(cfg_path.read_text())
cfg["server"]["listen"] = f"127.0.0.1:{port}"
cfg_path.write_text(json.dumps(cfg, indent=2) + "\n")
PY

  export PHOENIX_SERVER="http://127.0.0.1:${EXAMPLE_PORT}"
  export PHOENIX_TOKEN="$PHOENIX_ADMIN_TOKEN"
  unset PHOENIX_CA_CERT

  "$PHX_SERVER_BIN" --config "$EXAMPLE_DATA_DIR/config.json" >"$EXAMPLE_DATA_DIR/server.log" 2>&1 &
  PHOENIX_SERVER_PID=$!
  export PHOENIX_SERVER_PID

  for _ in $(seq 1 50); do
    if "$PHX_BIN" status >/dev/null 2>&1; then
      return
    fi
    sleep 0.2
  done

  echo "error: phoenix-server failed to start. log:" >&2
  cat "$EXAMPLE_DATA_DIR/server.log" >&2 || true
  exit 1
}

stop_local_phoenix() {
  if [[ -n "${PHOENIX_SERVER_PID:-}" ]]; then
    kill "$PHOENIX_SERVER_PID" >/dev/null 2>&1 || true
    wait "$PHOENIX_SERVER_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "${EXAMPLE_DATA_DIR:-}" && -d "$EXAMPLE_DATA_DIR" ]]; then
    rm -rf "$EXAMPLE_DATA_DIR"
  fi
}
