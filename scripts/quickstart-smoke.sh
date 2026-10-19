#!/usr/bin/env bash
# Runs the docs/quickstart.md commands end to end and fails if they break
# or take longer than the 2-minute promise. Keep the two in sync: if you
# change a quickstart command, change it here too.
#
#   scripts/quickstart-smoke.sh                  # binaries on PATH (Option A)
#   scripts/quickstart-smoke.sh --docker IMAGE   # Docker image (Option B + TLS-from-host)
#
# Env: PHOENIX_SMOKE_PORT (default 19090) is the host port used instead of
# 9090, so the smoke never collides with a real server on this machine.
set -euo pipefail

PORT="${PHOENIX_SMOKE_PORT:-19090}"
LIMIT_SECONDS=120
START=$SECONDS
WORK="$(mktemp -d -t phoenix-quickstart-XXXXXX)"
SERVER_PID=""
CONTAINER=""
VOLUME=""

# cleanup keeps the script's own exit status. errexit is off in here
# because waiting on the server we just killed returns 143 by design.
cleanup() {
  local rc=$?
  set +e
  if [[ -n "$SERVER_PID" ]]; then kill "$SERVER_PID"; wait "$SERVER_PID" 2>/dev/null; fi
  if [[ -n "$CONTAINER" ]]; then docker rm -f "$CONTAINER" >/dev/null; fi
  if [[ -n "$VOLUME" ]]; then docker volume rm "$VOLUME" >/dev/null; fi
  rm -rf "$WORK"
  exit "$rc"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

# wait_for runs "$@" until it succeeds, for up to 10 seconds.
wait_for() {
  for _ in $(seq 1 50); do "$@" >/dev/null 2>&1 && return 0; sleep 0.2; done
  "$@" # one last time, with output, so the failure is visible
}

token_from_init() { awk '/ADMIN TOKEN/{getline; print; exit}'; }

smoke_binaries() {
  echo "==> init"
  PHOENIX_TOKEN="$(phoenix-server --init "$WORK/phoenix" | token_from_init)"
  [[ -n "$PHOENIX_TOKEN" ]] || fail "no admin token in --init output"
  export PHOENIX_TOKEN
  sed -i.bak "s/127.0.0.1:9090/127.0.0.1:$PORT/" "$WORK/phoenix/config.json"
  export PHOENIX_SERVER="http://127.0.0.1:$PORT"

  echo "==> start"
  phoenix-server --config "$WORK/phoenix/config.json" >"$WORK/server.log" 2>&1 &
  SERVER_PID=$!
  wait_for phoenix status || { cat "$WORK/server.log" >&2; fail "server did not come up"; }

  echo "==> set / get / exec"
  printf '%s' 'sk-demo-123' | phoenix set demo/api-key --value-stdin
  [[ "$(phoenix get demo/api-key)" == "sk-demo-123" ]] || fail "get returned the wrong value"
  out="$(phoenix exec --env API_KEY=phoenix://demo/api-key -- sh -c 'echo "API_KEY has ${#API_KEY} chars"')"
  [[ "$out" == "API_KEY has 11 chars" ]] || fail "exec output: $out"
}

smoke_docker() {
  local image="$1"
  VOLUME="phoenix-quickstart-$$"
  CONTAINER="phoenix-quickstart-$$"

  echo "==> init (docker)"
  PHOENIX_TOKEN="$(docker run --rm -v "$VOLUME:/data" "$image" --init /data | token_from_init)"
  [[ -n "$PHOENIX_TOKEN" ]] || fail "no admin token in --init output"
  export PHOENIX_TOKEN

  echo "==> start (docker, loopback only)"
  docker run -d --name "$CONTAINER" -v "$VOLUME:/data" "$image" >/dev/null
  wait_for docker exec -e PHOENIX_TOKEN "$CONTAINER" phoenix status || fail "server did not come up"

  echo "==> set / get (docker exec)"
  printf '%s' 'sk-demo-123' | docker exec -i -e PHOENIX_TOKEN "$CONTAINER" phoenix set demo/api-key --value-stdin
  [[ "$(docker exec -e PHOENIX_TOKEN "$CONTAINER" phoenix get demo/api-key)" == "sk-demo-123" ]] \
    || fail "get returned the wrong value"

  echo "==> TLS from host"
  docker rm -f "$CONTAINER" >/dev/null
  docker run --rm -v "$VOLUME:/data" --entrypoint sed "$image" -i \
    -e 's/"listen": "127.0.0.1:9090"/"listen": "0.0.0.0:9090"/' \
    -e '/"tls": {/{n;s/"enabled": false/"enabled": true/;}' \
    /data/config.json
  docker run -d --name "$CONTAINER" -p "127.0.0.1:$PORT:9090" -v "$VOLUME:/data" "$image" >/dev/null
  # The host may not have the phoenix CLI; use the one inside the image,
  # but on the host network namespace so the request really crosses the
  # published port with certificate verification.
  docker cp -q "$CONTAINER:/data/ca.crt" "$WORK/ca.crt"
  chmod 644 "$WORK/ca.crt"
  local host_get=(docker run --rm --network host -v "$WORK/ca.crt:/ca.crt:ro"
    -e PHOENIX_TOKEN -e PHOENIX_SERVER="https://127.0.0.1:$PORT" -e PHOENIX_CA_CERT=/ca.crt
    --entrypoint phoenix "$image" get demo/api-key)
  wait_for "${host_get[@]}" || fail "HTTPS from host failed"
  [[ "$("${host_get[@]}")" == "sk-demo-123" ]] || fail "HTTPS get returned the wrong value"
}

if [[ "${1:-}" == "--docker" ]]; then
  [[ -n "${2:-}" ]] || fail "usage: $0 --docker IMAGE"
  smoke_docker "$2"
else
  smoke_binaries
fi

elapsed=$((SECONDS - START))
(( elapsed <= LIMIT_SECONDS )) || fail "took ${elapsed}s, over the ${LIMIT_SECONDS}s quickstart budget"
echo "PASS: quickstart in ${elapsed}s"
