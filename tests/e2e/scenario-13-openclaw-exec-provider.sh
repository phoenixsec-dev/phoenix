#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 13 openclaw-exec-provider
init_scenario 13
start_server
printf '%s' synthetic-openclaw-one | phoenix_admin set openclaw/one --value-stdin >/dev/null
printf '%s' synthetic-openclaw-two | phoenix_admin set openclaw/two --value-stdin >/dev/null
run_provider() { PHOENIX_TOKEN="$ADMIN_TOKEN" "$PHOENIX" openclaw-exec-provider; }
out="$(printf '%s' '{"protocolVersion":1,"provider":"phoenix","ids":["openclaw/one","phoenix://openclaw/two"]}' | run_provider)"
assert_eq "$(jq -r '.values["openclaw/one"]' <<<"$out")" synthetic-openclaw-one
assert_eq "$(jq -r '.values["phoenix://openclaw/two"]' <<<"$out")" synthetic-openclaw-two
partial="$(printf '%s' '{"protocolVersion":1,"provider":"phoenix","ids":["openclaw/one","openclaw/missing"]}' | run_provider)"
assert_eq "$(jq -r '.values["openclaw/one"]' <<<"$partial")" synthetic-openclaw-one
[[ "$(jq -r '.errors["openclaw/missing"].message' <<<"$partial")" != null ]] || die "per-id error missing"
empty="$(printf '%s' '{"protocolVersion":1,"provider":"phoenix","ids":[]}' | PHOENIX_SERVER=http://127.0.0.1:1 PHOENIX_TOKEN=synthetic-unused "$PHOENIX" openclaw-exec-provider)"
assert_eq "$(jq -r '.values | length' <<<"$empty")" 0
if printf '%s' '{"protocolVersion":1,"provider":"phoenix","ids":[]}{}' | run_provider >"$RUN_DIR/trailing.out" 2>"$RUN_DIR/trailing.err"; then die "trailing JSON accepted"; fi
assert_contains "$(cat "$RUN_DIR/trailing.err")" 'trailing data'
dupe="$(printf '%s' '{"protocolVersion":1,"provider":"phoenix","ids":["openclaw/one","openclaw/one"]}' | run_provider)"
assert_eq "$(jq -r '.values["openclaw/one"]' <<<"$dupe")" synthetic-openclaw-one
# The old extra names were removed and point at the one that stays.
for old in "resolve --stdin-json" "secret-provider openclaw"; do
  rc=0
  # shellcheck disable=SC2086
  printf '%s' '{"protocolVersion":1,"provider":"phoenix","ids":["openclaw/two"]}' | PHOENIX_TOKEN="$ADMIN_TOKEN" "$PHOENIX" $old >"$RUN_DIR/alias.out" 2>&1 || rc=$?
  [[ "$rc" -eq 1 ]] || die "phoenix $old did not fail (rc=$rc)"
  assert_contains "$(cat "$RUN_DIR/alias.out")" "openclaw-exec-provider" "phoenix $old must name the command to use"
done
ok "Scenario 13 PASS"
