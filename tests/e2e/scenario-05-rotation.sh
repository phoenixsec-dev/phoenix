#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 05 rotation-under-load
init_scenario 05
start_server
for i in $(seq 1 50); do phoenix_admin set "rotation/ns$((i%10))/key$i" -v "synthetic-rotation-$i" >/dev/null; done
(
  for _ in $(seq 1 30); do PHOENIX_TOKEN="$ADMIN_TOKEN" "$PHOENIX" get rotation/ns1/key1 >/dev/null; sleep 0.05; done
) & reader=$!
rotation="$(phoenix_admin rotate-master)"
wait "$reader"
[[ -f "$RUN_DIR/master.key.prev" ]] || die "master.key.prev missing"
assert_contains "$rotation" 'Namespaces re-wrapped: 1' "rotation count"
for i in 1 17 50; do assert_eq "$(phoenix_admin get "rotation/ns$((i%10))/key$i")" "synthetic-rotation-$i"; done
assert_contains "$(phoenix_admin audit -n 100)" rotate-master "rotation audit"
ok "Scenario 05 PASS"
