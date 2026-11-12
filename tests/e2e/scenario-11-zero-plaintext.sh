#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 11 zero-plaintext-config
init_scenario 11
start_server
printf '%s' synthetic-zero-db | phoenix_admin set zero/db-password --value-stdin >/dev/null
printf '%s' synthetic-zero-api | phoenix_admin set zero/api-key --value-stdin >/dev/null
cat >"$RUN_DIR/compose.yml" <<'YAML'
services:
  app:
    image: example.invalid/synthetic-only
    environment:
      DATABASE_PASSWORD: phoenix://zero/db-password
      API_KEY: phoenix://zero/api-key
YAML
PHOENIX_TOKEN="$ADMIN_TOKEN" "$PHOENIX" verify "$RUN_DIR/compose.yml" >/dev/null
PHOENIX_TOKEN="$ADMIN_TOKEN" "$PHOENIX" exec --env DATABASE_PASSWORD=phoenix://zero/db-password --env API_KEY=phoenix://zero/api-key -- env >"$RUN_DIR/child.env"
grep -qx 'DATABASE_PASSWORD=synthetic-zero-db' "$RUN_DIR/child.env" || die "DB env mismatch"
grep -qx 'API_KEY=synthetic-zero-api' "$RUN_DIR/child.env" || die "API env mismatch"
rm -f "$RUN_DIR/child.env"
assert_not_contains "$(cat "$RUN_DIR/compose.yml" "$RUN_DIR/store.json" "$RUN_DIR/audit.log")" synthetic-zero-db "plaintext leaked outside the child's environment"
assert_not_contains "$(cat "$RUN_DIR/compose.yml" "$RUN_DIR/store.json" "$RUN_DIR/audit.log")" synthetic-zero-api "plaintext leaked outside the child's environment"
ok "Scenario 11 PASS"
