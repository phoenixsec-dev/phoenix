#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 11 zero-plaintext-config
init_scenario 11
start_server
phoenix_admin set zero/db-password -v synthetic-zero-db >/dev/null
phoenix_admin set zero/api-key -v synthetic-zero-api >/dev/null
cat >"$RUN_DIR/compose.yml" <<'YAML'
services:
  app:
    image: example.invalid/synthetic-only
    environment:
      DATABASE_PASSWORD: phoenix://zero/db-password
      API_KEY: phoenix://zero/api-key
YAML
PHOENIX_TOKEN="$ADMIN_TOKEN" "$PHOENIX" verify "$RUN_DIR/compose.yml" >/dev/null
PHOENIX_TOKEN="$ADMIN_TOKEN" "$PHOENIX" exec --output-env "$RUN_DIR/resolved.env" --env DATABASE_PASSWORD=phoenix://zero/db-password --env API_KEY=phoenix://zero/api-key -- true >/dev/null
grep -qx 'DATABASE_PASSWORD=synthetic-zero-db' "$RUN_DIR/resolved.env" || die "DB env mismatch"
grep -qx 'API_KEY=synthetic-zero-api' "$RUN_DIR/resolved.env" || die "API env mismatch"
assert_not_contains "$(cat "$RUN_DIR/compose.yml" "$RUN_DIR/store.json" "$RUN_DIR/audit.log")" synthetic-zero-db "plaintext leaked outside resolved env"
assert_not_contains "$(cat "$RUN_DIR/compose.yml" "$RUN_DIR/store.json" "$RUN_DIR/audit.log")" synthetic-zero-api "plaintext leaked outside resolved env"
ok "Scenario 11 PASS"
