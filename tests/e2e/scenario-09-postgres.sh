#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 09 postgres-integration
require_cmd docker
require_cmd psql
docker compose version >/dev/null 2>&1 || skip "docker compose plugin is not installed"
init_scenario 09
compose="$E2E_DIR/docker-compose.e2e.yml"
project="phoenix-e2e-$(basename "$RUN_DIR" | tr -cd '[:alnum:]-')"
E2E_POSTGRES_PORT="$(free_port)"; export E2E_POSTGRES_PORT
compose_cmd=(docker compose -p "$project" -f "$compose")
cleanup_postgres() { local rc=$?; "${compose_cmd[@]}" down -v >/dev/null 2>&1 || true; cleanup_scenario; return "$rc"; }
trap cleanup_postgres EXIT INT TERM
"${compose_cmd[@]}" up -d postgres >/dev/null
for _ in $(seq 1 60); do PGPASSWORD=synthetic-pg-initial psql -h 127.0.0.1 -p "$E2E_POSTGRES_PORT" -U testuser -d testdb -c 'select 1' >/dev/null 2>&1 && break; sleep 0.5; done
PGPASSWORD=synthetic-pg-initial psql -h 127.0.0.1 -p "$E2E_POSTGRES_PORT" -U testuser -d testdb -c 'select 1' >/dev/null
start_server
phoenix_admin set integration/pg-password -v synthetic-pg-initial >/dev/null
PHOENIX_TOKEN="$ADMIN_TOKEN" "$PHOENIX" exec --env PGPASSWORD=phoenix://integration/pg-password -- psql -h 127.0.0.1 -p "$E2E_POSTGRES_PORT" -U testuser -d testdb -c 'select 1' >/dev/null
PGPASSWORD=synthetic-pg-initial psql -h 127.0.0.1 -p "$E2E_POSTGRES_PORT" -U testuser -d testdb -c "alter user testuser password 'synthetic-pg-rotated'" >/dev/null
phoenix_admin set integration/pg-password -v synthetic-pg-rotated >/dev/null
PHOENIX_TOKEN="$ADMIN_TOKEN" "$PHOENIX" exec --env PGPASSWORD=phoenix://integration/pg-password -- psql -h 127.0.0.1 -p "$E2E_POSTGRES_PORT" -U testuser -d testdb -c 'select 1' >/dev/null
if PGPASSWORD=synthetic-pg-initial psql -h 127.0.0.1 -p "$E2E_POSTGRES_PORT" -U testuser -d testdb -c 'select 1' >/dev/null 2>&1; then die "old PostgreSQL password still works"; fi
ok "Scenario 09 PASS"
