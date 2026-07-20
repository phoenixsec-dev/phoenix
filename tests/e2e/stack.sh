#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$ROOT_DIR/docker-compose.e2e.yml"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-phoenix-e2e-$(id -u)}"
compose=(docker compose -p "$COMPOSE_PROJECT_NAME" -f "$COMPOSE_FILE")
command -v docker >/dev/null 2>&1 || { echo 'docker is required' >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo 'docker compose plugin is required' >&2; exit 1; }
case "${1:-}" in
  up) "${compose[@]}" up -d --build; "${compose[@]}" ps ;;
  down) "${compose[@]}" down -v ;;
  ps) "${compose[@]}" ps ;;
  logs) "${compose[@]}" logs --tail 100 "${2:-}" ;;
  *) echo "Usage: $0 {up|down|ps|logs [service]}" >&2; exit 2 ;;
esac
