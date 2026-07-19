#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$ROOT_DIR/lib.sh"

usage() {
  cat <<'EOF'
Usage: ./run-all.sh [--list] [--scenarios 01,05,13-foo] [--format human|jsonl|tap]

Scenarios are auto-discovered from executable scenario-NN-name.sh files.
Exit 0 = pass, 77 = skip, any other nonzero = fail.
EOF
}

discover() {
  find "$ROOT_DIR" -maxdepth 1 -type f -name 'scenario-[0-9][0-9]-*.sh' -perm -u+x -printf '%f\n' | LC_ALL=C sort
}

LIST=0; SELECTED=""; FORMAT=human
while [[ $# -gt 0 ]]; do
  case "$1" in
    --list) LIST=1; shift ;;
    --scenarios) [[ $# -ge 2 ]] || die "--scenarios requires a value"; SELECTED="$2"; shift 2 ;;
    --format) [[ $# -ge 2 ]] || die "--format requires a value"; FORMAT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[[ "$FORMAT" == human || "$FORMAT" == jsonl || "$FORMAT" == tap ]] || die "invalid format: $FORMAT"
[[ "$FORMAT" != jsonl ]] || command -v jq >/dev/null 2>&1 || die "--format jsonl requires jq"

mapfile -t ALL < <(discover)
[[ ${#ALL[@]} -gt 0 ]] || die "no executable scenarios discovered"

if [[ "$LIST" -eq 1 ]]; then
  for file in "${ALL[@]}"; do printf '%s\n' "${file#scenario-}" | sed 's/\.sh$//'; done
  exit 0
fi

SELECTED_FILES=()
if [[ -z "$SELECTED" ]]; then
  SELECTED_FILES=("${ALL[@]}")
else
  IFS=',' read -r -a wanted <<<"$SELECTED"
  for raw in "${wanted[@]}"; do
    item="${raw//[[:space:]]/}"
    matches=()
    for file in "${ALL[@]}"; do
      slug="${file#scenario-}"; slug="${slug%.sh}"; id="${slug%%-*}"
      if [[ "$item" == "$id" || "$item" == "$slug" || "$item" == "$file" ]]; then matches+=("$file"); fi
    done
    [[ ${#matches[@]} -eq 1 ]] || die "unknown or ambiguous scenario: $item"
    SELECTED_FILES+=("${matches[0]}")
  done
fi

[[ "$FORMAT" != tap ]] || printf '1..%d\n' "${#SELECTED_FILES[@]}"
failures=0; index=0
for file in "${SELECTED_FILES[@]}"; do
  index=$((index + 1)); slug="${file#scenario-}"; slug="${slug%.sh}"
  started="$(date +%s)"; output="$(mktemp "${TMPDIR:-/tmp}/phoenix-e2e-output.XXXXXX")"
  set +e
  "$ROOT_DIR/$file" >"$output" 2>&1
  rc=$?
  set -e
  duration=$(( $(date +%s) - started ))
  if [[ $rc -eq 0 ]]; then status=pass; elif [[ $rc -eq 77 ]]; then status=skip; else status=fail; failures=$((failures + 1)); fi

  case "$FORMAT" in
    human)
      cat "$output"
      printf '[RESULT] %s %s (%ss)\n' "$status" "$slug" "$duration"
      ;;
    jsonl)
      jq -cn --arg scenario "$slug" --arg status "$status" --argjson exit_code "$rc" --argjson duration_seconds "$duration" \
        '{scenario:$scenario,status:$status,exit_code:$exit_code,duration_seconds:$duration_seconds}'
      [[ "$status" != fail ]] || cat "$output" >&2
      ;;
    tap)
      if [[ "$status" == pass ]]; then
        printf 'ok %d - %s\n' "$index" "$slug"
      elif [[ "$status" == skip ]]; then
        printf 'ok %d - %s # SKIP\n' "$index" "$slug"
      else
        printf 'not ok %d - %s\n' "$index" "$slug"
        sed 's/^/# /' "$output"
      fi
      ;;
  esac
  rm "$output"
done

[[ $failures -eq 0 ]] || exit 1
