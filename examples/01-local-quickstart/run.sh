#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "$0")/.." && pwd)/lib/common.sh"
trap stop_local_phoenix EXIT

start_local_phoenix

echo "==> Storing secrets"
"$PHX_BIN" set demo/api-key -v "sk-demo-123" -d "Example API key"
"$PHX_BIN" set demo/db-password -v "hunter2" -d "Example DB password"

echo "==> Preferred: inject secret into a command via phoenix exec"
"$PHX_BIN" exec \
  --env API_KEY=phoenix://demo/api-key \
  -- sh -c 'echo "API_KEY available in child process (${#API_KEY} chars)"'

echo "==> Optional explicit resolve (debug/manual inspection)"
"$PHX_BIN" resolve phoenix://demo/api-key phoenix://demo/db-password

echo "✅ Example 1 complete"
