#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "$0")/.." && pwd)/lib/common.sh"
trap stop_local_phoenix EXIT

start_local_phoenix

echo "==> Storing secrets"
"$PHX_BIN" set demo/api-key -v "sk-demo-123" -d "Example API key"
"$PHX_BIN" set demo/db-password -v "hunter2" -d "Example DB password"

echo "==> Reading one secret"
"$PHX_BIN" get demo/api-key

echo "==> Resolving references"
"$PHX_BIN" resolve phoenix://demo/api-key phoenix://demo/db-password

echo "✅ Example 1 complete"
