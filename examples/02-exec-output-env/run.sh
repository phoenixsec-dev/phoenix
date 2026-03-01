#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "$0")/.." && pwd)/lib/common.sh"
trap stop_local_phoenix EXIT

start_local_phoenix

echo "==> Preparing secrets"
"$PHX_BIN" set app/openai-key -v "sk-live-example" -d "OpenAI key"
"$PHX_BIN" set app/db-pass -v "db-pass-example" -d "DB password"

env_file="$EXAMPLE_DATA_DIR/app.env"

echo "==> Writing resolved env file"
"$PHX_BIN" exec \
  --env OPENAI_KEY=phoenix://app/openai-key \
  --env DB_PASSWORD=phoenix://app/db-pass \
  --output-env "$env_file"

echo "Generated env file: $env_file"
cat "$env_file"

echo "✅ Example 2 complete"
