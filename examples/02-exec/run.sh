#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "$0")/.." && pwd)/lib/common.sh"
trap stop_local_phoenix EXIT

start_local_phoenix

echo "==> Preparing secrets"
printf '%s' "sk-live-example" | "$PHX_BIN" set app/openai-key --value-stdin -d "OpenAI key"
printf '%s' "db-pass-example" | "$PHX_BIN" set app/db-pass --value-stdin -d "DB password"

# phoenix exec resolves the references and starts the command with the values
# in its environment only: nothing is written to disk, and Phoenix's own
# credentials (PHOENIX_TOKEN and friends) are stripped from the child.
echo "==> Running a command with two secrets in its environment"
"$PHX_BIN" exec \
  --env OPENAI_KEY=phoenix://app/openai-key \
  --env DB_PASSWORD=phoenix://app/db-pass \
  -- sh -c 'echo "OPENAI_KEY: ${#OPENAI_KEY} chars, DB_PASSWORD: ${#DB_PASSWORD} chars, PHOENIX_TOKEN passed on: ${PHOENIX_TOKEN:-no}"'

# --redact-output replaces a secret value that the command prints by mistake.
echo "==> Same command, careless output redacted"
"$PHX_BIN" exec --redact-output \
  --env OPENAI_KEY=phoenix://app/openai-key \
  -- sh -c 'echo "debug: key is $OPENAI_KEY"'

echo "✅ Example 2 complete"
