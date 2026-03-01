#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "$0")/.." && pwd)/lib/common.sh"
trap stop_local_phoenix EXIT

start_local_phoenix

echo "==> Seed secrets"
"$PHX_BIN" set app/ok -v "good"
"$PHX_BIN" set private/nope -v "nope"

echo "==> Verify malformed ACL is rejected"
if "$PHX_BIN" agent create bad-agent -t bad-token --acl "app/*read"; then
  echo "error: malformed ACL was unexpectedly accepted" >&2
  exit 1
else
  echo "Malformed ACL correctly rejected"
fi

echo "==> Create valid ACL agent (with whitespace and trailing semicolon)"
"$PHX_BIN" agent create scanner -t scanner-token --acl " app/*:read ;"

echo "==> Allowed read"
PHOENIX_TOKEN="scanner-token" "$PHX_BIN" get app/ok >/dev/null

echo "==> Denied read"
if PHOENIX_TOKEN="scanner-token" "$PHX_BIN" get private/nope >/dev/null 2>&1; then
  echo "error: scanner unexpectedly read private/nope" >&2
  exit 1
else
  echo "Denied path correctly blocked"
fi

echo "✅ Example 3 complete"
