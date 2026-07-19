#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 12 onepassword-bridge

[[ -n "${OP_SERVICE_ACCOUNT_TOKEN:-}" ]] || skip "OP_SERVICE_ACCOUNT_TOKEN is unset; 1Password backend test is opt-in"
require_cmd op

OP_VAULT="${PHOENIX_E2E_OP_VAULT:-phoenix-test}"
items="$(op item list --vault "$OP_VAULT" --format=json)" || die "could not list the configured 1Password test vault"

fixture=""
while IFS= read -r item_id; do
  fixture="$(op item get "$item_id" --vault "$OP_VAULT" --format=json | jq -r '
    .title as $title
    | .fields[]
    | select(.type == "CONCEALED" or .type == "STRING" or .type == "PASSWORD" or .type == "EMAIL" or .type == "URL")
    | select(($title | test("^[a-z0-9_-]+$")) and (.label | test("^[a-z0-9_-]+$")))
    | [$title, .label]
    | @tsv
  ' | head -n 1)"
  [[ -z "$fixture" ]] || break
done < <(jq -r '.[].id' <<<"$items")
[[ -n "$fixture" ]] || die "configured 1Password test vault has no usable synthetic item field"

IFS=$'\t' read -r item_name field_name <<<"$fixture"
secret_path="$item_name/$field_name"
expected="$(op read "op://$OP_VAULT/$item_name/$field_name")"
[[ -n "$expected" ]] || die "synthetic 1Password fixture resolved to an empty value"

init_scenario 12
vault_json="$(jq -Rn --arg value "$OP_VAULT" '$value')"
config_patch "d['store']['backend']='1password'; d['onepassword']={'enabled': True, 'vault': $vault_json, 'service_account_token_env': 'OP_SERVICE_ACCOUNT_TOKEN', 'cache_ttl': '0s'}"
start_server

actual="$(phoenix_admin resolve "phoenix://$secret_path")"
assert_eq "$actual" "$expected" "Phoenix reference did not resolve the 1Password value"
unset actual expected
ok "Phoenix reference resolved through the 1Password backend"

write_code="$(curl -sS -o "$RUN_DIR/write.json" -w '%{http_code}' -X PUT \
  "$PHOENIX_SERVER/v1/secrets/e2e/write-probe" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"value":"synthetic-write-probe"}')"
assert_eq "$write_code" "405" "1Password backend accepted a write"
assert_contains "$(jq -r '.error // ""' "$RUN_DIR/write.json")" "read-only" "write rejection was not explicit"
ok "read-only backend rejected writes"

missing_ref="phoenix://e2e-missing-item-$$/password"
if missing_output="$(phoenix_admin resolve "$missing_ref" 2>&1)"; then
  die "missing 1Password item unexpectedly resolved"
fi
assert_contains "$missing_output" "secret not found" "missing item did not return a clean not-found error"
ok "missing 1Password item failed cleanly"
