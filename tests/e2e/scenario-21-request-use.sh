#!/usr/bin/env bash
# Request-use grants (P2): deny -> request -> human deny -> cooldown -> request
# a different path -> approve narrowed -> sealed use via phoenix exec -> other
# path 403 -> revoke -> 403 -> restart keeps state -> short TTL expiry -> 403.
# Approval is driven through the API approver (access_requests.approvers);
# the dashboard leg comes with P3. Takes about 70s because the shortest
# legal grant is 1 minute.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 21 request-use-grants
init_scenario 21
# --init writes access_requests enabled (new-install default); add an API approver.
config_patch "d['access_requests']['approvers']=['e2e-approver']"
start_server

AGENT=synthetic-request-agent
APPROVER=synthetic-request-approver
phoenix_admin set infra/b2/app-key -v synthetic-b2-key >/dev/null
phoenix_admin set infra/other -v synthetic-other >/dev/null
phoenix_admin set infra/third -v synthetic-third >/dev/null
phoenix_admin set infra/short -v synthetic-short >/dev/null
phoenix_admin agent create e2e-agent -t "$AGENT" --acl 'dev/*:read' >/dev/null
phoenix_admin agent create e2e-approver -t "$APPROVER" --acl 'approver-none/*:list' >/dev/null
keyfile="$RUN_DIR/agent-seal.key"
keyout="$(phoenix_admin keypair generate e2e-agent -o "$keyfile")"
public="$(awk '/public key:/ {print $3}' <<<"$keyout")"; [[ -n "$public" ]] || die "seal public key missing"

# call TOKEN METHOD PATH [BODY] -> prints body, sets HTTP_CODE
call() {
  local tok="$1" method="$2" path="$3" body="${4:-}"
  local -a args=(-sS -o "$RUN_DIR/resp" -D "$RUN_DIR/headers" -w '%{http_code}' -X "$method" "$PHOENIX_SERVER$path"
    -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' -H "X-Phoenix-Seal-Key: $public")
  [[ -z "$body" ]] || args+=(--data "$body")
  HTTP_CODE="$(curl "${args[@]}")"
}
agent_exec() { PHOENIX_TOKEN="$AGENT" PHOENIX_SEAL_KEY="$keyfile" "$PHOENIX" exec "$@"; }

# 1. Denied, and told to request use.
call "$AGENT" GET /v1/secrets/infra/b2/app-key
assert_eq "$HTTP_CODE" 403 "initial denial status"
assert_eq "$(jq -r .code "$RUN_DIR/resp")" ACL_DENIED
assert_eq "$(jq -r .next_step "$RUN_DIR/resp")" request_use

# 2. Request, human denies.
call "$AGENT" POST /v1/access-requests '{"paths":["infra/b2/app-key"],"reason":"e2e: backup job fails auth","ttl":"30m"}'
assert_eq "$HTTP_CODE" 201 "first request"
r1="$(jq -r .id "$RUN_DIR/resp")"
assert_eq "$(jq -r .next_step "$RUN_DIR/resp")" wait
call "$APPROVER" POST "/v1/access-requests/$r1/deny" '{"note":"e2e no"}'
assert_eq "$HTTP_CODE" 200 "deny"
call "$AGENT" GET "/v1/access-requests/$r1"
assert_eq "$(jq -r .status "$RUN_DIR/resp")" denied

# 3. Same path again is in cooldown (429 + Retry-After).
call "$AGENT" POST /v1/access-requests '{"paths":["infra/b2/app-key"],"reason":"again"}'
assert_eq "$HTTP_CODE" 429 "cooldown status"
assert_eq "$(jq -r .code "$RUN_DIR/resp")" REQUEST_COOLDOWN
grep -qi '^retry-after:' "$RUN_DIR/headers" || die "cooldown 429 without Retry-After"

# 4. A different path set is fine; approver narrows it to one path.
call "$AGENT" POST /v1/access-requests '{"paths":["infra/other","infra/third"],"reason":"e2e: need other","ttl":"30m"}'
assert_eq "$HTTP_CODE" 201 "second request"
r2="$(jq -r .id "$RUN_DIR/resp")"
call "$AGENT" POST "/v1/access-requests/$r2/approve" '{}'
assert_eq "$(jq -r .code "$RUN_DIR/resp")" APPROVER_REQUIRED "agent cannot approve"
call "$ADMIN_TOKEN" POST "/v1/access-requests/$r2/approve" '{}'
assert_eq "$(jq -r .code "$RUN_DIR/resp")" APPROVER_REQUIRED "admin ACL alone cannot approve"
call "$APPROVER" POST "/v1/access-requests/$r2/approve" '{"paths":["infra/other"],"ttl":"15m"}'
assert_eq "$HTTP_CODE" 200 "approve narrowed"
grant_a="$(jq -r .grant_id "$RUN_DIR/resp")"
call "$AGENT" GET "/v1/access-requests/$r2"
assert_eq "$(jq -r .next_step "$RUN_DIR/resp")" use_exec

# 5. Sealed use through phoenix exec with the agent's own identity.
agent_exec --env GRANTED=phoenix://infra/other -- env >"$RUN_DIR/env"
grep -qx 'GRANTED=synthetic-other' "$RUN_DIR/env" || die "granted value not delivered through exec"
! grep -q '^PHOENIX_TOKEN=' "$RUN_DIR/env" || die "exec leaked PHOENIX_TOKEN to the child"
# Plaintext is refused for a sealed-only grant.
code="$(curl -sS -o "$RUN_DIR/plain" -w '%{http_code}' "$PHOENIX_SERVER/v1/secrets/infra/other" -H "Authorization: Bearer $AGENT")"
assert_eq "$code" 403 "plaintext read of sealed-only grant"
assert_eq "$(jq -r .code "$RUN_DIR/plain")" SEALED_REQUIRED
# Grant-only access never unseals.
call "$AGENT" GET '/v1/policy/check?path=infra/other&check=allow_unseal'
assert_eq "$(jq -r .allowed "$RUN_DIR/resp")" false "allow_unseal for a grant-only path"

# 6. The narrowed-out path stays denied.
if agent_exec --env NOPE=phoenix://infra/third -- true >"$RUN_DIR/third" 2>&1; then die "narrowed-out path was readable"; fi
assert_contains "$(cat "$RUN_DIR/third")" ACL_DENIED "narrowed-out path denial"

# 7. A short grant on another path (expires during the restart leg).
call "$AGENT" POST /v1/access-requests '{"paths":["infra/short"],"reason":"e2e: short","ttl":"30m"}'
r3="$(jq -r .id "$RUN_DIR/resp")"
call "$APPROVER" POST "/v1/access-requests/$r3/approve" '{"ttl":"1m"}'
assert_eq "$HTTP_CODE" 200 "approve short grant"
short_started=$SECONDS
agent_exec --env SHORT=phoenix://infra/short -- env | grep -qx 'SHORT=synthetic-short' || die "short grant not usable"

# 8. Revoke is immediate.
call "$APPROVER" POST "/v1/grants/$grant_a/revoke"
assert_eq "$HTTP_CODE" 200 "revoke"
if agent_exec --env GRANTED=phoenix://infra/other -- true >"$RUN_DIR/revoked" 2>&1; then die "revoked grant still usable"; fi
assert_contains "$(cat "$RUN_DIR/revoked")" GRANT_REVOKED "revoked denial"

# 9. Restart: revoke, the live short grant, and the deny cooldown all survive.
stop_server
start_server
[[ -s "$RUN_DIR/grants.json" ]] || die "grants.json was not written next to the ACL"
[[ "$(stat -c %a "$RUN_DIR/grants.json")" == 600 ]] || die "grants.json mode is not 0600"
if agent_exec --env GRANTED=phoenix://infra/other -- true >"$RUN_DIR/revoked2" 2>&1; then die "revoke lost on restart"; fi
assert_contains "$(cat "$RUN_DIR/revoked2")" GRANT_REVOKED "revoked after restart"
agent_exec --env SHORT=phoenix://infra/short -- env | grep -qx 'SHORT=synthetic-short' || die "short grant lost on restart"
call "$AGENT" POST /v1/access-requests '{"paths":["infra/b2/app-key"],"reason":"after restart"}'
assert_eq "$(jq -r .code "$RUN_DIR/resp")" REQUEST_COOLDOWN "cooldown after restart"

# 10. Short TTL expiry: the next use after expires_at is GRANT_EXPIRED.
remaining=$((62 - (SECONDS - short_started)))
if ((remaining > 0)); then log "waiting ${remaining}s for the 1m grant to expire"; sleep "$remaining"; fi
if agent_exec --env SHORT=phoenix://infra/short -- true >"$RUN_DIR/expired" 2>&1; then die "expired grant still usable"; fi
assert_contains "$(cat "$RUN_DIR/expired")" GRANT_EXPIRED "expired denial"
call "$AGENT" GET '/v1/grants?include=inactive'
assert_eq "$(jq -r '[.grants[] | .state] | sort | join(",")' "$RUN_DIR/resp")" "expired,revoked" "grant states"
call "$ADMIN_TOKEN" GET /v1/status
assert_eq "$(jq -r .access_requests.state "$RUN_DIR/resp")" ok "status access_requests"
ok "Scenario 21 PASS"
