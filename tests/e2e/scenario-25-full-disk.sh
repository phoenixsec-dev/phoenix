#!/usr/bin/env bash
# The data directory on a small filesystem that is really full (tmpfs), once
# with no bytes left and once with no files left:
#   - the server starts; reads, the dashboard login and role sessions work
#   - what cannot be saved answers an error and gives nobody anything; what was
#     taken away is gone at once, says it is not saved, and is saved by itself
#     once there is room
#   - the wrong master key and a missing store or access list are refused
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 25 full-disk
for cmd in curl python3 jq unshare mount dd sha256sum; do require_cmd "$cmd"; done

# Mounting needs root: a private user namespace, or sudo without a password
# (GitHub's runners). Only this scenario sees the mount.
if [[ -z "${E2E_FULL_DISK_NS:-}" ]]; then
  build_current
  if unshare -rm mount -t tmpfs tmpfs /mnt >/dev/null 2>&1; then
    E2E_FULL_DISK_NS=1 E2E_BIN_DIR="$BIN_DIR" exec unshare -rm "${BASH_SOURCE[0]}"
  elif sudo -n true >/dev/null 2>&1; then
    exec sudo -n env "PATH=$PATH" "HOME=$HOME" E2E_FULL_DISK_NS=1 "E2E_BIN_DIR=$BIN_DIR" unshare -m "${BASH_SOURCE[0]}"
  fi
  skip "needs a user namespace that may mount, or sudo without a password"
fi

RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/phoenix-e2e-s25.XXXXXX")"; SERVER_PID=""; trap cleanup_scenario EXIT INT TERM
D="${RUN_DIR:?}/data"; mkdir "$D"
READER=synthetic-full-reader; ASKER=synthetic-full-asker; APPROVER=synthetic-full-approver

# fill HOW / make_room: no bytes left, or no more files.
fill() {
  if [[ "$1" == bytes ]]; then
    dd if=/dev/zero of="$D/filler" bs=4k 2>/dev/null || true
  else
    local i; for i in $(seq 1 1000); do { : >"$D/filler.$i"; } 2>/dev/null || break; done
  fi
  if cp "$D/config.json" "$D/filler.probe" 2>/dev/null; then die "the disk is not full ($1)"; fi
}
make_room() { find "${D:?}" -maxdepth 1 -name 'filler*' -delete; }
# code TOKEN METHOD PATH [BODY] prints the status and keeps the answer in body.
code() { curl -sS -o "$RUN_DIR/body" -w '%{http_code}' -X "$2" "$PHOENIX_SERVER$3" -H "Authorization: Bearer $1" ${4:+--data "$4"}; }
want() { assert_eq "$(code "$2" "$3" "$4" "${5:-}")" "$1" "$HOW: $3 $4"; }
force() { code "$ADMIN_TOKEN" POST '/v1/agents?force=true' "{\"name\":\"$1\",\"token\":\"$2\",\"permissions\":[{\"path\":\"**\",\"actions\":[\"read_value\"]}]}"; }
mint() { code "$READER" POST /v1/session/mint "{\"role\":\"${1:-reader}\"}" >/dev/null; jq -r '.session_token // empty' "$RUN_DIR/body"; }
# refused_start WHAT TEXT: the server stops by itself with exit 1 and says TEXT.
refused_start() {
  local rc=0
  timeout 5 "$PHOENIX_SERVER_BIN" --config "$RUN_DIR/config.json" >"$RUN_DIR/refused.log" 2>&1 || rc=$?
  assert_eq "$rc" 1 "$HOW: start with $1"
  assert_contains "$(cat "$RUN_DIR/refused.log")" "$2" "$HOW: start with $1"
}
data_sums() { (cd "$D" && sha256sum store.json acl.json grants.json role-sessions.json master.key); }

for HOW in bytes files; do
  opts=size=1m; [[ "$HOW" == bytes ]] || opts=size=8m,nr_inodes=40
  mount -t tmpfs -o "$opts" tmpfs "$D"
  "$PHOENIX_SERVER_BIN" --init "$D" >"$RUN_DIR/init.out" </dev/null
  ADMIN_TOKEN="$(token_from_init "$RUN_DIR/init.out")"; PASSWORD="$(password_from_init "$RUN_DIR/init.out")"
  PHOENIX_SERVER="http://127.0.0.1:$(free_port)"; export PHOENIX_SERVER
  python3 - "$D/config.json" "$RUN_DIR/config.json" "${PHOENIX_SERVER#http://}" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d['server']['listen'] = sys.argv[3]
d['session'] = {'enabled': True, 'ttl': '1h', 'roles': {r: {'namespaces': ['app/*'], 'actions': ['list', 'read_value'], 'bootstrap_trust': ['bearer']} for r in ('reader', 'ops')}}
d['access_requests']['approvers'] = ['approver']
json.dump(d, open(sys.argv[2], 'w'), indent=2)
PY

  # A new install starts, and starts again before its first secret.
  start_server; stop_server; start_server
  printf %s synthetic-one | phoenix_admin set app/one --value-stdin -d "synthetic" >/dev/null
  printf %s synthetic-two | phoenix_admin set vault/two --value-stdin -d "synthetic" >/dev/null
  phoenix_admin agent create reader -t "$READER" --acl 'app/*:list,read_value' >/dev/null
  phoenix_admin agent create asker -t "$ASKER" --acl 'none/*:list' >/dev/null
  phoenix_admin agent create approver -t "$APPROVER" --acl 'none/*:list' >/dev/null
  phoenix_admin agent create leaver -t synthetic-full-leaver --acl 'app/*:list' >/dev/null
  phoenix_admin keypair generate asker -o "$RUN_DIR/asker.$HOW.key" >/dev/null
  PHOENIX_TOKEN="$ASKER" "$PHOENIX" request vault/two --reason e2e --ttl 1h >"$RUN_DIR/req"
  PHOENIX_TOKEN="$APPROVER" "$PHOENIX" approve "$(awk '/^Request:/ {print $2}' "$RUN_DIR/req")" --yes >/dev/null 2>&1
  use_grant() { PHOENIX_TOKEN="$ASKER" PHOENIX_SEAL_KEY="$RUN_DIR/asker.$HOW.key" "$PHOENIX" exec --env GOT=phoenix://vault/two -- sh -c 'printf %s "$GOT"'; }
  live="$(mint)"; ended="$(mint ops)"
  [[ -n "$live" && -n "$ended" ]] || die "$HOW: no role sessions"
  stop_server

  # --- Start on the full disk: a role changed, no lock files, no audit log ---
  python3 - "$RUN_DIR/config.json" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p)); d['session']['roles']['ops']['actions'] = ['list']; json.dump(d, open(p, 'w'))
PY
  find "${D:?}" -maxdepth 1 -name '*.lock' -delete
  mv "$D/audit.log" "$RUN_DIR/audit.$HOW"
  fill "$HOW"
  before="$(data_sums)"
  start_server
  assert_contains "$(cat "$RUN_DIR/server.log")" WARNING "$HOW: the log says what could not be saved"
  want 200 "$ADMIN_TOKEN" GET /v1/secrets/app/one
  want 200 "$READER" GET /v1/secrets/app/one
  want 200 "$live" GET /v1/secrets/app/one
  want 401 "$ended" GET /v1/secrets/app/one
  assert_secret "$(use_grant)" synthetic-two "$HOW: grant"
  dashboard_login "$PHOENIX_SERVER" "$PASSWORD" "$RUN_DIR/jar" || die "$HOW: dashboard login"
  minted="$(mint)"; [[ -n "$minted" ]] || die "$HOW: no session could be minted"
  want 200 "$minted" GET /v1/secrets/app/one
  want 200 "$minted" POST /v1/session/renew '{}'
  victim="$(mint)"; victim_id="$(jq -r .session_id "$RUN_DIR/body")"

  # --- Answered with an error: nothing given ---
  want 500 "$ADMIN_TOKEN" PUT /v1/secrets/app/one '{"value":"half-done"}'
  want 500 "$ADMIN_TOKEN" PUT /v1/secrets/app/new '{"value":"half-done"}'
  want 500 "$ADMIN_TOKEN" DELETE /v1/secrets/app/one
  assert_eq "$(force late synthetic-full-late)" 500 "$HOW: new agent"
  assert_eq "$(force reader "$READER")" 500 "$HOW: same token"
  want 200 "$live" GET /v1/secrets/app/one
  assert_eq "$(force admin synthetic-full-admin)" 500 "$HOW: own token"
  assert_contains "$(cat "$RUN_DIR/body")" "your old token still works" "$HOW: own token"
  assert_eq "$(code "$READER" POST '/v1/agents?force=true' '{"name":"reader","token":"synthetic-full-eve","permissions":[]}')" 403 "$HOW: refused replacement"
  want 200 "$live" GET /v1/secrets/app/one

  # --- Taken away: gone at once, and the answer says it is not saved ---
  want 500 "$ADMIN_TOKEN" POST "/v1/sessions/$victim_id/revoke" '{}'
  assert_contains "$(cat "$RUN_DIR/body")" "saving that failed" "$HOW: session revoke"
  want 500 "$APPROVER" POST "/v1/grants/$(api_token "$ASKER" GET /v1/grants | jq -r '.grants[0].id')/revoke" '{}'
  assert_contains "$(cat "$RUN_DIR/body")" REVOKE_NOT_DURABLE "$HOW: grant revoke"
  assert_eq "$(force leaver synthetic-full-new)" 500 "$HOW: new token"
  assert_contains "$(cat "$RUN_DIR/body")" "the old token no longer works and the new one is not in force" "$HOW: new token"

  # check_after WHEN: what holds on the full disk, once saved and after a restart.
  check_after() {
    local tok
    assert_secret "$(phoenix_admin get app/one)" synthetic-one "$HOW, $1: the secret"
    assert_eq "$(code "$ADMIN_TOKEN" GET /v1/secrets/app/new)" 404 "$HOW, $1: a new secret that failed"
    for tok in late admin eve leaver new; do
      assert_eq "$(code "synthetic-full-$tok" GET /v1/whoami)" 401 "$HOW, $1: the $tok token"
      want 200 "$ADMIN_TOKEN" GET /v1/whoami   # or the login lockout would count these
    done
    assert_eq "$(code "$READER" GET /v1/secrets/vault/two)" 403 "$HOW, $1: wider permissions"
    assert_eq "$(code "$live" GET /v1/secrets/app/one)" 200 "$HOW, $1: live session"
    assert_eq "$(code "$minted" GET /v1/secrets/app/one)" 200 "$HOW, $1: session minted on the full disk"
    assert_eq "$(code "$victim" GET /v1/secrets/app/one) $(jq -r .code "$RUN_DIR/body")" "401 SESSION_REVOKED" "$HOW, $1: revoked session"
    assert_eq "$(code "$ended" GET /v1/secrets/app/one)" 401 "$HOW, $1: ended session"
    if use_grant >"$RUN_DIR/out" 2>&1; then die "$HOW, $1: the revoked grant still reads"; fi
  }
  check_after "on the full disk"
  assert_eq "$(data_sums)" "$before" "$HOW: a data file changed on the full disk"

  # --- Room again: saved by itself (the slowest retry is every minute) ---
  make_room
  saved() {
    jq -e --arg id "$victim_id" 'any(.sessions[]; .session_id == $id and .revoked)' "$D/role-sessions.json" >/dev/null &&
      jq -e 'any(.grants[]; (.revoked_by // "") != "")' "$D/grants.json" >/dev/null &&
      jq -e '.agents.leaver.token_hash == ""' "$D/acl.json" >/dev/null
  }
  # Once is enough to see the sessions retry; a mint saves them too.
  [[ "$HOW" == bytes ]] || mint >/dev/null
  for _ in $(seq 1 80); do ! saved || break; sleep 1; done
  saved || die "$HOW: not saved by itself"
  check_after "with room again"
  stop_server; start_server
  check_after "after a restart"
  [[ -s "$D/audit.log" ]] || die "$HOW: the audit log did not start again"
  assert_eq "$(force leaver synthetic-full-new)" 200 "$HOW: run again"
  want 200 synthetic-full-new GET /v1/secrets/app/one
  stop_server
  ok "full disk ($HOW): starts, reads, gives nothing, saves later"

  # --- Files that are gone or wrong, with and without room ---
  for full in no yes; do
    for f in store.json acl.json; do
      mv "$D/$f" "$RUN_DIR/$f"
      [[ "$full" == no ]] || fill "$HOW"
      refused_start "no $f" "$D/$f is not there"
      [[ ! -e "$D/$f" ]] || die "$HOW: a refused start made $f"
      make_room; mv "$RUN_DIR/$f" "$D/$f"
    done
    cp "$D/master.key" "$RUN_DIR/master.key"
    head -c 32 /dev/urandom | base64 >"$D/master.key"
    before="$(data_sums)"
    [[ "$full" == no ]] || fill "$HOW"
    refused_start "a key that opens nothing" "the master key does not open"
    assert_eq "$(data_sums)" "$before" "$HOW: a refused start changed a file"
    make_room; cp "$RUN_DIR/master.key" "$D/master.key"
  done
  start_server; assert_secret "$(phoenix_admin get app/one)" synthetic-one "$HOW: everything back"; stop_server
  umount "$D"
  ok "full disk ($HOW): a wrong key and missing files are refused"
done
ok "Scenario 25 PASS"
