#!/usr/bin/env bash
# Upgrade from the previous release and back, on the same files:
#   1. the previous release fills a data directory: secrets, agents, grants, a
#      role session, a dashboard login
#   2. this build starts on it: nothing is lost, every credential still works
#   3. this build adds data of its own
#   4. the previous release starts on the result: it must either work, with all
#      of it, or refuse to start and leave every file as it was
#   5. this build starts again: still nothing lost
# The previous release is built from its published tag: the newest final
# version tag that is not newer than internal/version and is not this very
# tree. E2E_PREV_REF=<tag or commit> picks another.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 23 upgrade-from-previous-release
for cmd in git tar curl python3 jq sha256sum timeout cmp; do require_cmd "$cmd"; done

# previous_release prints the tag to upgrade from; nothing if there is none.
previous_release() {
  local current tag
  current="v$(sed -n 's/^var Version = "\(.*\)"$/\1/p' "$REPO_ROOT/internal/version/version.go")"
  for tag in $(git -C "$REPO_ROOT" tag --list 'v[0-9]*' --sort=-v:refname); do
    [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
    [[ "$(printf '%s\n%s\n' "$tag" "$current" | sort -V | tail -1)" == "$current" ]] || continue
    [[ "$(git -C "$REPO_ROOT" rev-parse "$tag^{tree}")" != "$(git -C "$REPO_ROOT" rev-parse 'HEAD^{tree}')" ]] || continue
    echo "$tag"; return
  done
}
PREV="${E2E_PREV_REF:-$(previous_release)}"
[[ -n "$PREV" ]] || skip "no release tag in this clone (a shallow clone has none: git fetch --tags)"
git -C "$REPO_ROOT" rev-parse -q --verify "$PREV^{commit}" >/dev/null || die "unknown git ref: $PREV"
log "previous release: $PREV"

build_current
NEW_PHOENIX="$PHOENIX"; NEW_SERVER="$PHOENIX_SERVER_BIN"
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/phoenix-e2e-s23.XXXXXX")"; SERVER_PID=""; trap cleanup_scenario EXIT INT TERM
mkdir "$RUN_DIR/old-src" "$RUN_DIR/old-bin" "$RUN_DIR/state"
git -C "$REPO_ROOT" archive "$PREV" | tar -x -C "$RUN_DIR/old-src"
(cd "$RUN_DIR/old-src" && "$GO_BIN" build -o "$RUN_DIR/old-bin/" ./cmd/...)
use_old() { PHOENIX="$RUN_DIR/old-bin/phoenix"; PHOENIX_SERVER_BIN="$RUN_DIR/old-bin/phoenix-server"; }
use_new() { PHOENIX="$NEW_PHOENIX"; PHOENIX_SERVER_BIN="$NEW_SERVER"; }
PREV_VERSION="v$("$RUN_DIR/old-bin/phoenix" version | awk '{print $2}')"

# The data directory belongs to the previous release: init it with its binary.
use_old
"$PHOENIX_SERVER_BIN" --init "$RUN_DIR/state" >"$RUN_DIR/init.out" </dev/null
ADMIN_TOKEN="$(token_from_init "$RUN_DIR/init.out")"; [[ -n "$ADMIN_TOKEN" ]] || die "old init token missing"
port="$(free_port)"
python3 - "$RUN_DIR/state" "$port" <<'PY'
import json, sys
state, port = sys.argv[1:]
p = state + '/config.json'; d = json.load(open(p))
d['server']['listen'] = '127.0.0.1:' + port
d['policy'] = {'path': state + '/policy.json'}
d['session'] = {'enabled': True, 'ttl': '1h', 'roles': {'reader': {'namespaces': ['app/*'], 'actions': ['list', 'read_value'], 'bootstrap_trust': ['bearer']}}}
d['access_requests']['approvers'] = ['approver']
# bcrypt hash of e2e-dash-password
d['dashboard'] = {'enabled': True, 'password_hash': '$2a$10$HLVxwM4wKNkthQOq6HXfuOj6tC68h.gfwNjx2MSHkqPXkgvrMpK3a'}
json.dump(d, open(p, 'w'), indent=2)
json.dump({'attestation': {}}, open(state + '/policy.json', 'w'))
PY
PHOENIX_SERVER="http://127.0.0.1:$port"; export PHOENIX_SERVER
# Helpers expect the config at RUN_DIR/config.json.
ln -s "$RUN_DIR/state/config.json" "$RUN_DIR/config.json"

READER=synthetic-upgrade-reader; APPROVER=synthetic-upgrade-approver; ASKER=synthetic-upgrade-asker; GONE=synthetic-upgrade-gone
agent() { local tok="$1"; shift; PHOENIX_TOKEN="$tok" "$PHOENIX" "$@"; }
# ask_exec PATH: the asker uses a granted secret the way an agent does (sealed).
ask_exec() { PHOENIX_TOKEN="$ASKER" PHOENIX_SEAL_KEY="$RUN_DIR/asker.seal.key" "$PHOENIX" exec --env GOT="phoenix://$1" -- sh -c 'printf %s "$GOT"'; }
# request PATH: files a request as the asker and prints its id.
request() { agent "$ASKER" request "$1" --reason "e2e upgrade" --ttl 1h | awk '/^Request:/ {print $2}'; }
approve() { agent "$APPROVER" approve "$1" --yes >/dev/null 2>&1; }
grant_of() { api_token "$APPROVER" GET "/v1/access-requests/$1" | jq -r .grant_id; }
mint() { api_token "$READER" POST /v1/session/mint '{"role":"reader"}' | jq -r .session_token; }
# http_code TOKEN PATH prints the status of a read, keeping the body in RUN_DIR/body.
http_code() { curl -sS -o "$RUN_DIR/body" -w '%{http_code}' "$PHOENIX_SERVER$2" -H "Authorization: Bearer $1"; }
# keep_audit / check_audit WHO: every byte of the audit log that keep_audit saw
# is still there; later lines may follow.
keep_audit() { cp "$RUN_DIR/state/audit.log" "$RUN_DIR/audit.kept"; }
check_audit() { cmp -s -n "$(stat -c %s "$RUN_DIR/audit.kept")" "$RUN_DIR/audit.kept" "$RUN_DIR/state/audit.log" || die "$1: audit history changed"; }

# --- 1. Fill it with the previous release ---
start_server
put() { printf '%s' "$2" | phoenix_admin set "$1" --value-stdin "${@:3}" >/dev/null; }
put app/one synthetic-one -d "first synthetic secret" --tags "blue,green"
put app/two synthetic-two-v1 -d "changed later"
put app/two synthetic-two-v2 -d "changed later"
put app/elsewhere synthetic-elsewhere -d "policy blocks it here"
# Only now: the rule also stops the admin from writing the secret.
stop_server
echo '{"attestation":{"app/elsewhere":{"source_ip":["192.0.2.1"]}}}' >"$RUN_DIR/state/policy.json"
start_server
put app/deleted synthetic-deleted -d "deleted again"
phoenix_admin delete app/deleted >/dev/null
multiline=$'line one\nline two \xe2\x9c\x93'
put app/multi "$multiline" -d "more than one line"
for n in granted revoked pending; do put "vault/$n" "synthetic-$n" -d "synthetic $n"; done
phoenix_admin agent create reader -t "$READER" --acl 'app/*:list,read_value' >/dev/null
phoenix_admin agent create approver -t "$APPROVER" --acl 'approver-none/*:list' >/dev/null
phoenix_admin agent create asker -t "$ASKER" --acl 'asker-none/*:list' >/dev/null
phoenix_admin agent create gone -t "$GONE" --acl 'app/*:read_value' >/dev/null
phoenix_admin agent delete gone >/dev/null
phoenix_admin keypair generate asker -o "$RUN_DIR/asker.seal.key" >/dev/null
r_granted="$(request vault/granted)"; approve "$r_granted"
r_revoked="$(request vault/revoked)"; approve "$r_revoked"
agent "$APPROVER" grants revoke "$(grant_of "$r_revoked")" >/dev/null
r_pending="$(request vault/pending)"
assert_secret "$(ask_exec vault/granted)" synthetic-granted "grant works on the previous release"
old_session="$(mint)"
assert_eq "$(http_code "$old_session" /v1/secrets/app/one)" 200 "session works on the previous release"
secrets_before="$(phoenix_admin list --names)"
meta_before="$(api_admin GET /v1/metadata/app/one | jq -S .)"
agents_before="$(phoenix_admin agent list)"
stop_server
keep_audit
cp -a "$RUN_DIR/state" "$RUN_DIR/state.before"

# check_old_data WHO: everything step 1 made, except the session, checked
# against whatever server is running.
check_old_data() {
  local who="$1" line
  assert_secret "$(phoenix_admin get app/one)" synthetic-one "$who: admin token and first secret"
  assert_secret "$(phoenix_admin get app/two)" synthetic-two-v2 "$who: updated secret"
  assert_secret "$(phoenix_admin get app/multi)" "$multiline" "$who: multi-line secret"
  assert_eq "$(http_code "$ADMIN_TOKEN" /v1/secrets/app/deleted)" 404 "$who: deleted secret stays deleted"
  # Every field the previous release showed is there unchanged; new ones may be added.
  [[ "$(api_admin GET /v1/metadata/app/one | jq --argjson old "$meta_before" '. + $old == .')" == true ]] || die "$who: description, tags, dates or authors changed"
  # Every name from step 1 is still listed; later steps only add some.
  phoenix_admin list --names >"$RUN_DIR/names"
  while read -r line; do grep -qxF -- "$line" "$RUN_DIR/names" || die "$who: secret $line is gone"; done <<<"$secrets_before"
  phoenix_admin agent list >"$RUN_DIR/agents"
  while read -r line; do grep -qF -- "$line" "$RUN_DIR/agents" || die "$who: agent line lost: $line"; done <<<"$agents_before"
  assert_secret "$(agent "$READER" get app/one)" synthetic-one "$who: reader token"
  assert_eq "$(http_code "$READER" /v1/secrets/vault/granted)" 403 "$who: reader stays out of vault/"
  assert_eq "$(http_code "$READER" /v1/secrets/app/elsewhere)" 403 "$who: policy still applies"
  assert_eq "$(http_code "$GONE" /v1/secrets/app/one)" 401 "$who: deleted agent's token stays dead"
  assert_secret "$(ask_exec vault/granted)" synthetic-granted "$who: active grant and seal key"
  if ask_exec vault/revoked >"$RUN_DIR/revoked" 2>&1; then die "$who: revoked grant came back"; fi
  assert_contains "$(cat "$RUN_DIR/revoked")" GRANT_REVOKED "$who: revoked grant"
  dashboard_login "$PHOENIX_SERVER" e2e-dash-password "$(mktemp "$RUN_DIR/jar.XXXXXX")" || die "$who: dashboard password"
  check_audit "$who"
}
# Sessions saved before v0.23.1 end once, on purpose (see its release notes).
# From that release on every session must survive every step here. A release
# that ends sessions on purpose has to change this line, and say so.
SESSIONS_SURVIVE=0
if [[ "$(printf '%s\nv0.23.1\n' "$PREV_VERSION" | sort -V | head -1)" == v0.23.1 ]]; then SESSIONS_SURVIVE=1; fi
# check_session TOKEN WHO: the exact session works. Before v0.23.1 it may be
# refused instead, as a session the client replaces by itself, and that
# replacement must work.
check_session() {
  local code home; code="$(http_code "$1" /v1/secrets/app/one)"
  if [[ "$code" != 200 ]]; then
    [[ "$SESSIONS_SURVIVE" -eq 0 ]] || die "$2: a role session was lost ($code)"
    assert_eq "$code $(jq -r .code "$RUN_DIR/body")" "401 SESSION_INVALID" "$2: session"
    log "$2: ended the role session; checking that clients mint a new one"
  fi
  home="$(mktemp -d "$RUN_DIR/home.XXXXXX")"
  mkdir "$home/.phoenix"
  python3 - "$home/.phoenix/token-cache.json" "$PHOENIX_SERVER" "$1" <<'PY'
import hashlib,json,sys
key='session:reader@'+hashlib.sha256(sys.argv[2].encode()).hexdigest()[:8]
json.dump({key:{'token':sys.argv[3],'agent':'session:reader','expires_at':'2999-01-01T00:00:00Z'}},open(sys.argv[1],'w'))
PY
  assert_secret "$(HOME="$home" PHOENIX_TOKEN="$READER" PHOENIX_ROLE=reader "$PHOENIX" get app/one 2>"$RUN_DIR/remint.err")" synthetic-one "$2: role session through the CLI"
}

# --- 2. This build on the same files ---
use_new
assert_contains "$("$NEW_SERVER" --check-config --config "$RUN_DIR/config.json")" "config OK" "the previous release's config must pass --check-config"
start_server
check_old_data "this build"
check_session "$old_session" "this build"
[[ "$(stat -c %s "$RUN_DIR/state/audit.log")" -gt "$(stat -c %s "$RUN_DIR/audit.kept")" ]] || die "nothing was added to the audit log"
approve "$r_pending" || die "a request left waiting by the previous release could not be approved"
assert_secret "$(ask_exec vault/pending)" synthetic-pending "request answered after the upgrade"
ok "upgrade from $PREV: nothing lost, every credential works"

# --- 3. Data this build makes ---
LATE=synthetic-upgrade-late
put app/late synthetic-late -d "made after the upgrade"
phoenix_admin agent create late -t "$LATE" --acl 'app/*:list,read_value' >/dev/null
new_session="$(mint)"
stop_server
keep_audit

# check_new_data WHO: step 3's data (and the grant approved in step 2).
check_new_data() {
  assert_secret "$(agent "$LATE" get app/late)" synthetic-late "$1: agent and secret made after the upgrade"
  assert_secret "$(ask_exec vault/pending)" synthetic-pending "$1: grant approved after the upgrade"
}
# Every data file with its checksum, except the audit log: check_audit covers
# it, and even a refused start may add a line.
fingerprint() { (cd "$RUN_DIR/state" && find . -type f ! -name 'audit.log*' -exec sha256sum {} + | LC_ALL=C sort); }

# --- 4. The previous release on the new files ---
use_old
before="$(fingerprint)"
# try_start LOG: starts the server for 3 seconds; exit 124 means it ran.
try_start() { timeout 3 "$PHOENIX_SERVER_BIN" --config "$RUN_DIR/config.json" >"$1" 2>&1; }
rc=0; try_start "$RUN_DIR/rollback.log" || rc=$?
if [[ "$rc" -eq 124 ]]; then
  # It starts (the timeout stopped it), so everything must be there.
  start_server
  check_old_data "$PREV on the new files"
  check_new_data "$PREV on the new files"
  check_session "$old_session" "$PREV on the new files"
  check_session "$new_session" "$PREV on the new files"
  put app/rolled-back synthetic-rolled-back -d "written by the previous release"
  stop_server
  check_audit "$PREV on the new files"
  rolled_back=1
  ok "rolling back to $PREV works"
else
  # A clean refusal is exit 1 with a message about loading its files. A crash, a
  # taken port or a command that never ran is not one.
  assert_eq "$rc" 1 "$PREV exit code on the new files"
  tail -1 "$RUN_DIR/rollback.log" | grep -qE '^[0-9/]+ [0-9:]+ (loading|initializing|opening|invalid config)' || { cat "$RUN_DIR/rollback.log" >&2; die "$PREV stopped on the new files without saying which file it cannot load"; }
  assert_eq "$(fingerprint)" "$before" "$PREV refused the new files but changed them"
  check_audit "$PREV refusing the new files"
  # It must be the new data it refuses: the very same command still starts on
  # the files as they were before the upgrade.
  mv "$RUN_DIR/state" "$RUN_DIR/state.after"; mv "$RUN_DIR/state.before" "$RUN_DIR/state"
  rc=0; try_start "$RUN_DIR/control.log" || rc=$?
  mv "$RUN_DIR/state" "$RUN_DIR/state.before"; mv "$RUN_DIR/state.after" "$RUN_DIR/state"
  assert_eq "$rc" 124 "$PREV must still start on its own files, or the refusal is not about the data"
  rolled_back=0
  ok "$PREV refuses the new files and leaves them alone: $(tail -1 "$RUN_DIR/rollback.log")"
fi

keep_audit   # whatever that start added must survive the next one

# --- 5. This build again ---
use_new
start_server
check_old_data "this build again"
check_new_data "this build again"
check_session "$old_session" "this build again"
# After a refused rollback nothing touched this build's own session.
[[ "$rolled_back" -eq 1 ]] || SESSIONS_SURVIVE=1
check_session "$new_session" "this build again"
[[ "$rolled_back" -eq 0 ]] || assert_secret "$(phoenix_admin get app/rolled-back)" synthetic-rolled-back "secret written during the rollback"
ok "Scenario 23 PASS"
