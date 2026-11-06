#!/bin/sh
# Prepares one machine for Phoenix SSH certificates. Run as root, once per machine.
# See docs/ssh-certificates.md.
#
#   ssh-node-setup.sh install <machine-name> <phoenix-url> <phoenix-tls-ca-file>
#   ssh-node-setup.sh remove
#
# install is safe to run again. It makes an "agent" user that nobody can log in as
# without a certificate from Phoenix for this machine, whose approval Phoenix says is
# still active, and that has recorded passwordless sudo. Set KEEP_AUTHORIZED_KEYS=1 to leave the user's existing
# authorized_keys working alongside certificates, for a machine being moved over.
set -eu

CA_PUB=/etc/ssh/phoenix-user-ca.pub
TLS_CA=/etc/ssh/phoenix-tls-ca.crt
SSHD_CONF=/etc/ssh/sshd_config.d/50-phoenix-agent.conf
SUDOERS=/etc/sudoers.d/agent-phoenix
ENV_FILE=/etc/phoenix-ssh-window.env
WINDOW_BIN=/usr/local/sbin/phoenix-ssh-window
AUTHZ_BIN=/usr/local/sbin/phoenix-ssh-authz
UNIT=/etc/systemd/system/phoenix-ssh-window

# The SSH service's name on this distro.
sshd_service() {
  if systemctl is-active --quiet sshd; then echo sshd; else echo ssh; fi
}

# Makes sure the service is up. sshd -t needs that too: /run/sshd only exists while
# it runs. On Debian 12 with ssh.socket active, a reload kills sshd (it can't re-bind
# the socket's port) and the service stays down until something starts it again.
# Existing sessions survive either way.
ensure_sshd() {
  service=$(sshd_service)
  tries=0
  until systemctl is-active --quiet "$service"; do
    systemctl start "$service" || true
    tries=$((tries + 1))
    if [ "$tries" -ge 10 ]; then
      echo "the $service service will not start: check it now" >&2
      return 1
    fi
    sleep 1
  done
}

reload_sshd() {
  systemctl reload "$(sshd_service)" || true
  sleep 1
  ensure_sshd
}

install_all() {
  machine=$1 url=$2 tls_ca=$3
  case $machine in *[!a-z0-9-]* | "" | -*) echo "bad machine name: $machine" >&2; exit 2 ;; esac
  case $url in https://*) ;; *) echo "phoenix url must be https://" >&2; exit 2 ;; esac

  # Check the server first, so a wrong URL changes nothing on this machine.
  ca_json=$(curl -fsS --max-time 10 --cacert "$tls_ca" "$url/v1/ssh/ca")
  ca_key=$(printf '%s' "$ca_json" | sed -n 's/.*"public_key":"\(ssh-ed25519 [A-Za-z0-9+/=]*\).*/\1/p')
  [ -n "$ca_key" ] || { echo "could not read the CA key from $url" >&2; exit 1; }

  ensure_sshd
  id agent >/dev/null 2>&1 || useradd --create-home --shell /bin/bash agent
  passwd --lock agent >/dev/null

  [ "$tls_ca" = "$TLS_CA" ] || install -m 0644 -o root -g root "$tls_ca" "$TLS_CA"
  printf '%s\n' "$ca_key" > "$CA_PUB.new"; chmod 0644 "$CA_PUB.new"; mv "$CA_PUB.new" "$CA_PUB"
  keep_keys=${KEEP_AUTHORIZED_KEYS:-0}
  printf 'PHOENIX_URL=%s\nPHOENIX_MACHINE=%s\nKEEP_AUTHORIZED_KEYS=%s\n' "$url" "$machine" "$keep_keys" > "$ENV_FILE"
  chmod 0644 "$ENV_FILE"

  # sshd runs this at every login. It prints this machine's name only while the
  # certificate's grant is still active, so a revoke stops a certificate that has
  # not expired yet, and a pass for another machine never matches. Printing nothing
  # refuses the login, so if Phoenix can't be reached nobody new gets in.
  cat > "$AUTHZ_BIN" <<'AUTHZ'
#!/bin/sh
. /etc/phoenix-ssh-window.env
grant=$(printf '%s' "$1" | sed -n 's/^grant=\(gnt_[0-9a-f]\{32\}\),.*/\1/p')
[ -n "$grant" ] || exit 0
answer=$(curl -fsS --max-time 5 --cacert /etc/ssh/phoenix-tls-ca.crt "$PHOENIX_URL/v1/ssh/window/$PHOENIX_MACHINE/$grant") || exit 0
case $answer in
  *'"open":true'*) printf '%s\n' "$PHOENIX_MACHINE" ;;
esac
AUTHZ
  chmod 0755 "$AUTHZ_BIN"

  cat > "$WINDOW_BIN" <<'WINDOW'
#!/bin/sh
# Ends each agent SSH session whose own approval is over, so a revoke reaches a
# session that is already open. Only SSH sessions: user services the agent account
# runs (Cerberus's sidecar on xidax) are left alone.
#
# A session's grant comes from sshd's log line for that session's leader process.
# With certificates only, a session with no grant to check should not exist, so it
# ends too. It asks Phoenix only while a session exists. If Phoenix can't be reached
# it does nothing: new logins are already refused, and it asks again next run.
. /etc/phoenix-ssh-window.env
for id in $(loginctl list-sessions --no-legend | awk '$3 == "agent" { print $1 }'); do
  [ "$(loginctl show-session "$id" -p Service --value)" = sshd ] || continue
  leader=$(loginctl show-session "$id" -p Leader --value)
  grant=$(journalctl -q -o cat _PID="$leader" | sed -n 's/.* ID grant=\(gnt_[0-9a-f]\{32\}\),.*/\1/p' | tail -n 1)
  if [ -z "$grant" ]; then
    [ "$KEEP_AUTHORIZED_KEYS" = 1 ] && continue
    echo "no approval found: ending session $id"
    loginctl terminate-session "$id"
    continue
  fi
  answer=$(curl -fsS --max-time 5 --cacert /etc/ssh/phoenix-tls-ca.crt "$PHOENIX_URL/v1/ssh/window/$PHOENIX_MACHINE/$grant") || continue
  case $answer in
    *'"open":false'*)
      echo "approval $grant over: ending session $id"
      loginctl terminate-session "$id"
      ;;
  esac
done
WINDOW
  chmod 0755 "$WINDOW_BIN"
  cat > "$UNIT.service" <<SERVICE
[Unit]
Description=End agent SSH sessions when their Phoenix approval is over

[Service]
Type=oneshot
ExecStart=$WINDOW_BIN
# It runs every 30 seconds; only warnings and its own stdout are worth a disk write.
LogLevelMax=notice
SERVICE
  cat > "$UNIT.timer" <<TIMER
[Unit]
Description=Check the Phoenix approval of agent SSH sessions

[Timer]
OnBootSec=1min
OnUnitActiveSec=30s
AccuracySec=5s

[Install]
WantedBy=timers.target
TIMER
  systemctl daemon-reload
  systemctl enable --now phoenix-ssh-window.timer >/dev/null

  # Recorded so a session can be replayed with sudoreplay after the fact. A machine
  # that already gives the agent user sudo (xidax) keeps its own rule.
  if ! sudo -n -l -U agent 2>/dev/null | grep -q 'NOPASSWD: ALL'; then
    tmp=$(mktemp)
    cat > "$tmp" <<SUDO
Defaults:agent use_pty, log_output, iolog_dir=/var/log/sudo-io, iolog_file=%{user}/%{seq}, logfile=/var/log/sudo-agent.log, log_year, log_host
agent ALL=(ALL:ALL) NOPASSWD: ALL
SUDO
    visudo -cf "$tmp" >/dev/null
    install -m 0440 -o root -g root "$tmp" "$SUDOERS"
    rm -f "$tmp"
  fi

  # Last on purpose: login turns on only once everything that limits it is running.
  keys_line="    AuthorizedKeysFile none"
  [ "$keep_keys" = 1 ] && keys_line="    # AuthorizedKeysFile none (KEEP_AUTHORIZED_KEYS=1)"
  had_conf=0
  [ -e "$SSHD_CONF" ] && { had_conf=1; cp -p "$SSHD_CONF" "$SSHD_CONF.prev"; }
  cat > "$SSHD_CONF" <<CONF
# Managed by Phoenix scripts/ssh-node-setup.sh. See docs/ssh-certificates.md.
Match User agent
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AuthenticationMethods publickey
$keys_line
    TrustedUserCAKeys $CA_PUB
    AuthorizedPrincipalsCommand $AUTHZ_BIN %i
    AuthorizedPrincipalsCommandUser nobody
    X11Forwarding no
    AllowTcpForwarding no
    AllowAgentForwarding no
CONF
  chmod 0644 "$SSHD_CONF"
  if ! sshd -t; then
    if [ "$had_conf" = 1 ]; then mv "$SSHD_CONF.prev" "$SSHD_CONF"; else rm -f "$SSHD_CONF"; fi
    echo "sshd rejected the new config; put the old one back" >&2
    exit 1
  fi
  rm -f "$SSHD_CONF.prev"
  reload_sshd
  echo "ready: $machine"
}

# Never stops partway: a problem with sshd is reported at the end, with everything
# else already removed, so a machine can't be left half set up.
remove_all() {
  status=0
  # Login off first. The timer stops only after that, so nothing is left unlimited.
  rm -f "$SSHD_CONF"
  reload_sshd || status=1
  systemctl disable --now phoenix-ssh-window.timer 2>/dev/null || true
  rm -f "$UNIT.service" "$UNIT.timer" "$WINDOW_BIN" "$AUTHZ_BIN" "$ENV_FILE" "$SUDOERS" "$CA_PUB" "$TLS_CA"
  systemctl daemon-reload
  [ "$status" = 0 ] && echo "removed. The agent user and its files are left in place."
  return "$status"
}

case ${1:-} in
  install) [ $# -eq 4 ] || { echo "usage: $0 install <machine-name> <phoenix-url> <phoenix-tls-ca-file>" >&2; exit 2; }; install_all "$2" "$3" "$4" ;;
  remove) remove_all ;;
  *) echo "usage: $0 install <machine-name> <phoenix-url> <phoenix-tls-ca-file> | remove" >&2; exit 2 ;;
esac
