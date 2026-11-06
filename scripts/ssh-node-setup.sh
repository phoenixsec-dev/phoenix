#!/bin/sh
# Prepares one machine for Phoenix SSH certificates. Run as root, once per machine.
# See docs/ssh-certificates.md.
#
#   ssh-node-setup.sh install <machine-name> <phoenix-url> <phoenix-tls-ca-file>
#   ssh-node-setup.sh remove
#
# install is safe to run again. It makes an "agent" user that nobody can log in as
# without a certificate from Phoenix for this machine's name, and that has recorded
# passwordless sudo. Set KEEP_AUTHORIZED_KEYS=1 to leave the user's existing
# authorized_keys working alongside certificates, for a machine being moved over.
set -eu

CA_PUB=/etc/ssh/phoenix-user-ca.pub
PRINCIPALS=/etc/ssh/phoenix-principals
TLS_CA=/etc/ssh/phoenix-tls-ca.crt
SSHD_CONF=/etc/ssh/sshd_config.d/50-phoenix-agent.conf
SUDOERS=/etc/sudoers.d/agent-phoenix
ENV_FILE=/etc/phoenix-ssh-window.env
WINDOW_BIN=/usr/local/sbin/phoenix-ssh-window
UNIT=/etc/systemd/system/phoenix-ssh-window

# Reloads whichever name this distro gives the SSH service. A reload keeps
# existing connections, so a bad change can't lock anyone out of a running session.
reload_sshd() {
  if systemctl is-active --quiet sshd; then
    systemctl reload sshd
  else
    systemctl reload ssh
  fi
}

install_all() {
  machine=$1 url=$2 tls_ca=$3
  case $machine in *[!a-z0-9-]* | "" | -*) echo "bad machine name: $machine" >&2; exit 2 ;; esac
  case $url in https://*) ;; *) echo "phoenix url must be https://" >&2; exit 2 ;; esac

  # Check the server first, so a wrong URL changes nothing on this machine.
  ca_json=$(curl -fsS --max-time 10 --cacert "$tls_ca" "$url/v1/ssh/ca")
  ca_key=$(printf '%s' "$ca_json" | sed -n 's/.*"public_key":"\(ssh-ed25519 [A-Za-z0-9+/=]*\).*/\1/p')
  [ -n "$ca_key" ] || { echo "could not read the CA key from $url" >&2; exit 1; }

  id agent >/dev/null 2>&1 || useradd --create-home --shell /bin/bash agent
  passwd --lock agent >/dev/null

  [ "$tls_ca" = "$TLS_CA" ] || install -m 0644 -o root -g root "$tls_ca" "$TLS_CA"
  printf '%s\n' "$ca_key" > "$CA_PUB.new"; chmod 0644 "$CA_PUB.new"; mv "$CA_PUB.new" "$CA_PUB"
  # A certificate works here only if it names this machine. That is what stops a
  # pass approved for one machine from opening another.
  printf '%s\n' "$machine" > "$PRINCIPALS.new"; chmod 0644 "$PRINCIPALS.new"; mv "$PRINCIPALS.new" "$PRINCIPALS"

  keys_line="    AuthorizedKeysFile none"
  [ "${KEEP_AUTHORIZED_KEYS:-0}" = 1 ] && keys_line="    # AuthorizedKeysFile none (KEEP_AUTHORIZED_KEYS=1)"
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
    AuthorizedPrincipalsFile $PRINCIPALS
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

  printf 'PHOENIX_URL=%s\nPHOENIX_MACHINE=%s\n' "$url" "$machine" > "$ENV_FILE"
  chmod 0644 "$ENV_FILE"
  cat > "$WINDOW_BIN" <<'WINDOW'
#!/bin/sh
# Ends the agent user's SSH sessions once Phoenix says the approval is over, so
# revoke takes effect on a session that is already open. Only SSH sessions: user
# services the agent account runs (Cerberus's sidecar on xidax) are left alone.
# It asks Phoenix only while a session exists. If Phoenix can't be reached it does
# nothing, because the certificate's own expiry still blocks new logins.
. /etc/phoenix-ssh-window.env
sessions=
for id in $(loginctl list-sessions --no-legend | awk '$3 == "agent" { print $1 }'); do
  [ "$(loginctl show-session "$id" -p Service --value)" = sshd ] && sessions="$sessions $id"
done
[ -n "$sessions" ] || exit 0
answer=$(curl -fsS --max-time 5 --cacert /etc/ssh/phoenix-tls-ca.crt "$PHOENIX_URL/v1/ssh/window/$PHOENIX_MACHINE") || exit 0
case $answer in
  *'"open":false'*)
    for id in $sessions; do
      echo "approval over: ending session $id"
      loginctl terminate-session "$id"
    done
    ;;
esac
WINDOW
  chmod 0755 "$WINDOW_BIN"
  cat > "$UNIT.service" <<SERVICE
[Unit]
Description=End agent SSH sessions when the Phoenix approval is over

[Service]
Type=oneshot
ExecStart=$WINDOW_BIN
# It runs every 30 seconds; only warnings and its own stdout are worth a disk write.
LogLevelMax=notice
SERVICE
  cat > "$UNIT.timer" <<TIMER
[Unit]
Description=Check the Phoenix approval for agent SSH sessions

[Timer]
OnBootSec=1min
OnUnitActiveSec=30s
AccuracySec=5s

[Install]
WantedBy=timers.target
TIMER
  systemctl daemon-reload
  systemctl enable --now phoenix-ssh-window.timer >/dev/null
  echo "ready: $machine"
}

remove_all() {
  systemctl disable --now phoenix-ssh-window.timer 2>/dev/null || true
  rm -f "$UNIT.service" "$UNIT.timer" "$WINDOW_BIN" "$ENV_FILE" "$SUDOERS" "$SSHD_CONF" "$CA_PUB" "$PRINCIPALS" "$TLS_CA"
  systemctl daemon-reload
  sshd -t
  reload_sshd
  echo "removed. The agent user and its files are left in place."
}

case ${1:-} in
  install) [ $# -eq 4 ] || { echo "usage: $0 install <machine-name> <phoenix-url> <phoenix-tls-ca-file>" >&2; exit 2; }; install_all "$2" "$3" "$4" ;;
  remove) remove_all ;;
  *) echo "usage: $0 install <machine-name> <phoenix-url> <phoenix-tls-ca-file> | remove" >&2; exit 2 ;;
esac
