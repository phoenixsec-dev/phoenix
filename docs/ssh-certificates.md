# SSH Certificates

An agent needs to log in to a machine and run something as root. Instead of
giving it a key that works forever, a human approves a request and Phoenix signs
a short-lived certificate: a login pass with an expiry built in.

- **The signing key never leaves the server.** It is a file next to the ACL
  (`ssh_ca.key`), not a secret. No API returns it and no ACL rule can reach it.
- **The agent holds nothing long-lived.** `phoenix ssh` makes a throwaway key,
  gets it signed, and deletes both when ssh exits.
- **A broad ACL does not help.** An agent with `*` access to every secret still
  needs an approval to log in. The grant is the only thing that counts.
- **A pass works in one place.** It names one machine, works only from the IP
  that asked, and ends when the grant ends.
- **A revoke beats a pass that is still in date.** The machine asks Phoenix at
  every login whether that pass's grant still stands.

## The flow

```bash
# Agent: asks if there is no approval yet, waits, then logs in and runs the command
phoenix ssh arch-omen --reason "install the firewall rules" --ttl 15m -- sudo -n ./install.sh

# Human: dashboard -> Approvals -> approve. The card says "root login on this machine".

# Agent: more commands in the same window need no new approval
phoenix ssh arch-omen -- sudo -n systemctl status something

# Human: take it back. New logins stop at once, even with a pass the agent kept.
# Open sessions under that approval end within about 30 seconds.
#   dashboard -> Grants -> Revoke
```

It uses the [request-use grant flow](access-requests.md): the same request
limits, TTL choices, audit log and notifications. The agent must use its own
identity (bearer token, not a `phxs_` session). A login is a grant with its own
action, `ssh_login`, on the path `ssh/<machine>`. Because the action is different,
a grant to read a secret at that path can never log in, and a login grant can never
read a secret. `deny_paths`, `require_sealed` and `ALREADY_ALLOWED` do not apply to
logins, and they are always tied to the IP that asked. `deny_paths: ["*"]` is a valid
way to turn on logins while keeping every secret out of the request flow. One machine
per request.

The command goes to ssh as is, so quote it as you would for ssh: `phoenix ssh arch-omen -- 'cd /srv && ls'`.

After a revoke, `phoenix ssh` stops and says to ask the human. It will not file a
new request by itself. If the human agrees, run it again with `--ask-again`.

## Server setup

`access_requests` must be enabled. Add:

```json
"ssh_ca": {
  "enabled": true,
  "hosts": {
    "arch-omen": { "address": "192.168.0.99" }
  }
}
```

| Key | Meaning |
|---|---|
| `enabled` | Off when the block is missing. |
| `key_path` | Signing key. Empty = `ssh_ca.key` next to the ACL file. Made on first start, mode `0600`. Back it up with the rest of the data directory; losing it only means running the machine setup again. |
| `hosts` | Machine name -> `address` and optional `user` (default `agent`). The name is what agents ask for and what a pass is signed for. Removing a machine or the block ends its open sessions. |

## Machine setup

Once per machine, as root. It fetches the CA's public key from the server, so the
server must be configured first:

```bash
sudo scripts/ssh-node-setup.sh install arch-omen https://phoenix.example.net:9443 /path/to/phoenix-ca.crt
```

It makes these changes. `remove` undoes all of them except the `agent` user:

| Change | Why |
|---|---|
| `agent` user, password locked | The only login this feature opens |
| `/etc/ssh/phoenix-user-ca.pub` | Trust certificates from this Phoenix |
| `/usr/local/sbin/phoenix-ssh-authz` | sshd runs it at every login. Says yes only for this machine's name while the pass's grant is active |
| `/etc/ssh/sshd_config.d/50-phoenix-agent.conf` | For `agent` only: certificates only, no forwarding. Other users are untouched |
| `/etc/sudoers.d/agent-phoenix` | Passwordless sudo, with session output recorded for `sudoreplay` |
| `phoenix-ssh-window.timer` | Every 30s, ends each `agent` SSH session whose own approval is over |

Check it from the machine: `sshd -T -C user=agent,host=x,addr=127.0.0.1 | grep -i -E 'trustedusercakeys|authorizedprincipalscommand|authorizedkeysfile'`.
The machine's sshd log names who logged in: `ID grant=gnt_...,agent=vector,host=arch-omen`.
Set `KEEP_AUTHORIZED_KEYS=1` on the install to leave existing keys working while a
machine moves over. Sessions from those keys have no grant, so the timer leaves them
alone until you run install again without it.

## What this does and does not protect

- **A grant is real root for its length.** Anything with root can install a
  backdoor that outlives the window. The recording and the log show what happened
  afterwards; they do not prevent it.
- **If a machine cannot reach Phoenix,** nobody new can log in, and an open session
  keeps running until it can. The timer finds out on its next run.
- **Rotating an agent's token ends its grant for signing, not its passes.** A pass
  already issued keeps working until it expires. Revoke the grant to end it now.
- **The dashboard login is the approval.** Anyone who has that password can
  approve anything. Do not keep it where an agent can read it.
- **Root on the Phoenix host beats all of this.** It can read `ssh_ca.key`.
- **The source IP is what Phoenix sees.** Behind a proxy or subnet router that is
  the router's address, and the certificate will only work from there.
