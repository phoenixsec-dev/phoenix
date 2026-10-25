# Phoenix Secrets — Key Management

## Master key rotation

Rotate the master encryption key without downtime:

```bash
phoenix rotate-master
```

Phoenix generates a new master key, re-wraps namespace DEKs, and saves the
store and then the key file. If a step fails, Phoenix rolls back to the old
key and, in most cases, repairs the store on its own. When it cannot, it
logs a `CRITICAL` message with manual recovery steps (see below).

The store file and master key file are each written with fsync before and
after the rename. A crash or power loss leaves either the whole old file or
the whole new file, never a truncated one. This relies on the filesystem
honoring fsync; if the final directory sync fails, Phoenix logs a `WARNING`
and the change may roll back to the old file on power loss.

Each file is safe on its own, but the two are not written as one unit. A
crash in the moment between saving the store and saving the new key can
leave a store that the key file cannot open. The `.pre-rotate` backup below
covers that case.

### If rotation fails

Normally a failed rotation rolls back on its own and the old key stays in
use. In the rare case where the store file on disk is left in a state the
current `master.key` cannot open, the server logs a `CRITICAL` message that
lists the recovery files it actually managed to leave next to the store.
That can happen when the rollback cannot repair the store, or when a retry
fails early while the store is still broken from an earlier failure. The
files:

- `<store>.pre-rotate` — a snapshot of the store taken from memory just
  before rotation. It opens with the **current** `master.key`.
- `<store>.emergency-key` — the new master key. Written **only** when the
  master key is passphrase-protected, encrypted with that same passphrase,
  in the same format as `master.key`. Without a passphrase Phoenix refuses
  to write the new key to disk at all.

The running server keeps a working key in memory, and its next successful
write rewrites the store under the current key. So the easiest fix is to
clear the disk problem, then change or re-set any secret before restarting.
A `rotate-master` that succeeds repairs it too. If a retry fails, read the
log again: another `CRITICAL` message means the store is still unreadable
and names the recovery files that exist now. Recover from those, not from
what an earlier message listed.

If the server already stopped, or will not start (it cannot decrypt secrets):

1. Stop the server and copy the whole data directory somewhere safe first.
2. If `<store>.pre-rotate` exists: move it over the store file. Keep
   `master.key` as it is.
3. Otherwise, if `<store>.emergency-key` exists: keep the store file, and
   move `<store>.emergency-key` over `master.key`. Start with the usual
   passphrase.
4. If neither file exists or neither works: `master.key.prev` is the key
   from before the last rotation. Put it in place of `master.key` (this
   fixes a store that rolled back to the old version after a power cut).
5. Start the server and read a few secrets to confirm.
6. Once it works, delete the leftover recovery files and your safety copy.

The same `.pre-rotate` step fixes the crash-between-writes case above. Only
use it when the server cannot decrypt; a stale `.pre-rotate` next to a
working store is harmless and is replaced by the next rotation.

## Master key passphrase protection

Phoenix can protect the master key file with a passphrase using Argon2id and
AES-256-GCM.

### Initialize with a passphrase

```bash
phoenix-server --init /data/phoenix --passphrase "my-strong-passphrase"
```

### Providing the passphrase at boot

```bash
# 1. Pipe from stdin
echo "my-passphrase" | phoenix-server --config /data/config.json --passphrase-stdin

# 2. Environment variable
PHOENIX_MASTER_PASSPHRASE="my-passphrase" phoenix-server --config /data/config.json

# 3. Interactive TTY prompt
phoenix-server --config /data/config.json
```

### Add or change passphrase on an existing deployment

```bash
phoenix-server --protect-key --config /data/config.json
```

Enter an empty new passphrase to remove protection.

> **Warning:** If you lose the passphrase, you lose your secrets.

## Emergency access

Break-glass offline secret retrieval when the server is down:

```bash
phoenix emergency get myapp/db-password --data-dir /data/phoenix
```

For automation, use `--confirm` to skip the interactive prompt.

Emergency mode:
- reads `store.json` and `master.key` directly from disk
- supports a single secret only
- requires explicit confirmation
- logs the access to `audit.log` with agent `emergency-local`

## Related docs

- [Getting Started](getting-started.md)
- [Configuration and Operations](configuration.md)
- [Threat Model](threat-model.md)
