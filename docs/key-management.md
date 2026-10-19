# Phoenix Secrets — Key Management

## Master key rotation

Rotate the master encryption key without downtime:

```bash
phoenix rotate-master
```

Phoenix generates a new master key, re-wraps namespace DEKs, and persists the
change atomically. If anything fails mid-rotation, the two-phase commit path
recovers automatically.

The store file and master key file are written with fsync before and after
the rename, so a crash or power loss leaves either the old or the new file,
never a truncated one.

### If rotation fails

Normally a failed rotation rolls back on its own and the old key stays in
use. In the rare case where the rollback cannot repair the store file either,
the server logs a `CRITICAL` message and leaves these recovery files next to
the store:

- `<store>.pre-rotate` — the store as it was before rotation, readable with
  the current `master.key`. Recovery: stop the server, move it over the
  store file, start again.
- `<store>.emergency-key` — the new master key, written **only** when the
  master key is passphrase-protected, and encrypted with that passphrase.
  Without a passphrase Phoenix refuses to write the new key to disk at all.

The running server keeps a working key in memory, and its next successful
write repairs the store file, so avoid restarting it until you have acted.
Delete both files once you have recovered.

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
