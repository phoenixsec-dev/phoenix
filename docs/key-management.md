# Phoenix Key Management

## Master key rotation

Rotate the master encryption key without downtime:

```bash
phoenix rotate-master
```

Phoenix generates a new master key, re-wraps namespace DEKs, and persists the
change atomically. If anything fails mid-rotation, the two-phase commit path
recovers automatically.

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
