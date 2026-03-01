# Phoenix Runnable Examples

These examples are end-to-end shell scripts you can run locally.

## Prerequisites

- Go 1.25+
- `python3`
- From repo root: `git.home/vector/phoenix`

Each script will:
- build `bin/phoenix` + `bin/phoenix-server` if missing
- initialize an isolated temp data dir
- start a local TLS Phoenix server on a random localhost port
- clean up on exit

## Examples

1. **Local quickstart**
   ```bash
   ./examples/01-local-quickstart/run.sh
   ```

2. **Exec wrapper with `--output-env`**
   ```bash
   ./examples/02-exec-output-env/run.sh
   ```

3. **ACL strict parsing + enforcement**
   ```bash
   ./examples/03-acl-strictness/run.sh
   ```

