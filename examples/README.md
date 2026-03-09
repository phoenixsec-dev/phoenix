# Phoenix Runnable Examples

These examples are end-to-end shell scripts you can run locally.

## Prerequisites

- Go 1.25+
- `python3`
- From repo root: `github.com/phoenixsec-dev/phoenix`

Each script will:
- build `bin/phoenix` + `bin/phoenix-server` if missing
- initialize an isolated temp data dir
- start a local TLS Phoenix server on a random localhost port
- clean up on exit

## Examples

1. **Local quickstart (prefers `phoenix exec`)**
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


## MCP HTTP quick check (no script)

If you need MCP Streamable HTTP instead of stdio:

```bash
PHOENIX_MCP_TOKEN=test-mcp-token ./bin/phoenix mcp-server --http 127.0.0.1:8080
```

Endpoint: `http://127.0.0.1:8080/mcp`
Auth header: `Authorization: Bearer test-mcp-token`
