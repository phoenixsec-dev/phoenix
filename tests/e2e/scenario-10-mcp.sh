#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 10 mcp-stdio
init_scenario 10
start_server
phoenix_admin set mcp/key -v synthetic-mcp >/dev/null
cat >"$RUN_DIR/mcp.in" <<'JSON'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"phoenix_list","arguments":{"prefix":"mcp/"}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"phoenix_get","arguments":{"path":"mcp/key"}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"phoenix_resolve","arguments":{"refs":["phoenix://mcp/key"]}}}
JSON
PHOENIX_TOKEN="$ADMIN_TOKEN" "$PHOENIX" mcp-server <"$RUN_DIR/mcp.in" >"$RUN_DIR/mcp.out"
python3 - "$RUN_DIR/mcp.out" <<'PY'
import json, sys
rows=[json.loads(x) for x in open(sys.argv[1], encoding='utf-8') if x.strip()]
assert [r.get('id') for r in rows] == [1,2,3,4,5], rows
text=json.dumps(rows)
for expected in ('phoenix_get','phoenix_resolve','phoenix_list','mcp/key','synthetic-mcp'):
    assert expected in text, expected
PY
ok "Scenario 10 PASS"
