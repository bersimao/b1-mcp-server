# sps-mcp-server

A secure [Model Context Protocol](https://modelcontextprotocol.io) server that
gives an AI client (e.g. Claude Code) guarded access to SAP Business One via
both the database (HANA / MS SQL) and the Service Layer OData API.

## Features

- **7 MCP tools**: `connect_database`, `execute_sql`, `execute_sql_ai`,
  `execute_procedure`, `execute_service_layer`, `get_schema_info`,
  `check_connection`.
- **Multi-environment**: switch between client databases at runtime via named
  connection profiles. No restart needed.
- **Server-side guardrails**: SAP table classification (CORE / USER / CUSTOM /
  TEMP) with per-operation rules. INSERT/DELETE on SAP core tables blocked.
  UPDATE on SAP core tables limited to `U_*` UDFs. DROP blocked outside
  anonymous blocks. Anonymous blocks are also validated server-side (they no
  longer bypass guardrails).
- **Stored-procedure inspection**: SP source code is fetched and scanned for
  prohibited DML before execution; results cached.
- **AI-generated SQL is parameterised**: `execute_sql_ai` rejects queries
  whose `?` placeholder count doesn't match the supplied parameter array.
- **Audit log**: every operation, allowed or denied, is recorded as JSON Lines.
- **Rate limiting** per tool with sliding window.

## Install

```bash
npx sps-mcp-server
```

Or add to your Claude Code MCP config:

```json
{
  "mcpServers": {
    "sps-db": {
      "command": "npx",
      "args": ["-y", "sps-mcp-server"]
    }
  }
}
```

## Connection profiles

The server starts unconnected. Connections are loaded from
`~/.claude/connections.json` (one profile per environment) and selected at
runtime by the AI via the `connect_database` tool.

Profile matching behavior in `connect_database`:
- Exact match by `id` or `dbName` is preferred.
- Partial matches are accepted only when they resolve to a single profile.
- Ambiguous partial matches are rejected with a list of candidates.

Example `~/.claude/connections.json`:

```json
[
  {
    "id": "client_a_prd",
    "dbType": "hana",
    "dbServer": "10.0.0.10:30015",
    "dbName": "SBO_CLIENT_A",
    "dbUser": "B1ADMIN",
    "dbPassword": "•••",
    "slUrl": "https://10.0.0.10:50000/b1s/v1",
    "slUser": "manager",
    "slPassword": "•••"
  },
  {
    "id": "client_b_hmg",
    "dbType": "mssql",
    "dbServer": "10.0.0.20:1433",
    "dbName": "SBO_CLIENT_B_HMG",
    "dbUser": "SA",
    "dbPassword": "•••"
  }
]
```

Service Layer fields (`slUrl`, `slUser`, `slPassword`) are optional — DirectDb
can be configured alone.

## Security model

**The AI never sees credentials.** They are read from
`~/.claude/connections.json` inside the server process, passed directly into
the underlying `sps-sap-interface` adapters, and are never interpolated into
any tool response, audit log entry, or error message. Adapters do not retain
the password after init.

What the AI does see when it calls `connect_database` with `"list"`:

- profile `id`
- `dbName`, `dbType`
- `slUrl` (URL only, no user/password)
- a capability flag (`DB`, `SL`, `DB+SL`)

Recommendations for your `connections.json`:

- Lock the file to your user only.
  - Linux/macOS: `chmod 600 ~/.claude/connections.json`.
  - Windows: `icacls "%USERPROFILE%\.claude\connections.json" /inheritance:r /grant:r "%USERNAME%:F"`.
- Do not commit it to any git repository or share it via cloud sync.
- Each user maintains their own copy. Credentials never come from this npm
  package.

## Configuration (env vars)

All optional.

| Variable | Default | Purpose |
|---|---|---|
| `MCP_CONNECTIONS_FILE` | `~/.claude/connections.json` | Path to profile file |
| `MCP_AUDIT_LOG_PATH` | `~/.claude/logs/sps-mcp-audit.jsonl` | Audit log JSONL file. Empty disables file logging |
| `MCP_LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |
| `MCP_MAX_QUERY_LENGTH` | `8000` | Max SQL length in characters |
| `MCP_PROCEDURE_CACHE_TTL_MS` | `1800000` | SP inspection cache TTL |
| `MCP_PROCEDURE_CACHE_MAX_SIZE` | `200` | SP inspection cache size |
| `MCP_RATE_LIMIT_MAX_CALLS` | `60` | Max calls per tool per window |
| `MCP_RATE_LIMIT_WINDOW_MS` | `60000` | Rate-limit window |
| `MCP_DRY_RUN` | `false` | If `true`, validate but don't execute |

## Guardrail summary

| Operation | SAP_CORE (≤4 chars: ORDR, OITM, …) | SAP_USER (`@`-prefixed) | CUSTOM (>4 chars) | TEMP (`#` / `##`) |
|---|---|---|---|---|
| SELECT | allow | allow | allow | allow |
| INSERT | block | confirm | allow | allow |
| UPDATE | only `U_*` cols | allow | allow | allow |
| DELETE | block | confirm | allow | allow |
| DROP | block | block | block (outside `BEGIN..END`) | block (outside `BEGIN..END`) |

EXEC / EXECUTE / CALL in raw SQL is always blocked — call the
`execute_procedure` tool, which inspects the SP body before running it.

## Development

```bash
npm install
npm run build
npm run test
npm run test:watch
# Optional aliases (same behavior, useful if you prefer explicit naming):
npm run test:bash
npm run test:watch:bash
```

Quick connection sanity check (uses a profile from `connections.json`):

```bash
npx tsx scripts/test-connection.ts <profile-id>
```

## License

MIT — see [LICENSE](./LICENSE).
