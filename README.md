# sps-mcp-server

A secure [Model Context Protocol](https://modelcontextprotocol.io) server that
gives an AI client (e.g. Claude Code) guarded access to SAP Business One via
both the database (HANA / MS SQL) and the Service Layer OData API.

## Features

- **5 MCP tools**: `connect_database`, `execute_sql`, `execute_service_layer`,
  `get_schema_info`, `check_connection`.
- **Multi-environment**: switch between client databases at runtime via named
  connection profiles. No restart needed.
- **Read-only by design**: the SQL path executes only `SELECT`. Every
  `INSERT/UPDATE/DELETE/DROP/CREATE/ALTER/EXEC` is blocked server-side with no
  confirmation bypass — writes are handed to a human to run in a real DB client.
- **Server-side guardrails**: all SQL goes through the same validation whether
  the user or the AI wrote it. Anonymous `DO BEGIN..END` blocks are classified
  by the most dangerous statement inside them, so a write hidden behind a
  trailing `SELECT` is still a write.
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
| `MCP_RATE_LIMIT_MAX_CALLS` | `60` | Max calls per tool per window |
| `MCP_RATE_LIMIT_WINDOW_MS` | `60000` | Rate-limit window |
| `MCP_QUERY_TIMEOUT_MS` | `60000` | Statement ceiling. A query still running at this point is aborted. Raise it if a legitimate report needs longer |
| `MCP_MAX_RESULT_ROWS` | `500` | Max rows returned to the model; extra rows are cut and announced |
| `MCP_MAX_RESULT_CHARS` | `100000` | Max characters of result JSON, applied after the row cap |
| `MCP_DRY_RUN` | `false` | If `true`, validate but don't execute |

The numeric limits above must be positive integers. Anything else (a typo, an
empty value, `0`) is rejected at startup with a message on stderr and the
default is used instead — a misconfigured limit never means "no limit".
`MCP_LOG_LEVEL` behaves the same way, falling back to `info`.

## Guardrail summary

The SQL path is **read-only**, so the live answer does not depend on which
table you touch:

| Operation | Any table (SAP core, UDT, custom, temp) |
|---|---|
| SELECT | allow |
| INSERT / UPDATE / DELETE / DROP | block — run it yourself in a DB client |
| CREATE / ALTER | block |
| EXEC / EXECUTE / CALL | block — stored procedures cannot be run through this server |

Also blocked: multi-statement queries (semicolons outside `BEGIN..END`),
unterminated quotes or brackets, `OPENQUERY` / `OPENROWSET` / `OPENDATASOURCE`,
and `SELECT ... INTO <table>`.

Service Layer requests allow `GET` and `PATCH` only. `POST` / `PUT` / `DELETE`
are blocked — note that `PATCH` **is** a write, and is the one write path the
server permits.

The per-table classification model (SAP_CORE / SAP_USER / CUSTOM / TEMP with
per-operation rules) still exists in `src/guardrails/rules/` and is fully
tested, but on the read-only server it is not reachable from the live path.
See [SECURITY.md](./SECURITY.md) for the full model and its known limitations.

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
