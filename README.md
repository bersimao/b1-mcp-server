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

### Transitive dependency advisories

`sps-sap-interface` declares its dependencies with **exact pins**
(`axios: 0.25.0`, `express: 4.17.1`, `@sap/hana-client: 2.18.22`), so a default
install resolves known-vulnerable versions and `npm audit` reports roughly 16
advisories, 9 of them high.

Only `axios`, `express` and `cors` carry the high-severity ones, and they are
reachable exclusively through `sps-sap-interface`'s `ServiceLayer.js` /
`Xsjs.js`. **This server does not import either**: Service Layer traffic goes
through the local strict-TLS adapter in `src/sl/serviceLayerAdapter.ts`, and
only `DirectDb` is loaded from the dependency. The vulnerable packages are
installed on disk but never executed on any code path this server uses.

`overrides` declared inside a published package are ignored by npm — they apply
only at the root of an install. To clear the advisories, add this to **your
own** `package.json` and reinstall:

```json
{
  "overrides": {
    "axios": "^0.33.0",
    "express": "^4.21.2",
    "cors": "^2.8.6",
    "@sap/hana-client": "^2.21.31",
    "uuid": "^11.1.1"
  }
}
```

Verified: this takes a consumer install to `found 0 vulnerabilities`. Note that
`npx -y sps-mcp-server` runs from a temporary directory with no root
`package.json`, so overrides cannot apply there. If a clean audit matters in
your environment, install the server into a real project (or a managed global
prefix) that carries the block above rather than invoking it through `npx`.

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
    "slUrl": "https://10.0.0.10:50000/b1s/v2",
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

Both SAP Service Layer roots are supported: `/b1s/v1` for OData v3 and
`/b1s/v2` for OData v4. Login, health checks and relative GET/PATCH requests
use the exact root configured by the profile. Request validation is
version-neutral; callers pass only the relative endpoint (for example,
`Items?$select=ItemCode&$top=1`). OData query and payload differences remain
the caller's responsibility. SAP recommends v2 for current installations.

## Security model

**MCP tool responses never expose credentials.** They are read from
`~/.claude/connections.json` inside the server process, passed directly into
the connection adapters, and are never interpolated into any tool response,
audit log entry, or error message. The Service Layer adapter retains only the
session cookie after login, not the username or password. This protocol-level
protection does not stop an AI host that has unrestricted same-user shell or
filesystem access from opening the file directly; see the hook guidance below.

Service Layer connections require HTTPS with normal certificate validation by
default. For an internal certificate authority, set `NODE_EXTRA_CA_CERTS` to
the CA bundle before starting the MCP process.

For a legacy SAP installation whose certificate cannot be renewed, the first
`connect_database` call inspects TLS without sending credentials and requests
explicit approval through MCP form elicitation. An accepted certificate is
stored by canonical `https://host:port` origin in
`~/.claude/service-layer-trust.json` (mode `0600`), so profiles sharing one SL
endpoint share one pin. The file is created only after the first approval and
contains no credentials. A changed certificate requires approval again;
clients without elicitation support fail closed. Legacy manual profile pin
fields remain accepted only for one-time migration into this local store.

Profiles reload on every `connect_database` call. A DB-only profile can gain
`slUrl`, `slUser` and `slPassword` while its DB connection is active; the next
call keeps that DB connection and initializes only Service Layer.

Global certificate verification disablement is never supported: the adapter
refuses to connect when `NODE_TLS_REJECT_UNAUTHORIZED=0` is present.

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
- On POSIX systems, the server fails closed and refuses to load a profile file
  that grants any permission to group or other users.
- Each user maintains their own copy. Credentials never come from this npm
  package.

### Claude Code hook and sandbox guidance

Use a centrally managed Claude Code `PreToolUse` hook or equivalent host policy
to deny AI-issued access to the canonical resolved path of
`connections.json`. Cover every filesystem-capable tool (`Read`, `Grep`,
`Glob`, edit/write tools and filesystem MCP servers), not only literal filename
matches. Shell commands are the difficult case: matching the path text is not
sufficient because commands, working directories and symlinks can access it
indirectly. Prefer a host filesystem sandbox that denies the credential path;
otherwise require approval for shell access outside the workspace.

The hook/policy must live outside AI-writable project and user settings. For
Claude Code enterprise deployments, install it in the platform's managed
settings so project instructions cannot override it. Deny AI writes to
`service-layer-trust.json` as well; reading that file is not secret, but its
integrity controls which legacy certificate is trusted.

Hooks are defense in depth, not an OS security boundary. They govern tool calls
issued through the AI host; they cannot stop this MCP process, another local
process, or a malicious npm package running as the same OS user from reading a
mode-`0600` file. Strong isolation requires a dedicated OS identity, sandbox,
or remotely hosted credential broker. See the
[Claude Code hooks and managed-settings guidance](https://docs.anthropic.com/en/docs/claude-code/iam).

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
| `MCP_SL_TIMEOUT_MS` | `30000` | Service Layer login/request timeout |
| `MCP_SL_TRUST_FILE` | `~/.claude/service-layer-trust.json` | Local non-secret certificate trust store |
| `MCP_SL_MAX_URL_LENGTH` | `2048` | Maximum relative OData URL length |
| `MCP_SL_MAX_BODY_CHARS` | `50000` | Maximum serialised PATCH body length |
| `MCP_SL_PATCH_ENABLED` | `true` | Emergency PATCH kill switch; set to `false` to disable writes |
| `MCP_ELICITATION_TIMEOUT_MS` | `120000` | How long a human gets to answer an approval form (certificate trust, PATCH) before it fails closed |
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

Service Layer requests allow `GET` and guarded `PATCH` only. `POST` / `PUT` /
`DELETE` are blocked. PATCH requires one directly keyed entity endpoint and an
explicit user acceptance through MCP form elicitation. The approval screen is
bound to the database, endpoint, exact body, field list and SHA-256 body hash.
A client without elicitation support cannot PATCH. `MCP_DRY_RUN=true` never
executes PATCH, and `MCP_SL_PATCH_ENABLED=false` disables it globally.

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
