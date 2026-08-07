# b1-mcp-server

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
- **Server-side guardrails**: all raw SQL submitted to `execute_sql` goes
  through the same validation whether the user or the AI wrote it. Anonymous
  `DO BEGIN..END` blocks are classified by the most dangerous statement inside
  them, so a write hidden behind a trailing `SELECT` is still a write.
- **Audit trail**: selected-profile connection attempts and database/Service
  Layer calls that reach policy or execution are recorded as JSON Lines,
  including policy denials.
- **Rate limiting** per tool with sliding window.

## Install

Requires Node.js 18 or newer.

```bash
npx b1-mcp-server
```

Or add to your Claude Code MCP config:

```json
{
  "mcpServers": {
    "b1-db": {
      "command": "npx",
      "args": ["-y", "b1-mcp-server"]
    }
  }
}
```

### Dependencies

Five runtime dependencies: `@modelcontextprotocol/sdk`, `zod`,
`@sap/hana-client` and `mssql` (plus `generic-pool`, which backs the HANA
connection pool). Database access is a local driver — `src/db/directDb.ts` —
built directly on the HANA and MS SQL clients; Service Layer traffic goes
through the strict-TLS adapter in `src/sl/serviceLayerAdapter.ts` using Node's
own `fetch` and `https`. No HTTP framework, no axios, no PostgreSQL driver.

A clean install audits at `found 0 vulnerabilities` with no `overrides` block,
which also means `npx -y b1-mcp-server` is clean — overrides never applied
there, since npx runs without a root `package.json`.

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

Every profile requires `id`, `dbType` and `dbName`. Add `dbServer` and `dbUser`
to configure DirectDb; add `slUrl` and `slUser` to configure Service Layer.
Each configured side also requires its non-empty password (`dbPassword` or
`slPassword`). Missing/empty passwords fail locally without a login attempt,
avoiding an unnecessary failure that may count toward account lockout under the
configured login policy. Non-empty password strings are passed through without
trimming. Either side, or both sides, can be configured in one profile.

Both SAP Service Layer roots are supported: `/b1s/v1` for OData v3 and
`/b1s/v2` for OData v4. Login, health checks and relative GET/PATCH requests
use the exact root configured by the profile. Request validation is
version-neutral; callers pass only the relative endpoint (for example,
`Items?$select=ItemCode&$top=1`). OData query and payload differences remain
the caller's responsibility; configure the root supported by the target SAP B1
installation. SAP deprecated OData v3 starting with SAP Business One 10.0 FP
2405 and made OData v4 the primary protocol, so prefer `/b1s/v2` when the target
installation supports it; see the
[Service Layer API reference](https://help.sap.com/doc/056f69366b5345a386bb8149f1700c19/10.0/en-US/Service%20Layer%20API%20Reference.html).

## Security model

**The server does not intentionally interpolate profile passwords into MCP tool
responses or audit entries.** Passwords are read from
`~/.claude/connections.json` inside the server process and passed directly to
the configured database or Service Layer endpoint for login. The Service Layer
adapter retains only the session cookie afterward, not the username or
password. Database-driver and Service Layer error messages are returned and
audited verbatim for diagnosis, however, so there is no general-purpose secret
redaction boundary around arbitrary upstream error text. Do not place secrets
in profile IDs, database names, URLs or other non-password metadata. This
protocol-level protection also does not stop an AI host that has unrestricted
same-user shell or filesystem access from opening the file directly; see the
hook guidance below.

Service Layer connections require HTTPS with normal certificate validation by
default. For an internal certificate authority, set `NODE_EXTRA_CA_CERTS` to
the CA bundle before starting the MCP process.

For a legacy SAP installation whose certificate cannot be renewed, the first
`connect_database` call inspects TLS without sending credentials and requests
explicit approval through MCP form elicitation. An accepted certificate is
stored by canonical `https://host:port` origin in
`~/.claude/service-layer-trust.json` (mode `0600`), so profiles sharing one SL
endpoint share one pin. The file is created after explicit approval or after a
matching legacy manual profile pin is migrated successfully, and contains no
credentials. A changed certificate requires approval again; clients without
elicitation support fail closed. Legacy manual profile pin fields remain
accepted only for that one-time migration into this local store.

Profiles reload on every `connect_database` call. A DB-only profile can gain
`slUrl`, `slUser` and `slPassword` while its DB connection is active; the next
call keeps that DB connection and initializes only Service Layer.

Global certificate verification disablement is never supported: the adapter
refuses to connect when `NODE_TLS_REJECT_UNAUTHORIZED=0` is present.

What the AI does see when it calls `connect_database` with `"list"`:

- profile `id`
- `dbName`, `dbType`
- a capability flag (`DB`, `SL`, `DB+SL`)
- an `active` marker when either configured side is currently connected

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
[Claude Code hooks](https://code.claude.com/docs/en/hooks) and
[server-managed settings](https://code.claude.com/docs/en/server-managed-settings)
guidance.

## Configuration (env vars)

All optional.

**There is no `.env` file.** The server reads `process.env` directly and never
loads a dotenv file, so dropping a `.env` next to it does nothing. For a stdio
MCP server the client owns the environment — set variables in the `env` block of
your MCP configuration, which the client passes to the spawned process:

```json
{
  "mcpServers": {
    "b1-db": {
      "command": "npx",
      "args": ["-y", "b1-mcp-server"],
      "env": {
        "MCP_QUERY_TIMEOUT_MS": "120000",
        "MCP_SL_PATCH_ENABLED": "false"
      }
    }
  }
}
```

Credentials are **not** configured this way — they live only in
`connections.json`, which is resolved from your home directory and therefore
found regardless of where `npx` runs from.

| Variable | Default | Purpose |
|---|---|---|
| `MCP_CONNECTIONS_FILE` | `~/.claude/connections.json` | Path to profile file |
| `MCP_AUDIT_LOG_PATH` | `~/.claude/logs/b1-mcp-audit.jsonl` | Audit log JSONL file. Unset or empty uses the default path |
| `MCP_LOG_LEVEL` | `info` | Stderr verbosity: `debug` / `info` / `warn` / `error`. JSONL file logging is unaffected |
| `MCP_MAX_QUERY_LENGTH` | `8000` | Max SQL length in characters |
| `MCP_RATE_LIMIT_MAX_CALLS` | `60` | Max calls per tool per window |
| `MCP_RATE_LIMIT_WINDOW_MS` | `60000` | Rate-limit window |
| `MCP_QUERY_TIMEOUT_MS` | `60000` | Statement ceiling. A query still running at this point is aborted. Raise it if a legitimate report needs longer |
| `MCP_SL_TIMEOUT_MS` | `30000` | Service Layer login/request timeout |
| `MCP_SL_TRUST_FILE` | `~/.claude/service-layer-trust.json` | Local non-secret certificate trust store |
| `MCP_SL_MAX_URL_LENGTH` | `2048` | Maximum relative OData URL length |
| `MCP_SL_MAX_BODY_CHARS` | `50000` | Maximum serialised PATCH body length |
| `MCP_SL_PATCH_ENABLED` | `true` | Emergency PATCH kill switch; `true`/`false` are case-insensitive and invalid values disable writes |
| `MCP_ELICITATION_TIMEOUT_MS` | `120000` | How long a human gets to answer an approval form (certificate trust, PATCH) before it fails closed |
| `MCP_MAX_RESULT_ROWS` | `500` | Max rows returned to the model; extra rows are cut and announced |
| `MCP_MAX_RESULT_CHARS` | `100000` | Max characters of result JSON, applied after the row cap |
| `MCP_DRY_RUN` | `false` | The exact value `true` validates raw SQL and PATCH without executing them; connections and Service Layer GET still run |

The numeric limits above must be positive integers. An unset or whitespace-only
value uses the default. Any other invalid value (including `0`, a negative or a
non-integer) reports the fallback on stderr and uses the default — a
misconfigured limit never means "no limit". `MCP_LOG_LEVEL` likewise uses
`info` when unset/empty and reports a fallback for any other invalid value.

## Guardrail summary

The SQL path is **read-only**, so the live answer does not depend on which
table you touch:

| Operation | Any table (SAP core, UDT, custom, temp) |
|---|---|
| SELECT | allow, subject to the SELECT-specific restrictions below |
| INSERT / UPDATE / DELETE / DROP | block — run it yourself in a DB client |
| CREATE / ALTER | block |
| EXEC / EXECUTE / CALL | block — stored procedures cannot be run through this server |

Also blocked: multi-statement queries (semicolons outside `BEGIN..END`),
unterminated quotes or brackets, sequence advancement (`NEXTVAL` /
`NEXT VALUE FOR`), `OPENQUERY` / `OPENROWSET` / `OPENDATASOURCE`,
`SELECT ... INTO <table>`, and high-impact SQL Server lock hints (`UPDLOCK`,
`XLOCK`, `TABLOCK`, `TABLOCKX`, `HOLDLOCK`, `SERIALIZABLE`,
`REPEATABLEREAD`).

Service Layer requests allow `GET` and guarded `PATCH` only. `POST` / `PUT` /
`DELETE` are blocked. PATCH requires one directly keyed entity endpoint and an
explicit user acceptance through MCP form elicitation. The approval screen is
bound to the database, Service Layer root, endpoint, exact body, field list and SHA-256 body hash.
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

From a source checkout only, run this quick connection sanity check using a
profile from `connections.json` (`scripts/` is not shipped in the npm tarball):

```bash
npx tsx scripts/test-connection.ts <profile-id>
```

## License

MIT — see [LICENSE](./LICENSE).
