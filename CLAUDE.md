# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`sps-mcp-server` is a Model Context Protocol server that gives an AI client guarded access to SAP Business One via both `DirectDb` (HANA / MS SQL) and the Service Layer OData API. Both adapters come from the `sps-sap-interface` npm module.

The server starts **without** any database or Service Layer connection. The AI must call `connect_database` to load a profile from `~/.claude/connections.json` and connect both sides at once. There is no env-var fallback — credentials live exclusively in that file.

End-user docs (install, connection profile shape, security posture) are in [README.md](README.md). This file is for working *on* the codebase.

## Commands

```bash
npm install                        # one-time
npm run build                      # tsc — prebuild wipes dist/ for a clean output
npm run watch                      # tsc --watch
npm run dev                        # tsx src/index.ts (skips build)
npm test                           # vitest run — full suite (362 tests)
npm run test:watch                 # vitest in watch mode

# Single file
npx vitest run tests/guardrails/parser.test.ts

# By name pattern
npx vitest run -t "blocks DROP on SAP_CORE"
```

Standalone DirectDb sanity check against a connection profile (no MCP server, just the underlying adapter):

```bash
npx tsx scripts/test-connection.ts <profile-id>
```

Pre-publish dry run (verifies the tarball ships only `dist/`, `LICENSE`, `README.md`, `package.json`):

```bash
npm pack --dry-run
```

## Architecture

### Connection model

`DirectDb` and `ServiceLayer` are singletons exported from `sps-sap-interface`. Their `init()` methods can be re-called to switch environments. Thin wrappers:

- [src/db/adapter.ts](src/db/adapter.ts) — `DbAdapter`
- [src/sl/serviceLayerAdapter.ts](src/sl/serviceLayerAdapter.ts) — `ServiceLayerAdapter`

Each adapter tracks `dbName` and `dbType` but does **not** retain credentials after init.

[src/tools/connectDatabase.ts](src/tools/connectDatabase.ts) implements the safe dual-connection switch:

- Connecting to a new environment **always disconnects both** previous DB and SL first (prevents cross-environment operations).
- Partial success is allowed: if SL fails on the new target, DB stays active (and vice versa). Retrying the same profile reconnects only the failed side.
- Failed login attempts are tracked per profile/side; a warning is appended after `SAP_LOCKOUT_WARNING_THRESHOLD = 3` — SAP B1 locks accounts after repeated failures.

Profile matching (`ConnectionManager.find` in [src/config/connectionManager.ts](src/config/connectionManager.ts)): exact `id` → exact `dbName` → **unique** partial substring match. Ambiguous partials (multiple profiles share the substring) return `undefined` and the tool surfaces the candidate list instead of guessing.

### `sps-sap-interface` call shapes (gotchas)

- `DirectDb.executeQuery(query, params?)` — `{db}` is the schema placeholder DirectDb resolves at runtime; `?` is the parameter placeholder.
- `DirectDb.executeProcedure(name, paramsArray)` — positional array, **not** key-value.
- `ServiceLayer.execute({ method, url, data?, header?, page?, size?, timeout? })` — auto-reconnects on 401.
- **`?` parameter binding works for SELECT and INSERT but NOT for UPDATE.** UPDATEs are passed as plain text, which is why a dedicated 4-layer sanitiser exists.

### MCP tools

Every tool is registered in [src/server.ts](src/server.ts) and shares the same adapters / logger / rate limiter.

| Tool | File | Purpose |
|---|---|---|
| `connect_database` | [tools/connectDatabase.ts](src/tools/connectDatabase.ts) | Switch active DB + SL; `"list"` to enumerate profiles |
| `execute_sql` | [tools/executeSql.ts](src/tools/executeSql.ts) | User-provided SQL; all ops including anonymous blocks, fully validated server-side |
| `execute_sql_ai` | [tools/executeSqlAi.ts](src/tools/executeSqlAi.ts) | AI-generated SQL, **mandatory `?` placeholders** matching the parameters array length |
| `execute_procedure` | [tools/executeProcedure.ts](src/tools/executeProcedure.ts) | Calls SP after inspecting its body |
| `execute_service_layer` | [tools/executeServiceLayer.ts](src/tools/executeServiceLayer.ts) | OData GET/POST/PATCH/DELETE; DELETE requires user confirmation |
| `get_schema_info` | [tools/schemaIntrospection.ts](src/tools/schemaIntrospection.ts) | Read-only metadata, HANA + MSSQL catalog syntax |
| `check_connection` | [tools/checkConnection.ts](src/tools/checkConnection.ts) | Independent health pings for DB and SL |

The split between `execute_sql` and `execute_sql_ai` is **by origin, not by operation**. Both go through the same `validateAnySql()` pipeline — the difference is `execute_sql_ai` additionally requires that the `?` placeholder count matches the parameters array length, blocking malformed AI-generated queries before they hit the DB.

### Guardrail engine

[src/guardrails/](src/guardrails/) is the security core. Both SQL tools call `validateAnySql()` from [guardrails/index.ts](src/guardrails/index.ts), which:

1. [parser.ts](src/guardrails/parser.ts) — tokenises and classifies operation type, table list, SET columns. For `DO BEGIN..END` (HANA) and `BEGIN..END` (MSSQL) anonymous blocks, **decomposes** the body and surfaces every inner DML statement so each one passes through the rules below. Semicolons inside the block are allowed; bare multi-statement queries are not.
2. [tableClassifier.ts](src/guardrails/tableClassifier.ts) — name-based classification:
   - **SAP_CORE** (≤4 chars, e.g. `ORDR`, `OITM`, `INV1`): most restrictive
   - **SAP_USER** (`@`-prefixed UDTs, e.g. `@MY_UDT`)
   - **CUSTOM** (>4 chars, no `@`)
   - **TEMP** (`#` / `##` prefixed)
3. Per-operation rule under [guardrails/rules/](src/guardrails/rules/) — applied to every statement, including those extracted from anonymous blocks.
4. For `execute_sql_ai` only: [placeholderValidator.ts](src/guardrails/placeholderValidator.ts) — counts `?` and rejects mismatched parameter arrays.
5. For plain-text UPDATEs (which can't use `?` binding): [sanitisation/updateSanitiser.ts](src/sanitisation/updateSanitiser.ts) — 4 layers: input validation → structure validation (no UNION/INTERSECT/EXCEPT) → dangerous-pattern detection (`xp_cmdshell`, `EXEC(`, `CALL`, `WAITFOR`, `OPENROWSET`, `sp_executesql`) → comment blocking.

Operation rules matrix:

| Op | SAP_CORE | SAP_USER | CUSTOM | TEMP |
|---|---|---|---|---|
| SELECT | allow | allow | allow | allow |
| INSERT | block | confirm | allow | allow |
| UPDATE | only `U_*` cols | allow | allow | allow |
| DELETE | block | confirm | allow | allow |
| DROP | block | block | only inside `BEGIN..END` | only inside `BEGIN..END` |

Always blocked: `EXEC` / `EXECUTE` / `CALL` in raw SQL (use `execute_procedure`), `CREATE` / `ALTER`, multi-statement queries (semicolons).

### Stored procedure inspection

[src/inspection/](src/inspection/) — before any SP runs, its source is fetched from the system catalog and scanned for prohibited DML. Results cached by SHA-256 of the body in an LRU with 30-min TTL. This is why `execute_procedure` is the only path for SPs: `EXEC` / `CALL` in raw SQL is rejected.

### Audit log

[src/logging/auditLogger.ts](src/logging/auditLogger.ts) writes JSON Lines to stderr (always) and optionally to a file (default: `~/.claude/logs/sps-mcp-audit.jsonl`, set via `MCP_AUDIT_LOG_PATH`). Logging happens **before execution** — denied operations are recorded too. The MCP stdio transport uses stdout for JSON-RPC, so logs must never go to stdout.

## Layout

```
src/
  index.ts            entry, imports DirectDb/ServiceLayer, bootstraps
  server.ts           factory: registers all tools, shares adapters
  config/             settings + connection-profile loader
  db/, sl/            adapters around DirectDb / ServiceLayer
  tools/              one file per MCP tool
  guardrails/         parser, classifier, per-op rules, placeholder validator
  sanitisation/       UPDATE sanitiser, input validator
  builders/           structured JSON → parameterised SQL with {db} prefix
  inspection/         SP body inspector + LRU cache
  rateLimit/          sliding-window per-tool rate limiter
  logging/            JSON Lines audit logger
tests/                mirrors src/ — vitest, every guardrail rule covered
scripts/
  test-connection.ts  standalone DirectDb sanity check (takes profile id)
```

## Design principles

1. **Deny by default.** Unrecognised operations are rejected.
2. **Audit before execute.** Even denied operations are written to the audit log.
3. **Never rewrite suspicious queries.** Accept as-is or reject; no silent normalisation.
4. **Server is the authority on SQL safety.** Anonymous `DO BEGIN..END` / `BEGIN..END` blocks are decomposed and every inner statement is rule-checked — the AI's tool description still asks it to pre-validate as a courtesy, but trust does not depend on it.
5. **HANA vs MSSQL syntax differs** throughout (e.g. `CALL` vs `EXEC`, `DO BEGIN` vs `BEGIN`, schema-introspection queries). When adding features, handle both.
6. **`{db}` placeholder** appears in every generated query so DirectDb resolves the schema for the active profile.
7. **Credentials never leave the server process.** Profile listings expose only `id`, `dbName`, `dbType`, `slUrl`, capability flags. Adapters do not retain passwords. Nothing is interpolated into tool responses, audit entries, or error messages.

## Tech stack

Node ≥18, TypeScript ES2022 with Node16 modules. Dependencies: `@modelcontextprotocol/sdk` (stdio transport), `zod` (tool schema validation), `sps-sap-interface` (DirectDb + ServiceLayer). Tests via `vitest`.
