# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project reference
- **Project note:** [MCP sps-db](file:///mnt/c/Users/bernardo.simao/repos_local/OBSIDIAN/obsidian_work/MCP%20sps-db.md)
- **OneDrive (docs/entregáveis):** file:///mnt/c/Users/bernardo.simao/OneDrive%20-%20SPS%20Consultoria/Dados/PROJETOS/SPS/MCP%20sps-db
- Registry: this demand is registered in `~/.claude/data/demands.json`.

## Session behavior
- On session start, read the project note and surface its **open doubts**
  (`- [ ] #duvida`) in one short line. No doubts → say nothing.
- When we hit a genuine ambiguity (spec unclear, missing definition), don't let
  it die in chat: add it as `- [ ] #duvida ...` under the relevant TO-DO task in
  the project note (see the `duvida` skill) and tell me you logged it.
- Deliverables (final SQL, evidence, docs sent to the client) are COPIED to the
  OneDrive folder above; intermediate/throwaway files stay here in the workdir.

## Project

`sps-mcp-server` is a Model Context Protocol server that gives an AI client guarded access to SAP Business One via both `DirectDb` (HANA / MS SQL) and the Service Layer OData API. Both adapters come from the `sps-sap-interface` npm module.

**Read-only posture:** the DirectDb/SQL path executes only `SELECT` (and anonymous blocks whose statements are all reads); every `INSERT/UPDATE/DELETE/DROP/CREATE/ALTER/EXEC` is blocked at the guardrail — there is no confirmation bypass. The Service Layer path allows `GET` and `PATCH` only (`PATCH` is safe because the Service Layer commits atomically, unlike the shared DirectDb pool). Writes are the human's job: the AI hands the SQL to a person who runs it in a real DB client.

The server starts **without** any database or Service Layer connection. The AI must call `connect_database` to load a profile from `~/.claude/connections.json` and connect both sides at once. There is no env-var fallback — credentials live exclusively in that file.

End-user docs (install, connection profile shape, security posture) are in [README.md](README.md). This file is for working *on* the codebase.

## Commands

```bash
npm install                        # one-time
npm run build                      # tsc — prebuild wipes dist/ for a clean output
npm run watch                      # tsc --watch
npm run dev                        # tsx src/index.ts (skips build)
npm test                           # vitest run — full suite (227 tests)
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

- `DirectDb.executeQuery(query, params?)` — `{db}` is the schema placeholder DirectDb resolves at runtime; `?` is the parameter placeholder. This read-only server only ever issues `SELECT`, so `?` binding always applies.
- `ServiceLayer.execute({ method, url, data?, header?, page?, size?, timeout? })` — auto-reconnects on 401.

### MCP tools

Every tool is registered in [src/server.ts](src/server.ts) and shares the same adapters / logger / rate limiter.

| Tool | File | Purpose |
|---|---|---|
| `connect_database` | [tools/connectDatabase.ts](src/tools/connectDatabase.ts) | Switch active DB + SL; `"list"` to enumerate profiles |
| `execute_sql` | [tools/executeSql.ts](src/tools/executeSql.ts) | Runs SQL (user- or AI-written) — **read-only**: only SELECT and read-only anonymous blocks pass `validateAnySql()` |
| `execute_service_layer` | [tools/executeServiceLayer.ts](src/tools/executeServiceLayer.ts) | OData **GET / PATCH only**; POST/PUT/DELETE blocked server-side |
| `get_schema_info` | [tools/schemaIntrospection.ts](src/tools/schemaIntrospection.ts) | Read-only metadata, HANA + MSSQL catalog syntax |
| `check_connection` | [tools/checkConnection.ts](src/tools/checkConnection.ts) | Independent health pings for DB and SL |

`execute_sql` handles SQL regardless of origin — user-written or AI-generated queries all go through the same `validateAnySql()` pipeline, which on this read-only server permits only SELECT (and anonymous blocks whose statements are all reads).

### Guardrail engine

[src/guardrails/](src/guardrails/) is the security core. The `execute_sql` tool calls `validateAnySql()` from [guardrails/index.ts](src/guardrails/index.ts), which:

1. [parser.ts](src/guardrails/parser.ts) — tokenises and classifies operation type, table list, SET columns. For `DO BEGIN..END` (HANA) and `BEGIN..END` (MSSQL) anonymous blocks it classifies the block by the **most dangerous statement inside it**: any write/exec/DDL keyword (`INSERT/UPDATE/DELETE/DROP/CREATE/ALTER/CALL/EXEC/TRUNCATE/MERGE/…`) makes the whole block that operation, so a block can never be disguised as a read by appending a trailing `SELECT`. Keyword scanning blanks out quoted spans so a keyword inside a string/identifier doesn't false-trigger. Semicolons inside a block are allowed; bare multi-statement queries are not.
2. [tableClassifier.ts](src/guardrails/tableClassifier.ts) — name-based classification:
   - **SAP_CORE** (≤4 chars, e.g. `ORDR`, `OITM`, `INV1`): most restrictive
   - **SAP_USER** (`@`-prefixed UDTs, e.g. `@MY_UDT`)
   - **CUSTOM** (>4 chars, no `@`)
   - **TEMP** (`#` / `##` prefixed)
3. Read-only enforcement — `validateAnySql()` permits only `SELECT`; `INSERT/UPDATE/DELETE/DROP/CREATE/ALTER/EXEC` and unrecognised operations are all denied. Two writes-disguised-as-reads are blocked explicitly in [rules/selectRule.ts](src/guardrails/rules/selectRule.ts): `SELECT ... INTO <table>` (MS SQL table creation) and pass-through functions (`OPENQUERY/OPENROWSET/OPENDATASOURCE`). Both checks run on comment-stripped, quote-blanked SQL so an inline comment (`OPENQUERY/**/(...)`) cannot evade them.

The per-operation rules under [guardrails/rules/](src/guardrails/rules/) (INSERT/UPDATE/DELETE/DROP) still exist and encode the classification model below, but on the live read-only server they are reachable only through the internal `validate()` helper used by the unit tests — the live tool path stops at SELECT.

Classification model (the rules under `guardrails/rules/`, exercised by tests — **not** the live gate, which is read-only):

| Op | SAP_CORE | SAP_USER | CUSTOM | TEMP |
|---|---|---|---|---|
| SELECT | allow | allow | allow | allow |
| INSERT | block | confirm | allow | allow |
| UPDATE | only `U_*` cols | allow | allow | allow |
| DELETE | block | confirm | allow | allow |
| DROP | block | block | only inside `BEGIN..END` | only inside `BEGIN..END` |

Always blocked in raw SQL regardless: `EXEC` / `EXECUTE` / `CALL`, `CREATE` / `ALTER`, and multi-statement queries (semicolons outside blocks).

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
  guardrails/         parser, table classifier, per-op rules (index.ts = read-only gate)
  sanitisation/       input validator (length / null-byte pre-checks)
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
4. **Server is the authority on SQL safety.** The live SQL path is read-only: `validateAnySql()` executes only `SELECT`. Anonymous `DO BEGIN..END` / `BEGIN..END` blocks are classified by their most dangerous inner statement, so a write/exec hidden behind a trailing `SELECT` is still blocked — trust does not depend on the AI pre-validating.
5. **HANA vs MSSQL syntax differs** throughout (e.g. `CALL` vs `EXEC`, `DO BEGIN` vs `BEGIN`, schema-introspection queries). When adding features, handle both.
6. **`{db}` placeholder** appears in every generated query so DirectDb resolves the schema for the active profile.
7. **Credentials never leave the server process.** Profile listings expose only `id`, `dbName`, `dbType`, `slUrl`, capability flags. Adapters do not retain passwords. Nothing is interpolated into tool responses, audit entries, or error messages.

## Tech stack

Node ≥18, TypeScript ES2022 with Node16 modules. Dependencies: `@modelcontextprotocol/sdk` (stdio transport), `zod` (tool schema validation), `sps-sap-interface` (DirectDb + ServiceLayer). Tests via `vitest`.
