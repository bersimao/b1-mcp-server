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

`sps-mcp-server` is a Model Context Protocol server that gives an AI client guarded access to SAP Business One via both `DirectDb` (HANA / MS SQL) and the Service Layer OData API. DirectDb comes from `sps-sap-interface`; Service Layer uses the local verified-TLS fetch adapter.

**Read-only SQL posture:** DirectDb executes only `SELECT` (and anonymous blocks whose statements are all reads); every `INSERT/UPDATE/DELETE/DROP/CREATE/ALTER/EXEC` is blocked. Service Layer allows `GET` and guarded `PATCH`. PATCH requires a directly keyed entity and explicit user acceptance through MCP form elicitation; clients without elicitation support fail closed. SQL writes remain the human's job.

The server starts **without** any database or Service Layer connection. The AI must call `connect_database` to load a profile from `~/.claude/connections.json` and connect both sides at once. There is no env-var fallback — credentials live exclusively in that file.

End-user docs (install, connection profile shape, security posture) are in [README.md](README.md). This file is for working *on* the codebase.

## Commands

```bash
npm install                        # one-time
npm run build                      # tsc — prebuild wipes dist/ for a clean output
npm run watch                      # tsc --watch
npm run dev                        # tsx src/index.ts (skips build)
npm test                           # vitest run — full suite (286 tests)
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

`DirectDb` is the singleton exported from `sps-sap-interface`. The local Service Layer adapter deliberately bypasses the dependency's insecure `rejectUnauthorized:false` implementation. Thin wrappers:

- [src/db/adapter.ts](src/db/adapter.ts) — `DbAdapter`
- [src/sl/serviceLayerAdapter.ts](src/sl/serviceLayerAdapter.ts) — strict-by-default TLS `ServiceLayerAdapter` with explicit per-profile certificate pinning compatibility; retains only the session cookie

Each adapter tracks `dbName` and `dbType` but does **not** retain credentials after init.

[src/tools/connectDatabase.ts](src/tools/connectDatabase.ts) implements the safe dual-connection switch:

- `OperationCoordinator` serializes every operation and environment switch.
- Connecting to a new environment disconnects both sides and closes the old DirectDb pool first.
- Partial success is allowed: if SL fails on the new target, DB stays active (and vice versa). Retrying the same profile reconnects only the failed side. Profiles reload on every connection call, so adding SL fields to an already-active DB-only profile initializes only SL.
- Failed login attempts are tracked per profile/side; a warning is appended after `SAP_LOCKOUT_WARNING_THRESHOLD = 3` — SAP B1 locks accounts after repeated failures.

Profile matching (`ConnectionManager.find` in [src/config/connectionManager.ts](src/config/connectionManager.ts)): exact `id` → exact `dbName` → **unique** partial substring match. Ambiguous partials (multiple profiles share the substring) return `undefined` and the tool surfaces the candidate list instead of guessing.

### `sps-sap-interface` call shapes (gotchas)

- `DirectDb.executeQuery(query, params?)` — `{db}` is the schema placeholder DirectDb resolves at runtime; `?` is the parameter placeholder. This read-only server only ever issues `SELECT`, so `?` binding always applies. On MS SQL, DirectDb rewrites each `?` to `@mssqlboundparmN` before handing the statement to `mssql`.
- `DirectDb.init({ …, timeout })` — one value, two meanings: HANA `communicationTimeout`, MS SQL `connectionTimeout` **and** `requestTimeout`. DirectDb's own default is 600 000 ms; `connect_database` overrides it with `config.queryTimeoutMs` (`MCP_QUERY_TIMEOUT_MS`, default 60 s). This is the only cost ceiling in the server — the row cap runs after the DB has already done the work. Both engines were measured killing the statement server-side (`SYS.M_ACTIVE_STATEMENTS` / `sys.dm_exec_requests`), and both pools survive repeated timeouts (12 poisons → 25/25 clean). They differ in how the abort *looks*: MS SQL cancels the request and reports `Timeout: Request failed to complete in Nms`, but **HANA drops the socket**, so a timed-out query surfaces as `Connection down: [89012] Socket recv timeout` with no mention of a timeout at all — don't chase that as a network fault. `hana-client` reconnects transparently, so the next query just works.
- Service Layer uses native `fetch` for strict TLS and a pinned native HTTPS transport for approved legacy endpoints. Both `/b1s/v1` (OData v3) and `/b1s/v2` (OData v4) profile roots are preserved exactly; the security policy validates only version-neutral relative endpoints. Invalid certificates are inspected without credentials and require MCP form elicitation before their exact fingerprint is saved in the local owner-only trust store. Changed certificates require approval again. Redirects are disabled, requests have fixed timeouts and bounded responses, and pins are checked before login credentials can be transmitted. A 401 requires reconnecting the profile; credentials are not retained for automatic login.

### MCP tools

Every tool is registered in [src/server.ts](src/server.ts) and shares the same adapters / logger / rate limiter.

| Tool | File | Purpose |
|---|---|---|
| `connect_database` | [tools/connectDatabase.ts](src/tools/connectDatabase.ts) | Switch active DB + SL; `"list"` to enumerate profiles |
| `execute_sql` | [tools/executeSql.ts](src/tools/executeSql.ts) | Runs SQL (user- or AI-written) — **read-only**: only SELECT and read-only anonymous blocks pass `validateAnySql()` |
| `execute_service_layer` | [tools/executeServiceLayer.ts](src/tools/executeServiceLayer.ts) | OData GET plus keyed, user-approved PATCH; POST/PUT/DELETE blocked |
| `get_schema_info` | [tools/schemaIntrospection.ts](src/tools/schemaIntrospection.ts) | Read-only metadata, HANA + MSSQL catalog syntax. Fixed catalog SELECTs; the `filter` is bound as `?`, never interpolated — this is the only SQL path that skips the guardrail engine, so the bind is the whole defence |
| `check_connection` | [tools/checkConnection.ts](src/tools/checkConnection.ts) | Independent health pings for DB and SL |

`execute_sql` handles SQL regardless of origin — user-written or AI-generated queries all go through the same `validateAnySql()` pipeline, which on this read-only server permits only SELECT (and anonymous blocks whose statements are all reads).

### Guardrail engine

[src/guardrails/](src/guardrails/) is the security core. The `execute_sql` tool calls `validateAnySql()` from [guardrails/index.ts](src/guardrails/index.ts), which:

1. [parser.ts](src/guardrails/parser.ts) — tokenises and classifies operation type, table list, SET columns. For `DO BEGIN..END` (HANA) and `BEGIN..END` (MSSQL) anonymous blocks it classifies the block by the **most dangerous statement inside it**: any write/exec/DDL keyword (`INSERT/UPDATE/DELETE/DROP/CREATE/ALTER/CALL/EXEC/TRUNCATE/MERGE/UPSERT/REPLACE/IMPORT/EXPORT/WRITETEXT/UPDATETEXT/GRANT/REVOKE/RENAME/…`) makes the whole block that operation, so a block can never be disguised as a read by appending a trailing `SELECT`. Keyword scanning blanks out quoted spans so a keyword inside a string/identifier doesn't false-trigger. Semicolons inside a block are allowed; bare multi-statement queries are not.

   **Quoting is load-bearing.** `stripComments()` copies `'...'`, `"..."` and `[...]` spans verbatim (including `''`/`""`/`]]` escapes): a `--` or `/*` inside an identifier is data, not a comment. Stripping it used to delete the rest of the statement from the guardrail's view while the DB still executed it in full — `SELECT 1 AS [x--]; DROP TABLE OITM` collapsed to `SELECT 1 AS [x` and was allowed, with the audit log recording only the harmless prefix. Regression payloads live in [tests/guardrails/quotedSpanEvasion.test.ts](tests/guardrails/quotedSpanEvasion.test.ts). Any change to the comment/quote scanners must keep that suite green.
2. [tableClassifier.ts](src/guardrails/tableClassifier.ts) — name-based classification:
   - **SAP_CORE** (≤4 chars, e.g. `ORDR`, `OITM`, `INV1`): most restrictive
   - **SAP_USER** (`@`-prefixed UDTs, e.g. `@MY_UDT`)
   - **CUSTOM** (>4 chars, no `@`)
   - **TEMP** (`#` / `##` prefixed)
3. Malformed-quoting deny (`malformedSql`) — both gates reject SQL with an unterminated `'`, `"` or `[` span (checked on comment-stripped text, so an apostrophe inside a comment is fine). An unclosed span blinds every scanner from that point to the end of the statement, so a write keyword after it would never be seen.
4. Read-only enforcement — `validateAnySql()` permits only `SELECT`; `INSERT/UPDATE/DELETE/DROP/CREATE/ALTER/EXEC` and unrecognised operations are all denied. Three writes-disguised-as-reads are blocked explicitly in [rules/selectRule.ts](src/guardrails/rules/selectRule.ts): `SELECT ... INTO <table>` (MS SQL table creation); pass-through functions (`OPENQUERY/OPENROWSET/OPENDATASOURCE`); and a **write-keyword fail-safe** — anything classified as a read that still contains a bare write/DDL/exec keyword (`INSERT/UPDATE/DELETE/DROP/CREATE/ALTER/TRUNCATE/MERGE/UPSERT/GRANT/REVOKE/RENAME/EXEC/EXECUTE/CALL/WRITETEXT/UPDATETEXT`) is denied. The fail-safe closes statement chaining that carries no semicolon (e.g. T-SQL runs `SELECT * FROM ORDR WHERE 1=0 DELETE FROM ORDR` as two statements even though the multi-statement check sees no `;`) and backstops any gap in the block keyword scan. `REPLACE` is excluded there because it is a common string function; its upsert spelling has no read classification and is denied upstream. A fourth check denies **lock-taking table hints** (`UPDLOCK/XLOCK/TABLOCK/TABLOCKX/HOLDLOCK/SERIALIZABLE/REPEATABLEREAD`): the DirectDb pool never commits, so a lock a "read" acquires outlives the tool call and blocks real B1 users. `NOLOCK/READPAST/ROWLOCK/PAGLOCK` stay allowed — no locks, no added duration; HANA's `SELECT ... FOR UPDATE` needs no entry because the bare `UPDATE` already trips the fail-safe. All four checks run on comment-stripped, quote-blanked SQL so an inline comment (`OPENQUERY/**/(...)`) or a keyword hidden in a string/identifier cannot evade them.

5. Result caps — [tools/formatResult.ts](src/tools/formatResult.ts) is the single renderer for `execute_sql` and `get_schema_info`. It slices to `MCP_MAX_RESULT_ROWS` (default 500), then cuts the rendered JSON at `MCP_MAX_RESULT_CHARS` (default 100 000). The guardrails decide whether a query *may* run, never how much it returns — `SELECT * FROM OUSR` is a legal read. Truncation is always announced in a leading `[TRUNCATED: …]` note: a silently partial result set is worse than none, because the model would reason over it as complete.

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
7. **Credentials never leave through the MCP protocol.** Profile listings expose only `id`, `dbName`, `dbType`, `slUrl`, capability flags. Adapters do not retain passwords. Nothing is interpolated into tool responses, audit entries, or error messages. This does not prevent a same-user AI shell/filesystem tool from opening `connections.json`; deployment documentation requires managed hooks/sandboxing and identifies separate OS identity as the strong boundary.

## Tech stack

Node ≥18, TypeScript ES2022 with Node16 modules. Dependencies: `@modelcontextprotocol/sdk` (stdio transport), `zod` (tool schema validation), `sps-sap-interface` (DirectDb + ServiceLayer). Tests via `vitest`.
