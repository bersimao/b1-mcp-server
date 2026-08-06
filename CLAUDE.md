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

`sps-mcp-server` is a Model Context Protocol server that gives an AI client guarded access to SAP Business One via both `DirectDb` (HANA / MS SQL) and the Service Layer OData API. Both sides are local: `src/db/directDb.ts` on `@sap/hana-client` + `mssql`, and a verified-TLS `fetch` adapter for the Service Layer.

**Read-only SQL posture:** DirectDb executes only `SELECT` (and anonymous blocks whose statements are all reads); every `INSERT/UPDATE/DELETE/DROP/CREATE/ALTER/EXEC` is blocked. Service Layer allows `GET` and guarded `PATCH`. PATCH requires a directly keyed entity and explicit user acceptance through MCP form elicitation; clients without elicitation support fail closed. SQL writes remain the human's job.

The server starts **without** any database or Service Layer connection. The AI must call `connect_database` to load a profile from `~/.claude/connections.json` and connect both sides at once. There is no env-var fallback — credentials live exclusively in that file.

End-user docs (install, connection profile shape, security posture) are in [README.md](README.md). This file is for working *on* the codebase.

## Commands

```bash
npm install                        # one-time
npm run build                      # tsc — prebuild wipes dist/ for a clean output
npm run watch                      # tsc --watch
npm run dev                        # tsx src/index.ts (skips build)
npm test                           # vitest run — full suite (431 tests)
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

Driver regression harness against a real server — run this after any `@sap/hana-client` / `mssql` / `generic-pool` bump, since the unit tests mock the drivers:

```bash
npx tsx scripts/validate-directdb.ts <profile-id> [--timeouts]
```

Pre-publish dry run (verifies the tarball ships only `dist/`, `LICENSE`, `README.md`, `package.json`):

```bash
npm pack --dry-run
```

## Architecture

### Connection model

`DirectDb` ([src/db/directDb.ts](src/db/directDb.ts)) is instantiated once in [src/index.ts](src/index.ts) and handed to `createServer`. Thin wrappers:

- [src/db/adapter.ts](src/db/adapter.ts) — `DbAdapter`
- [src/sl/serviceLayerAdapter.ts](src/sl/serviceLayerAdapter.ts) — strict-by-default TLS `ServiceLayerAdapter` with explicit per-profile certificate pinning compatibility; retains only the session cookie

Each adapter tracks `dbName` and `dbType` but does **not** retain credentials after init.

[src/tools/connectDatabase.ts](src/tools/connectDatabase.ts) implements the safe dual-connection switch:

- `OperationCoordinator` serializes every operation and environment switch.
- Teardown is **per side**: each side carries a connection key (a hash of the profile fields that side uses), and any side whose key no longer matches the incoming profile is disconnected first — whether or not the new profile still configures it. Deleting the SL fields from a profile therefore really does end the session, and rotating one side's credentials no longer bounces the other. The invariant that DirectDb and Service Layer never point at different environments survives because a still-connected side either already matched the profile or is reconnected to it.
- Partial success is allowed: if SL fails on the new target, DB stays active (and vice versa). Retrying the same profile reconnects only the failed side. Profiles reload on every connection call, so adding SL fields to an already-active DB-only profile initializes only SL.
- Failed login attempts are tracked per profile/side; a warning is appended after `SAP_LOCKOUT_WARNING_THRESHOLD = 3` — SAP B1 locks accounts after repeated failures.

Profile matching (`ConnectionManager.find` in [src/config/connectionManager.ts](src/config/connectionManager.ts)): exact `id` → exact `dbName` → **unique** partial substring match. Ambiguous partials (multiple profiles share the substring) return `undefined` and the tool surfaces the candidate list instead of guessing.

### DirectDb ([src/db/directDb.ts](src/db/directDb.ts))

The database driver, built directly on `@sap/hana-client` + `mssql` + `generic-pool`. It replaced the `sps-sap-interface` dependency, which brought an Express server, an axios Service Layer, a PostgreSQL driver, `system-sleep` and `https@1.0.0` — an npm **stub package**, not Node's built-in — for three method calls, and forced a hand-maintained `overrides` block on every consumer. A clean tarball install now audits at 0 vulnerabilities with no overrides, which `npx` could never achieve before.

**Behaviour that matters:**

- `executeQuery(query, params?)` — `{db}` is the schema placeholder resolved at runtime; `?` is the parameter placeholder. This read-only server only ever issues `SELECT`, so `?` binding always applies. On MS SQL each `?` is rewritten to `@mssqlboundparmN` before the statement reaches `mssql` — quote- and comment-aware, so a `?` inside a literal (`WHERE Comments = 'why?'`) or comment stays untouched. A placeholder/value count mismatch throws instead of binding wrong.
- `init({ …, timeout })` — one value, two meanings: HANA `communicationTimeout`, MS SQL `connectionTimeout` **and** `requestTimeout`. Default 600 000 ms; `connect_database` overrides it with `config.queryTimeoutMs` (`MCP_QUERY_TIMEOUT_MS`, default 60 s). This is the only cost ceiling in the server — the row cap runs after the DB has already done the work. Both engines were measured killing the statement server-side (`SYS.M_ACTIVE_STATEMENTS` / `sys.dm_exec_requests`), and both pools survive repeated timeouts (12 poisons → 25/25 clean). They differ in how the abort *looks*: MS SQL cancels the request and reports `Timeout: Request failed to complete in Nms`, but **HANA drops the socket**, so a timed-out query surfaces as `Connection down: [89012] Socket recv timeout` with no mention of a timeout at all — don't chase that as a network fault. `hana-client` reconnects transparently, so the next query just works.
- HANA connects through the **callback** overload of `client.connect`. The synchronous overload blocked the event loop for the whole handshake and login. Initialization now authenticates exactly once before exposing a single-session pool, so one bad password means one rejected login rather than five eager attempts. Pool acquisition is bounded by the configured query timeout.
- The HANA pool releases the connection **on the error path too**. That is what lets it survive a poisoned query instead of leaking a slot per timeout.
- **`encrypt: false` is pinned explicitly for MS SQL.** `mssql@6` defaulted to no encryption and every on-prem SAP B1 profile was configured against that; `mssql@11` flips the default to `true`. Pinning it stops a driver bump from silently breaking every profile. Turning it on properly needs a per-profile opt-in and a certificate story, like the Service Layer adapter has.

**Re-validate after any driver bump.** [scripts/validate-directdb.ts](scripts/validate-directdb.ts) runs the read-only checks plus the timeout / pool-poisoning behaviour against a real server (`npx tsx scripts/validate-directdb.ts <profile-id> [--timeouts]`; `--timeouts` is opt-in because it holds a session open until the server kills the statement). Mocked unit tests cannot catch driver breakage — all three drivers are CommonJS, so `import { ConnectionPool } from 'mssql'` typechecks and then throws at runtime, and a green unit suite says nothing about it. Last run on `mssql@11.0.1` / `@sap/hana-client@2.29.25`: all checks passed on HANA (`hana_profile`) and MS SQL (`mssql_profile`), timeout shape and pool recovery unchanged from the values documented above.

### Service Layer

Uses native `fetch` for strict TLS and a pinned native HTTPS transport for approved legacy endpoints. Both `/b1s/v1` (OData v3) and `/b1s/v2` (OData v4) profile roots are preserved exactly; the security policy validates only version-neutral relative endpoints. Invalid certificates are inspected without credentials and require MCP form elicitation before their exact fingerprint is saved in the local owner-only trust store. Changed certificates require approval again. Redirects are disabled, requests have fixed timeouts and bounded responses, and pins are checked before login credentials can be transmitted. A 401 requires reconnecting the profile; credentials are not retained for automatic login.

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

5. Result caps — [tools/formatResult.ts](src/tools/formatResult.ts) is the single renderer for `execute_sql`, `get_schema_info` and `execute_service_layer` GET. It slices to `MCP_MAX_RESULT_ROWS` (default 500), then cuts the rendered JSON at `MCP_MAX_RESULT_CHARS` (default 100 000). The guardrails decide whether a query *may* run, never how much it returns — `SELECT * FROM OUSR` is a legal read. The Service Layer path caps twice on purpose: the adapter bounds the *raw* response at `maxResponseChars`, but pretty-printing inflates it well past that, so the cap is reapplied to what actually reaches the model. Truncation is always announced in a leading `[TRUNCATED: …]` note: a silently partial result set is worse than none, because the model would reason over it as complete.

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

[src/logging/auditLogger.ts](src/logging/auditLogger.ts) writes JSON Lines to stderr (always) and optionally to a file (default: `~/.claude/logs/sps-mcp-audit.jsonl`, set via `MCP_AUDIT_LOG_PATH`). Logging happens **before execution** — denied operations are recorded too — and SQL execution writes a second completion/failure record with duration or error details. The MCP stdio transport uses stdout for JSON-RPC, so logs must never go to stdout.

## Layout

```
src/
  index.ts            entry, constructs DirectDb, bootstraps
  server.ts           factory: registers all tools, shares adapters
  config/             settings + connection-profile loader
  db/                 directDb.ts (the driver) + adapter.ts (wrapper)
  sl/                 strict-TLS Service Layer adapter
  types/drivers.d.ts  minimal ambient types for the three CJS drivers
  tools/              one file per MCP tool
  guardrails/         parser, table classifier, per-op rules (index.ts = read-only gate)
  sanitisation/       input validator (length / null-byte pre-checks)
  rateLimit/          sliding-window per-tool rate limiter
  logging/            JSON Lines audit logger
tests/                mirrors src/ — vitest, every guardrail rule covered
scripts/
  test-connection.ts     standalone DirectDb sanity check (takes profile id)
  validate-directdb.ts   real-server driver regression harness
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

Node ≥18, TypeScript ES2022 with Node16 modules. Dependencies: `@modelcontextprotocol/sdk` (stdio transport), `zod` (tool schema validation), `@sap/hana-client` + `mssql` + `generic-pool` (DirectDb). Tests via `vitest`.
