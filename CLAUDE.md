# CLAUDE.md — Project Context for Claude Code

## What This Project Is

A custom MCP server (`sps-mcp-server`) for Claude Code that provides secure, guarded access to SAP Business One databases via the `sps-sap-interface` npm module (`DirectDb`).

## Architecture Summary

### Connection Model
- **Multi-database support:** Connection profiles are stored in `~/.claude/connections.json`. The AI uses the `connect_database` tool to switch between databases at runtime.
- **Dual connection:** Each profile can include DirectDb (DB) and Service Layer (SL) credentials. Both are connected in one step. If one fails, the other still connects (partial success).
- **No connection at startup (default):** The server starts without connections. The AI must call `connect_database` before executing queries.
- **Legacy mode:** If `MCP_DB_*` env vars are set, the server connects DirectDb at startup automatically.
- `sps-sap-interface` provides `DirectDb` and `ServiceLayer` singletons.
- `DirectDb.init()` and `ServiceLayer.init()` can be called multiple times to switch connections.
- `DirectDb.executeQuery(query, params?)` uses `{db}` placeholder for schema resolution and `?` for parameter binding.
- `DirectDb.executeProcedure(name, paramsArray)` takes positional array params, not key-value.
- `ServiceLayer.execute({ method, url, data?, header?, page?, size?, timeout? })` makes OData calls. Auto-reconnects on 401.
- **Parameter binding (`?`) works for SELECT and INSERT but NOT for UPDATE.** UPDATEs are passed as plain text.

### 7 MCP Tools
1. **`connect_database`** — Switch active DirectDb + Service Layer connection. Loads profiles from `~/.claude/connections.json`. Connects both DB and SL in one step. Supports search by ID, database name, or display name. Use `"list"` to see all profiles.
2. **`execute_sql`** — User-provided raw SQL. Supports any operation (SELECT, UPDATE, INSERT, DELETE, DO BEGIN...END blocks). Server-side guardrails for simple statements; AI pre-validates complex anonymous blocks via tool description instructions.
3. **`execute_sql_ai`** — AI-generated SQL with **mandatory parameterised placeholders** (?). Server rejects queries where placeholder count doesn't match parameters array length. Same guardrails as execute_sql. Supports all operation types.
4. **`execute_procedure`** — Inspects SP source code before execution via `ProcedureInspectionCache`.
5. **`execute_service_layer`** — OData requests via SAP B1 Service Layer (GET, POST, PATCH, DELETE). DELETE requires explicit user confirmation. All other methods allowed (SL enforces its own validation).
6. **`get_schema_info`** — Read-only metadata (tables, columns, procedures). Supports HANA and MSSQL catalog syntax.
7. **`check_connection`** — Pings both DirectDb and Service Layer independently. Reports status for each.

### Security Guardrails — Table Classification
Tables are classified by name:
- **SAP_CORE** (≤ 4 chars: ORDR, OITM, INV1, JDT, etc.): Most restrictive. INSERT blocked entirely. UPDATE only on U_* (User-Defined Fields). DELETE/DROP always blocked.
- **SAP_USER** (@-prefixed: @MY_UDT): INSERT/DELETE allowed with user confirmation. UPDATE allowed. DROP always blocked.
- **CUSTOM** (> 4 chars, no @): Full CRUD. DROP only inside BEGIN...END blocks.
- **TEMP** (# or ## prefixed): Full CRUD. Same DROP restriction as CUSTOM.

### Security Guardrails — Operation Rules
- **SELECT**: Always allowed (read-only).
- **INSERT on SAP_CORE**: Always blocked. SAP manages row creation via DI API/Service Layer.
- **INSERT on SAP_USER**: Allowed with user confirmation (confirmation gate).
- **UPDATE on SAP_CORE**: Only U_* columns allowed. Non-UDF columns blocked.
- **DELETE on SAP_CORE**: Always blocked.
- **DELETE on SAP_USER**: Allowed with user confirmation (confirmation gate).
- **DROP on SAP_CORE or SAP_USER**: Always blocked.
- **DROP on CUSTOM/TEMP**: Only inside instruction blocks (DO BEGIN...END for HANA, BEGIN...END for MSSQL).
- **EXEC/EXECUTE/CALL**: Blocked in raw SQL. Must use execute_procedure tool (which inspects SP body first).
- **CREATE/ALTER**: Blocked entirely.
- **Multi-statement queries** (semicolons): Always blocked.

### UPDATE Sanitiser (4 layers for plain-text UPDATEs)
1. Input validation (null bytes, non-printable chars, max length)
2. Structure validation (no UNION/INTERSECT/EXCEPT)
3. Dangerous pattern detection (xp_cmdshell, EXEC(, CALL, WAITFOR, OPENROWSET, sp_executesql, etc.)
4. Comment blocking (-- and /* */ not allowed in UPDATE queries)

### Stored Procedure Inspector
Before executing any SP, the server fetches its source from the system catalog and scans for prohibited DML. Results are cached by SHA-256 hash of the body with 30min TTL.

### SQL Builder
Structured JSON → parameterised SQL. Includes `{db}.` prefix on table names for DirectDb schema resolution. Escapes string values for UPDATE plain-text path.

## Project Structure
```
src/
  index.ts                    — Entry point, imports DirectDb, bootstraps server
  server.ts                   — Factory: config → logger → adapter → cache → tools → McpServer
  config/settings.ts          — Env var parsing with validation (DB fields optional)
  config/connectionManager.ts — Loads connection profiles from ~/.claude/connections.json
  db/adapter.ts               — Thin wrapper around DirectDb
  sl/serviceLayerAdapter.ts   — Thin wrapper around ServiceLayer (OData)
  logging/auditLogger.ts      — Append-only JSON Lines audit log (stderr + file)
  types/index.ts              — All shared types and enums
  guardrails/
    index.ts                  — Engine: validateAnySql(), validateReadOnly(), validateRawUpdate(), validate()
    parser.ts                 — SQL tokeniser/classifier (operation type, tables, SET columns)
    tableClassifier.ts        — Table name → SAP_CORE/SAP_USER/CUSTOM/TEMP
    placeholderValidator.ts   — Counts ? placeholders, validates against parameters array
    structuredGuardrails.ts   — Validates structured JSON operations directly (no SQL parsing)
    rules/
      selectRule.ts           — Always allow
      updateRule.ts           — UDF-only on SAP_CORE
      insertRule.ts           — Block on SAP_CORE, confirm on SAP_USER
      deleteRule.ts           — Block on SAP_CORE, confirm on SAP_USER
      dropRule.ts             — Block on SAP, conditional on CUSTOM/TEMP
  sanitisation/
    updateSanitiser.ts        — 4-layer defence for plain-text UPDATEs
    inputValidator.ts         — Pre-flight checks (empty, null bytes, length)
  builders/
    sqlBuilder.ts             — Structured JSON → parameterised SQL with {db} prefix
  inspection/
    procedureInspector.ts     — Scans SP bodies for prohibited DML
    procedureCache.ts         — SHA-256 hash cache with TTL + LRU eviction
  rateLimit/
    rateLimiter.ts            — Sliding-window rate limiter per tool
  tools/
    connectDatabase.ts        — Switch active DirectDb + Service Layer connection via profiles
    executeSql.ts             — User-provided SQL (any operation, anonymous blocks)
    executeSqlAi.ts           — AI-generated SQL (mandatory placeholders)
    executeProcedure.ts       — With SP body inspection
    executeServiceLayer.ts    — OData requests via Service Layer (GET/POST/PATCH/DELETE)
    schemaIntrospection.ts    — Read-only metadata
    checkConnection.ts        — Dual health check (DirectDb + Service Layer)
tests/                        — Mirrors src/ structure, uses vitest
  integration/
    tools.test.ts             — End-to-end tests with mock DirectDb
  guardrails/
    placeholderValidator.test.ts — Placeholder counting and validation tests
```

## Current Status
- **Phase 1 (guardrails + parser + classifier)**: Complete with exhaustive tests.
- **Phase 2 (DB integration + tools)**: Complete.
- **Phase 3 (server + audit logging)**: Complete.
- **Phase 4 (polish)**: Complete (rate limiting, dry-run mode, SECURITY.md).
- **Phase 5 (tool consolidation)**: Complete. Consolidated 4 operation-specific tools into 2 unified tools.
- **Phase 6 (multi-database connections)**: Complete. Dynamic connection switching via profiles.
- **Phase 7 (Service Layer support)**: Complete. Added `execute_service_layer` tool and `ServiceLayerAdapter`:
  - Dual connection: DirectDb + Service Layer connected in one step from same profile
  - Partial success: if one fails, the other still connects
  - Connection profiles extended with optional `slUrl`, `slUser`, `slPassword` fields
  - Generic `execute_service_layer` tool for GET/POST/PATCH/DELETE OData requests
  - `check_connection` reports both DirectDb and Service Layer status independently

## Key Design Decisions
1. **Deny by default.** Unrecognised operations are rejected.
2. **Two SQL tools by origin, not by operation.** `execute_sql` for user queries (flexible), `execute_sql_ai` for AI queries (strict placeholders). This replaces the old per-operation tool split.
3. **AI as pre-validator.** For complex SQL (anonymous blocks), the AI validates SAP rules via tool description instructions. Server handles simple statements with hardcoded guardrails.
4. **Mandatory placeholders for AI.** `execute_sql_ai` rejects queries where ? count doesn't match parameters array length. Prevents SQL injection from AI-generated queries.
5. **Audit logging happens BEFORE execution.** Even denied operations are recorded.
6. **Never modify suspicious queries.** Accept as-is or reject entirely.
7. **HANA uses CALL, MSSQL uses EXEC/EXECUTE.** Both are detected and blocked in raw SQL.
8. **{db} placeholder** in all queries for DirectDb schema resolution.
9. **Multi-database via profiles.** Connection profiles in `~/.claude/connections.json` allow switching between databases at runtime via `connect_database` tool. Server starts unconnected by default — tools return helpful error messages until a connection is established.
10. **Dual connection per profile.** Each profile can include DirectDb and Service Layer credentials. Both are connected in one step. Partial success is supported — if DB connects but SL fails (or vice versa), the working connection is kept.

## Tech Stack
- Node.js + TypeScript (ES2022, Node16 modules)
- @modelcontextprotocol/sdk (MCP server SDK, stdio transport)
- zod (input schema validation)
- vitest (testing)
- sps-sap-interface (DirectDb — company internal DB module)

## Running
```bash
npm install
npm run build
npm test
# Then add to Claude Code MCP config with env vars
```
