# CLAUDE.md — Project Context for Claude Code

## What This Project Is

A custom MCP server (`sps-mcp-server`) for Claude Code that provides secure, guarded access to SAP Business One databases via the `sps-sap-interface` npm module (`DirectDb`).

## Architecture Summary

### Connection Model
- `sps-sap-interface` provides `DirectDb` which connects to ONE database at startup via `DirectDb.init()`.
- Connection is fixed for the server's lifetime. The AI cannot change the target database.
- Credentials come from environment variables (see `.env.example`).
- `DirectDb.executeQuery(query, params?)` uses `{db}` placeholder for schema resolution and `?` for parameter binding.
- `DirectDb.executeProcedure(name, paramsArray)` takes positional array params, not key-value.
- **Parameter binding (`?`) works for SELECT and INSERT but NOT for UPDATE.** UPDATEs are passed as plain text.

### 5 MCP Tools
1. **`execute_query`** — Raw SQL, SELECT only. Enforced by `validateReadOnly()`.
2. **`execute_update`** — Accepts structured JSON (primary) or raw SQL (fallback for complex expressions like CASE, column arithmetic, subqueries). Both paths run through guardrails + sanitiser.
3. **`execute_insert`** — Structured JSON only. Blocked entirely on SAP core tables.
4. **`execute_procedure`** — Inspects SP source code before execution via `ProcedureInspectionCache`.
5. **`get_schema_info`** — Read-only metadata (tables, columns, procedures). Supports HANA and MSSQL catalog syntax.

### Security Guardrails — Table Classification
Tables are classified by name:
- **SAP_CORE** (≤ 4 chars: ORDR, OITM, INV1, JDT, etc.): Most restrictive. INSERT blocked entirely. UPDATE only on U_* (User-Defined Fields). DELETE/DROP always blocked.
- **SAP_USER** (@-prefixed: @MY_UDT): INSERT/UPDATE allowed. DELETE/DROP always blocked.
- **CUSTOM** (> 4 chars, no @): Full CRUD. DROP only inside BEGIN...END blocks.
- **TEMP** (# or ## prefixed): Full CRUD. Same DROP restriction as CUSTOM.

### Security Guardrails — Operation Rules
- **SELECT**: Always allowed (read-only).
- **INSERT on SAP_CORE**: Always blocked. SAP manages row creation via DI API/Service Layer.
- **UPDATE on SAP_CORE**: Only U_* columns allowed. Non-UDF columns blocked.
- **DELETE on SAP_CORE or SAP_USER**: Always blocked.
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
  config/settings.ts          — Env var parsing with validation
  db/adapter.ts               — Thin wrapper around DirectDb (ONLY file that touches sps-sap-interface)
  logging/auditLogger.ts      — Append-only JSON Lines audit log (stderr + file)
  types/index.ts              — All shared types and enums
  guardrails/
    index.ts                  — Engine: validateReadOnly(), validateRawUpdate(), validate()
    parser.ts                 — SQL tokeniser/classifier (operation type, tables, SET columns)
    tableClassifier.ts        — Table name → SAP_CORE/SAP_USER/CUSTOM/TEMP
    structuredGuardrails.ts   — Validates structured JSON operations directly (no SQL parsing)
    rules/
      selectRule.ts           — Always allow
      updateRule.ts           — UDF-only on SAP_CORE
      insertRule.ts           — Block all on SAP_CORE
      deleteRule.ts           — Block on SAP_CORE and SAP_USER
      dropRule.ts             — Block on SAP, conditional on CUSTOM/TEMP
  sanitisation/
    updateSanitiser.ts        — 4-layer defence for plain-text UPDATEs
    inputValidator.ts         — Pre-flight checks (empty, null bytes, length)
  builders/
    sqlBuilder.ts             — Structured JSON → parameterised SQL with {db} prefix
  inspection/
    procedureInspector.ts     — Scans SP bodies for prohibited DML
    procedureCache.ts         — SHA-256 hash cache with TTL + LRU eviction
  tools/
    executeQuery.ts           — SELECT only
    executeUpdate.ts          — Structured JSON or raw SQL
    executeInsert.ts          — Structured JSON only
    executeProcedure.ts       — With SP body inspection
    schemaIntrospection.ts    — Read-only metadata
tests/                        — Mirrors src/ structure, uses vitest
```

## Current Status
- **Phase 1 (guardrails + parser + classifier)**: Complete with exhaustive tests.
- **Phase 2 (DB integration + tools)**: Complete. All 5 tools wired to adapter.
- **Phase 3 (server + audit logging)**: Complete.
- **Phase 4 (polish)**: Not started. Remaining items:
  - Rate limiting (prevent AI runaway loops)
  - Dry-run mode (validate without executing)
  - SECURITY.md documentation
  - SQL builder tests need updating for {db} prefix
  - Integration tests with mock DirectDb

## Key Design Decisions
1. **Deny by default.** Unrecognised operations are rejected.
2. **Structured JSON is primary, raw SQL is fallback.** The server builds SQL from JSON when possible; falls back to guarded raw SQL for complex expressions.
3. **The server enforces tool selection.** The AI picks the tool, but the server blocks misuse (e.g., UPDATE through execute_query gets denied with a redirect message).
4. **Audit logging happens BEFORE execution.** Even denied operations are recorded.
5. **Never modify suspicious queries.** Accept as-is or reject entirely.
6. **HANA uses CALL, MSSQL uses EXEC/EXECUTE.** Both are detected and blocked in raw SQL.
7. **{db} placeholder** in all queries for DirectDb schema resolution.

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
