# Secure MCP Server for Claude Code — Architecture Guide

## 1. Project Overview

A custom MCP (Model Context Protocol) server built on Node.js that wraps your internal `sps-sap-interface` module. It exposes controlled database tools to Claude Code while enforcing strict security guardrails that prevent destructive operations on SAP B1 systems.

---

## 2. Project Structure

```
sps-mcp-server/
├── package.json
├── tsconfig.json
├── .env.example                  # Template for required env vars
├── src/
│   ├── index.ts                  # Entry point — bootstraps the MCP server
│   ├── server.ts                 # MCP server setup, tool registration
│   │
│   ├── config/
│   │   └── settings.ts           # Centralised config (env parsing, defaults)
│   │
│   ├── tools/                    # One file per MCP tool
│   │   ├── executeQuery.ts       # SELECT / UPDATE / INSERT via executeQuery
│   │   ├── executeProcedure.ts   # Stored-procedure calls via executeProcedure
│   │   └── schemaIntrospection.ts# Read-only metadata lookups
│   │
│   ├── guardrails/               # ← All security logic lives here
│   │   ├── index.ts              # Public API — single validate() entry point
│   │   ├── parser.ts             # Lightweight SQL tokeniser / classifier
│   │   ├── rules/
│   │   │   ├── selectRule.ts     # SELECT — always allowed (read-only)
│   │   │   ├── updateRule.ts     # UPDATE — UDF-only on core tables
│   │   │   ├── insertRule.ts     # INSERT — UDF-only on core tables
│   │   │   ├── deleteRule.ts     # DELETE — blocked on SAP tables
│   │   │   └── dropRule.ts       # DROP — conditional, strict context check
│   │   └── tableClassifier.ts    # Identifies table type (core / user / custom)
│   │
│   ├── sanitisation/
│   │   ├── updateSanitiser.ts    # Plain-text UPDATE safety (since no placeholders)
│   │   └── inputValidator.ts     # General input checks (length, encoding, etc.)
│   │
│   ├── db/
│   │   └── adapter.ts            # Thin wrapper around sps-sap-interface
│   │
│   ├── logging/
│   │   └── auditLogger.ts        # Immutable audit log for every operation
│   │
│   └── types/
│       └── index.ts              # Shared TypeScript types & enums
│
├── tests/
│   ├── guardrails/               # Unit tests for every rule
│   ├── sanitisation/             # Unit tests for sanitisers
│   ├── tools/                    # Integration tests per tool
│   └── fixtures/                 # SQL fixtures (valid + malicious)
│
└── docs/
    └── SECURITY.md               # Human-readable security policy
```

**Why this layout matters:**

- **`guardrails/` is isolated from `tools/`** — security rules are never mixed with business logic. This makes auditing trivial and prevents accidental bypass.
- **Each rule is its own file** — a single rule change never risks breaking another.
- **`sanitisation/` is separate from `guardrails/`** — validation ("should we allow this?") is a different concern from sanitisation ("how do we make this safe?"). Mixing them leads to subtle bugs.

---

## 3. Architectural Flow

Every incoming request follows a strict, linear pipeline. No step can be skipped.

```
Claude Code
    │
    ▼
┌─────────────────────────────┐
│  MCP Server (stdio transport)│
│                              │
│  1. Tool Router              │  ← Identifies which tool was called
│         │                    │
│  2. Input Validator          │  ← Encoding, length, null-byte checks
│         │                    │
│  3. SQL Parser/Classifier    │  ← Determines operation type + target tables
│         │                    │
│  4. Guardrail Engine         │  ← Applies all rules; DENY = hard stop
│         │                    │
│  5. Sanitiser (if UPDATE)    │  ← Extra layer for plain-text UPDATEs
│         │                    │
│  6. Audit Logger             │  ← Logs BEFORE execution (intent audit)
│         │                    │
│  7. sps-sap-interface call   │  ← Actual DB operation
│         │                    │
│  8. Response Formatter       │  ← Shapes result for Claude Code
└─────────────────────────────┘
```

**Key design decisions:**

- **Deny-by-default.** If a query doesn't explicitly match an ALLOW rule, it is rejected.
- **Audit logging happens BEFORE execution.** Even if the DB call fails, we have a record of what was attempted.
- **The guardrail engine is synchronous and pure** — no side effects, no DB calls. It takes a parsed query and returns `{ allowed: boolean, reason: string }`. This makes it trivially testable.

---

## 4. Table Classification Logic

This is the foundation of every rule. Get this wrong and the entire guardrail system is compromised.

```
┌──────────────────────────────────────────────────────────────┐
│                    Table Name Input                           │
│                         │                                    │
│          ┌──────────────┼──────────────────┐                 │
│          ▼              ▼                  ▼                 │
│   Starts with @?   Length = 4?      Length > 4 & no @?       │
│          │              │                  │                 │
│   SAP User Table   SAP B1 Core       Custom Table           │
│   ──────────────   ──────────         ────────────           │
│   UPDATE: allowed  UPDATE: UDF only   UPDATE: allowed        │
│   INSERT: allowed  INSERT: UDF only   INSERT: allowed        │
│   DELETE: BLOCKED  DELETE: BLOCKED    DELETE: case-by-case   │
│   DROP:   BLOCKED  DROP:   BLOCKED    DROP:   conditional    │
└──────────────────────────────────────────────────────────────┘
```

**Important edge cases to handle:**

- Table names may be quoted (`"ORDR"`, `[ORDR]`) or schema-prefixed (`SBO_MyCompany.dbo.ORDR`). The classifier must strip these wrappers before measuring length.
- Table names are case-insensitive for classification purposes.
- Temp tables (`#temp`, `##globalTemp`) are a distinct category — treated as custom tables but with relaxed DROP rules.

### `tableClassifier.ts` — Pseudocode

```typescript
export enum TableType {
  SAP_CORE   = 'SAP_CORE',    // 4-char names: ORDR, OITM, INV1, etc.
  SAP_USER   = 'SAP_USER',    // @-prefixed: @MY_UDT
  CUSTOM     = 'CUSTOM',      // Longer names, no @: INVENTORY_AUDIT
  TEMP       = 'TEMP',        // # or ## prefixed
}

export function classifyTable(rawName: string): TableType {
  // 1. Strip schema prefix (everything before last dot)
  // 2. Strip quoting characters: ", [, ], `
  // 3. Trim whitespace
  const clean = stripSchemaAndQuotes(rawName);

  if (clean.startsWith('##') || clean.startsWith('#')) return TableType.TEMP;
  if (clean.startsWith('@'))                           return TableType.SAP_USER;
  if (clean.length === 4)                              return TableType.SAP_CORE;
  // Length ≤ 3 without @ — treat as SAP_CORE (e.g., ITM, JDT exist in B1)
  if (clean.length <= 4)                               return TableType.SAP_CORE;
  return TableType.CUSTOM;
}
```

> **Note:** SAP B1 does have some system tables shorter than 4 characters (e.g., `OADM` is 4, but `JDT` is 3). The safest default is to treat anything ≤ 4 characters as SAP_CORE. This errs on the side of caution — a false positive (blocking a custom 3-char table) is infinitely better than a false negative (allowing a write to a SAP system table).

---

## 5. Guardrail Rules — Detailed Specifications

### 5.1 SELECT Rule

```
ALLOW — always. SELECT is read-only.
No restrictions on target table or fields.
```

Minor safeguard: reject if the "SELECT" is actually a CTE or subquery that wraps a mutation (e.g., `WITH x AS (...) DELETE FROM ...`). The parser should check the final operation type, not just the first keyword.

### 5.2 UPDATE Rule

```
Target: SAP_CORE table (≤ 4 chars)?
  → Only allowed if EVERY column in the SET clause starts with U_ or u_
  → If ANY non-UDF column is present → DENY

Target: SAP_USER (@-prefixed) or CUSTOM table?
  → ALLOW

Additional constraint:
  → sps-sap-interface cannot use placeholders for UPDATEs.
  → The query is passed as plain text.
  → Mandatory sanitisation pass (see §6).
```

**Detecting SET columns — approach:**

Rather than writing a full SQL parser (which is fragile), use a targeted regex strategy:

1. Find the `SET` keyword that follows the table name.
2. Extract the column-assignment list between `SET` and `WHERE` (or end of statement).
3. Split by commas (respecting parentheses depth for subqueries).
4. For each assignment, the left-hand side before `=` is the column name.
5. Verify each column name starts with `U_` or `u_` (case-insensitive).

```typescript
// Pseudocode
function extractSetColumns(sql: string): string[] {
  const setMatch = sql.match(/\bSET\b(.+?)(\bWHERE\b|$)/is);
  if (!setMatch) return [];
  const assignments = splitRespectingParens(setMatch[1], ',');
  return assignments.map(a => a.split('=')[0].trim().replace(/["[\]`]/g, ''));
}
```

### 5.3 INSERT Rule

```
Target: SAP_CORE table (≤ 4 chars)?
  → Only allowed if EVERY column in the column list starts with U_ or u_
  → If ANY non-UDF column is present → DENY

Target: SAP_USER or CUSTOM?
  → ALLOW
```

For INSERTs, extract the column list from the `INSERT INTO table (col1, col2, ...)` syntax and apply the same U_ check.

### 5.4 DELETE Rule

```
Target: SAP_CORE or SAP_USER?
  → DENY — absolutely no exceptions.

Target: CUSTOM or TEMP?
  → ALLOW (with audit logging).
```

### 5.5 DROP Rule

This is the most nuanced rule.

```
Target: SAP_CORE or SAP_USER?
  → DENY — absolutely no exceptions.

Target: CUSTOM or TEMP?
  → ALLOW only if the DROP appears inside an instruction block:
      HANA:   DO BEGIN ... END
      MSSQL:  BEGIN ... END
  → Or if it's inside a stored procedure body (CREATE PROCEDURE / ALTER PROCEDURE).
  → Standalone DROP statements → DENY even for custom tables.
```

**Detecting instruction blocks:**

The parser checks whether the `DROP` keyword's character offset falls within a `BEGIN...END` pair. This requires tracking block depth (nested BEGINs).

```typescript
function isInsideBlock(sql: string, dropOffset: number): boolean {
  let depth = 0;
  const tokens = tokenize(sql); // simple keyword + offset tokeniser
  for (const token of tokens) {
    if (token.offset >= dropOffset) break;
    if (token.value === 'BEGIN' || token.value === 'DO') depth++;
    if (token.value === 'END') depth = Math.max(0, depth - 1);
  }
  return depth > 0;
}
```

---

## 6. The UPDATE Sanitisation Problem

Since `sps-sap-interface` can't use placeholders for UPDATE statements, we're passing raw SQL. This is the single highest-risk surface in the entire system. Here's how we mitigate it.

### 6.1 Defence-in-Depth Strategy

Don't rely on a single check. Stack multiple layers:

```
Layer 1: Input Validator
  → Reject null bytes (\x00)
  → Reject non-printable characters (except whitespace)
  → Enforce maximum query length (e.g., 8000 chars)
  → Reject queries with multiple statements (semicolons outside string literals)

Layer 2: Structure Validator
  → Confirm the query is a single UPDATE statement
  → Confirm it has exactly one SET clause and at most one WHERE clause
  → Reject if it contains subqueries in the SET values (no nested SELECTs)
  → Reject UNION, INTERSECT, EXCEPT

Layer 3: Dangerous Pattern Detector
  → Block: xp_cmdshell, EXEC(, EXECUTE(, sp_executesql
  → Block: WAITFOR DELAY, WAITFOR TIME (timing attacks)
  → Block: OPENROWSET, OPENDATASOURCE, BULK INSERT
  → Block: INTO OUTFILE, LOAD_FILE (HANA equivalents too)
  → Block: comments (-- and /* */) which can be used to hide payloads
  → Block: string concatenation operators (+ in MSSQL, || in HANA)
    that appear in WHERE clauses (common injection vector)

Layer 4: Value Type Constraints
  → For string values in SET: only allow properly quoted single-quote literals
  → For numeric values: validate they parse as numbers
  → For NULL: allow the literal NULL keyword
```

### 6.2 `updateSanitiser.ts` — Key Function

```typescript
export interface SanitisationResult {
  safe: boolean;
  reason?: string;   // Why it was rejected
  query?: string;    // The (unchanged) query if safe
}

export function sanitiseUpdate(sql: string): SanitisationResult {
  // Layer 1 — Input validation
  if (containsNullBytes(sql))        return deny('Null bytes detected');
  if (exceedsMaxLength(sql, 8000))   return deny('Query exceeds maximum length');
  if (hasMultipleStatements(sql))    return deny('Multiple statements detected');

  // Layer 2 — Structure validation
  if (!isSingleUpdateStatement(sql)) return deny('Not a single UPDATE statement');
  if (containsSubquery(sql))         return deny('Subqueries not allowed in UPDATE');

  // Layer 3 — Dangerous patterns
  const dangerousPattern = detectDangerousPatterns(sql);
  if (dangerousPattern)              return deny(`Blocked pattern: ${dangerousPattern}`);

  // Layer 4 — (Optional, for high-security mode)
  // Validate value types in SET clause

  return { safe: true, query: sql };
}
```

> **Critical note:** We do NOT modify the query. We either accept it as-is or reject it entirely. "Fixing" a suspicious query is more dangerous than blocking it — you risk creating a valid but unintended query.

---

## 7. MCP Tool Definitions

The server exposes three tools to Claude Code:

### 7.1 `execute_query`

```typescript
{
  name: 'execute_query',
  description: `Execute a SQL query against the target database.
    Supports SELECT, UPDATE, and INSERT.
    - SELECT: unrestricted read access.
    - UPDATE/INSERT on SAP core tables (4-char names):
      only User-Defined Fields (U_*) may be modified.
    - DELETE and DROP are handled by separate rules.
    Parameters are passed as placeholders for SELECT.
    UPDATE is passed as plain text with strict sanitisation.`,
  inputSchema: {
    type: 'object',
    properties: {
      database: {
        type: 'string',
        description: 'Target database name (required — scopes connection)'
      },
      query: {
        type: 'string',
        description: 'The SQL query to execute'
      },
      parameters: {
        type: 'array',
        items: { type: ['string', 'number', 'boolean', 'null'] },
        description: 'Placeholder values for parameterised queries (SELECT only)'
      },
      dbType: {
        type: 'string',
        enum: ['hana', 'mssql'],
        description: 'Target database engine'
      }
    },
    required: ['database', 'query', 'dbType']
  }
}
```

### 7.2 `execute_procedure`

```typescript
{
  name: 'execute_procedure',
  description: `Call a stored procedure on the target database.
    Parameters are handled safely via sps-sap-interface placeholders.`,
  inputSchema: {
    type: 'object',
    properties: {
      database:  { type: 'string' },
      procedure: { type: 'string', description: 'Procedure name' },
      parameters: {
        type: 'object',
        description: 'Key-value pairs for procedure parameters'
      },
      dbType: { type: 'string', enum: ['hana', 'mssql'] }
    },
    required: ['database', 'procedure', 'dbType']
  }
}
```

### 7.3 `get_schema_info`

```typescript
{
  name: 'get_schema_info',
  description: `Retrieve metadata about tables, columns, or procedures.
    Read-only. Use to explore the database schema before writing queries.`,
  inputSchema: {
    type: 'object',
    properties: {
      database: { type: 'string' },
      objectType: { type: 'string', enum: ['tables', 'columns', 'procedures'] },
      filter: { type: 'string', description: 'Optional name filter (LIKE pattern)' },
      dbType: { type: 'string', enum: ['hana', 'mssql'] }
    },
    required: ['database', 'objectType', 'dbType']
  }
}
```

---

## 8. Audit Logging

Every operation — allowed or denied — gets logged.

```typescript
interface AuditEntry {
  timestamp:   string;           // ISO 8601
  tool:        string;           // Which MCP tool was called
  database:    string;           // Target database
  dbType:      'hana' | 'mssql';
  operation:   string;           // SELECT, UPDATE, INSERT, DELETE, DROP, PROCEDURE
  tables:      string[];         // All tables referenced
  tableTypes:  TableType[];      // Classification of each table
  query:       string;           // The full query (for post-incident review)
  decision:    'ALLOW' | 'DENY';
  reason:      string;           // Why it was allowed/denied
  durationMs?: number;           // Execution time (if allowed and executed)
  error?:      string;           // Error message if execution failed
}
```

**Storage:** Write to a local append-only JSON Lines file (`audit.jsonl`). For production, consider streaming to a centralised log service.

**Retention:** Keep at least 90 days of logs. In a security incident, these are your forensic trail.

---

## 9. Error Handling Strategy

Never expose internal details to Claude Code. The AI does not need to see stack traces, connection strings, or internal module names.

```typescript
// What the MCP tool returns on error:
{
  content: [{
    type: 'text',
    text: 'Operation denied: UPDATE on table ORDR is restricted to User-Defined Fields (U_*). Column "CardCode" is not a UDF.'
  }],
  isError: true
}

// What gets logged internally (full detail):
{
  ...auditEntry,
  error: 'GuardrailDenied: updateRule — non-UDF column "CardCode" in SET clause for SAP_CORE table "ORDR"',
  stackTrace: '...'
}
```

---

## 10. Configuration via Environment

```bash
# .env.example

# Required — which database to connect to
MCP_DEFAULT_DB_TYPE=hana          # or mssql

# Guardrail tuning
MCP_MAX_QUERY_LENGTH=8000
MCP_ALLOW_COMMENTS_IN_SQL=false   # Block -- and /* */
MCP_AUDIT_LOG_PATH=./logs/audit.jsonl

# Logging level
MCP_LOG_LEVEL=info                # debug | info | warn | error
```

---

## 11. Implementation Order (Recommended Phases)

### Phase 1 — Foundation (do this first)

1. Scaffold the project (package.json, tsconfig, folder structure).
2. Build `tableClassifier.ts` + exhaustive unit tests.
3. Build `parser.ts` — the SQL tokeniser/classifier that identifies operation type and target tables.
4. Build each rule in `guardrails/rules/` with unit tests.
5. Build the `guardrails/index.ts` orchestrator that chains all rules.

**At this point you can fully test every security rule without any DB connection.**

### Phase 2 — DB Integration

6. Build `db/adapter.ts` — thin wrapper around `sps-sap-interface`.
7. Build the `execute_query` tool with the full pipeline (validate → guardrail → sanitise → execute).
8. Build `execute_procedure` tool.
9. Build `get_schema_info` tool.

### Phase 3 — Server & Hardening

10. Wire up `server.ts` with the MCP SDK (`@modelcontextprotocol/sdk`).
11. Add audit logging.
12. Add the `updateSanitiser.ts` with its full defence-in-depth layers.
13. End-to-end testing with Claude Code connected via stdio.

### Phase 4 — Polish

14. Add rate limiting (optional but recommended — prevents runaway loops).
15. Add a `dry_run` mode where queries are validated but not executed (useful for Claude Code to "pre-check" a query).
16. Write `SECURITY.md` documentation.

---

## 12. Key Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| SQL parser misclassifies operation | Bypass of guardrails | Use operation detection on the *outermost* statement, not the first keyword. Maintain a deny-list of evasion patterns (CTEs wrapping mutations). |
| Table name obfuscation (quotes, schemas) | Wrong table classification | Strip all decoration before classifying. Test with every quoting style. |
| UPDATE without placeholders | SQL injection | Four-layer sanitisation. Never modify queries — accept or reject. |
| AI constructs multi-statement payloads | Chained attacks | Reject any query with semicolons outside string literals. |
| AI uses dynamic SQL (`EXEC(@sql)`) | Guardrail bypass | Block EXEC/EXECUTE patterns in sanitiser. |
| AI drops tables via `SELECT INTO` / `INTO` | Data exfiltration | Detect `INTO` clauses in SELECT statements; deny if target is a SAP table. |

---

## 13. Testing Strategy

Every guardrail rule needs three categories of tests:

1. **Happy path** — valid operations that should be allowed.
2. **Block path** — malicious or invalid operations that must be denied.
3. **Edge cases** — obfuscated table names, unusual quoting, mixed case, unicode, empty strings, extremely long inputs.

Example test matrix for the UPDATE rule:

```
✅ UPDATE "@MY_UDT" SET "Name" = 'test' WHERE "Code" = '1'
✅ UPDATE ORDR SET "U_CustomField" = 'val' WHERE "DocEntry" = 1
❌ UPDATE ORDR SET "CardCode" = 'C001' WHERE "DocEntry" = 1
❌ UPDATE ORDR SET "U_Custom" = 'a', "CardCode" = 'b' WHERE ...
❌ UPDATE [ORDR] SET [CardCode] = 'C001'
❌ UPDATE "SBO_Demo"."dbo"."ORDR" SET "CardCode" = 'C001'
✅ UPDATE MY_CUSTOM_TABLE SET "Status" = 'active'
❌ UPDATE ORDR SET "U_Field" = 'val'; DROP TABLE ORDR --
```

---

## 14. What `server.ts` Looks Like (Skeleton)

```typescript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { registerQueryTool } from './tools/executeQuery.js';
import { registerProcedureTool } from './tools/executeProcedure.js';
import { registerSchemaTool } from './tools/schemaIntrospection.js';

const server = new McpServer({
  name: 'sps-mcp-server',
  version: '1.0.0',
  description: 'Secure MCP server for SAP B1 database operations'
});

// Register tools
registerQueryTool(server);
registerProcedureTool(server);
registerSchemaTool(server);

// Start with stdio transport (Claude Code communicates over stdin/stdout)
const transport = new StdioServerTransport();
await server.connect(transport);
```

---

## 15. Claude Code Configuration

Once built, register it in Claude Code's MCP settings:

```json
{
  "mcpServers": {
    "sps-db": {
      "command": "node",
      "args": ["./dist/index.js"],
      "cwd": "/path/to/sps-mcp-server"
    }
  }
}
```

---

*This document is your architectural blueprint. Phase 1 (guardrails + classifier + parser) can be built and fully tested without any database. Start there — it's the security foundation everything else depends on.*
